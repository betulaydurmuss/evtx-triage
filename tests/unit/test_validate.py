"""The validator must reject anything it cannot trace back to the evidence.

The injection catalogue at the bottom is the Faz 6 exit criterion in unit form:
every injected fault must be caught, and the untouched answer must still pass.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from evtx_triage.validate import IPV4, ValidationContext, extract_json, validate_interpretation

CONTEXT = ValidationContext(
    group_id="G0001",
    row_ids=frozenset({"R000001", "R000002"}),
    guidance_ids=frozenset({"G-001"}),
    event_ids=frozenset({10, 11}),
    techniques=frozenset({"T1003.001", "T1558"}),
    ipv4=frozenset({"10.0.2.17"}),
)


def _body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "group_id": "G0001",
        "assessment": "suspicious",
        "what_happened": [
            {
                "text": "A tool opened lsass.exe (EID 10) from 10.0.2.17, see T1003.001.",
                "evidence": ["R000002"],
            }
        ],
        "next_steps": [
            {"text": "Check the dump file (EID 11).", "evidence": ["R000001"], "guidance": ["G-001"]}
        ],
    }
    body.update(overrides)
    return body


def _check(raw: str) -> tuple[Any, list[str]]:
    return validate_interpretation(raw, CONTEXT)


def test_valid_output_is_accepted() -> None:
    interpretation, errors = _check(json.dumps(_body()))
    assert errors == []
    assert interpretation is not None
    assert interpretation.assessment.value == "suspicious"


def test_parent_technique_of_a_tagged_sub_technique_is_allowed() -> None:
    raw = json.dumps(
        _body(what_happened=[{"text": "OS credential dumping (T1003).", "evidence": ["R000002"]}])
    )
    assert _check(raw)[1] == []


def test_sub_technique_of_a_tagged_parent_is_not_allowed() -> None:
    raw = json.dumps(_body(what_happened=[{"text": "Kerberoasting (T1558.003).", "evidence": ["R000002"]}]))
    interpretation, errors = _check(raw)
    assert interpretation is None
    assert any("T1558.003" in error for error in errors)


def test_think_block_and_code_fence_are_stripped() -> None:
    assert _check(f"<think>weighing</think>\n{json.dumps(_body())}")[1] == []
    assert _check(f"```json\n{json.dumps(_body())}\n```")[1] == []


def test_every_violation_is_reported_not_just_the_first() -> None:
    body = _body(
        what_happened=[{"text": "EID 4624 from 192.168.1.9 via T1110.", "evidence": ["R999999"]}],
    )
    errors = _check(json.dumps(body))[1]
    assert len(errors) == 4  # row, EID, IP and technique


def test_extract_json_handles_surrounding_prose() -> None:
    assert extract_json('Here you go: {"a": 1} hope that helps') == '{"a": 1}'


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("from 10.0.2.17.", ["10.0.2.17"]),
        ("version 6.1.7601.17514", []),
        ("host 999.1.1.1", []),
        ("addr 1.2.3.4:445", ["1.2.3.4"]),
        ("10.0.2.17.5", []),
    ],
)
def test_ipv4_pattern(text: str, found: list[str]) -> None:
    assert IPV4.findall(text) == found


def _set_text(body: dict[str, Any], section: str, text: str) -> dict[str, Any]:
    body[section][0]["text"] = text
    return body


# Each fault takes a valid answer and breaks exactly one rule.
INJECTED_FAULTS: dict[str, Any] = {
    "cites a row that does not exist": lambda b: b["what_happened"][0].update(evidence=["R999999"]),
    "cites a row of the group that was not shown": lambda b: b["next_steps"][0].update(evidence=["R000003"]),
    "claim without evidence": lambda b: b["what_happened"][0].update(evidence=[]),
    "next step without evidence": lambda b: b["next_steps"][0].update(evidence=[]),
    "cites guidance that was not retrieved": lambda b: b["next_steps"][0].update(guidance=["G-042"]),
    "wrong group id": lambda b: b.update(group_id="G0002"),
    "unknown assessment": lambda b: b.update(assessment="definitely_evil"),
    "missing field": lambda b: b.pop("next_steps"),
    "unexpected field": lambda b: b.update(confidence=0.9),
    "fabricated EID in a claim": lambda b: _set_text(b, "what_happened", "Logon seen (EID 4624)."),
    "fabricated EID in a next step": lambda b: _set_text(b, "next_steps", "Look for EID 1117."),
    "fabricated technique id": lambda b: _set_text(b, "what_happened", "This is T1059.001."),
    "fabricated IP address": lambda b: _set_text(b, "what_happened", "Traffic to 203.0.113.7."),
}


@pytest.mark.parametrize("fault", sorted(INJECTED_FAULTS))
def test_injected_fault_is_caught(fault: str) -> None:
    body = _body()
    INJECTED_FAULTS[fault](body)
    interpretation, errors = _check(json.dumps(body))
    assert interpretation is None, f"not caught: {fault}"
    assert errors


@pytest.mark.parametrize(
    "raw",
    ["{ not json at all", "", "The group looks malicious.", '{"group_id": "G0001"'],
)
def test_malformed_output_is_caught(raw: str) -> None:
    interpretation, errors = _check(raw)
    assert interpretation is None
    assert errors


# --- assessment warnings (ADR-0001 section 9c.3) ------------------------------------


def _outcome(assessment: str, status: str = "accepted"):
    from evtx_triage.models import GroupInterpretation, InterpretationOutcome

    interpretation = GroupInterpretation(**_body(assessment=assessment)) if status == "accepted" else None
    return InterpretationOutcome(group_id="G0001", status=status, interpretation=interpretation, attempts=1)


def _group(level: str):
    from types import SimpleNamespace

    from evtx_triage.models import Level

    return SimpleNamespace(max_level=Level(level))


@pytest.mark.parametrize(
    ("assessment", "level", "neutralized", "expected"),
    [
        ("likely_benign", "critical", 0, 1),
        ("insufficient_evidence", "high", 0, 1),
        ("likely_benign", "medium", 0, 0),  # below min_level: a benign verdict is plausible
        ("likely_malicious", "critical", 0, 0),
        ("suspicious", "high", 3, 1),  # control tokens were defused: always worth a warning
        ("likely_benign", "critical", 3, 2),
    ],
)
def test_assessment_warnings(assessment: str, level: str, neutralized: int, expected: int) -> None:
    from evtx_triage.models import Assessment, Level
    from evtx_triage.validate import assessment_warnings

    warnings = assessment_warnings(
        _outcome(assessment),
        _group(level),  # type: ignore[arg-type]
        min_level=Level.high,
        assessments=[Assessment.likely_benign, Assessment.insufficient_evidence],
        neutralized_control_tokens=neutralized,
    )
    assert len(warnings) == expected


def test_rejected_answers_get_no_assessment_warning() -> None:
    from evtx_triage.models import Assessment, Level
    from evtx_triage.validate import assessment_warnings

    assert (
        assessment_warnings(
            _outcome("likely_benign", status="rejected"),
            _group("critical"),  # type: ignore[arg-type]
            min_level=Level.high,
            assessments=[Assessment.likely_benign],
            neutralized_control_tokens=5,
        )
        == []
    )
