"""The retry and fallback policy, exercised without a GPU."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from evtx_triage.config import Config
from evtx_triage.llm.client import FakeLLM, LLMError, LLMOutOfMemoryError
from evtx_triage.llm.interpret import interpret_group, load_prompt
from evtx_triage.pipeline import make_budget, run_deterministic


def _good(group_id: str, row_id: str) -> str:
    return json.dumps(
        {
            "group_id": group_id,
            "assessment": "suspicious",
            "what_happened": [{"text": "A process accessed lsass.exe (EID 10).", "evidence": [row_id]}],
            "next_steps": [{"text": "Review the host.", "evidence": [row_id], "guidance": []}],
        }
    )


def _bad(group_id: str) -> str:
    return json.dumps(
        {
            "group_id": group_id,
            "assessment": "suspicious",
            "what_happened": [{"text": "Invented row.", "evidence": ["R999999"]}],
            "next_steps": [{"text": "Nothing.", "evidence": ["R999999"], "guidance": []}],
        }
    )


def _first_group(config: Config, mini_csv: Path):
    result = run_deterministic(config, mini_csv)
    group = result.selected[0]
    return group, result.packed_by_group[group.group_id], result


def _run(config: Config, client: FakeLLM, group, packed, result):
    return interpret_group(
        client,
        group,
        packed,
        context=result.context_by_group[group.group_id],
        user_prompt=result.user_prompt_by_group[group.group_id],
        prompt=load_prompt(config.llm.prompt_version),
        budget=make_budget(config),
        max_retries=1,
    )


def test_valid_first_answer_is_accepted(config: Config, mini_csv: Path) -> None:
    group, packed, result = _first_group(config, mini_csv)
    client = FakeLLM([_good(group.group_id, packed.included_row_ids[0])])

    outcome = _run(config, client, group, packed, result)

    assert outcome.status == "accepted"
    assert outcome.attempts == 1
    assert len(client.calls) == 1


def test_invalid_then_valid_is_accepted_on_retry(config: Config, mini_csv: Path) -> None:
    group, packed, result = _first_group(config, mini_csv)
    client = FakeLLM([_bad(group.group_id), _good(group.group_id, packed.included_row_ids[0])])

    outcome = _run(config, client, group, packed, result)

    assert outcome.status == "accepted"
    assert outcome.attempts == 2
    # The retry prompt must tell the model what was wrong.
    assert "rejected for these reasons" in client.calls[1][1]


def test_twice_invalid_falls_back(config: Config, mini_csv: Path) -> None:
    group, packed, result = _first_group(config, mini_csv)
    client = FakeLLM([_bad(group.group_id), _bad(group.group_id)])

    outcome = _run(config, client, group, packed, result)

    assert outcome.status == "rejected"
    assert outcome.attempts == 2
    assert outcome.interpretation is None
    assert any("R999999" in reason for reason in outcome.reasons)


def test_out_of_memory_is_never_retried(config: Config, mini_csv: Path) -> None:
    group, packed, result = _first_group(config, mini_csv)
    client = FakeLLM([LLMOutOfMemoryError("CUDA failure 2: out of memory"), _good(group.group_id, "R000001")])

    outcome = _run(config, client, group, packed, result)

    assert outcome.status == "skipped"
    assert outcome.attempts == 1
    assert len(client.calls) == 1
    assert "out of memory" in outcome.reasons[0].lower()


def test_transport_failure_is_reported(config: Config, mini_csv: Path) -> None:
    group, packed, result = _first_group(config, mini_csv)
    client = FakeLLM([LLMError("connection refused")])

    outcome = _run(config, client, group, packed, result)

    assert outcome.status == "skipped"
    assert "connection refused" in outcome.reasons[0]


def test_evidence_block_is_fenced_as_data(config: Config, mini_csv: Path) -> None:
    group, packed, result = _first_group(config, mini_csv)
    client = FakeLLM([_good(group.group_id, packed.included_row_ids[0])])
    _run(config, client, group, packed, result)

    system, user = client.calls[0]
    assert "untrusted" in system.lower()
    assert "<<<BEGIN EVIDENCE" in user and "END EVIDENCE>>>" in user


def test_oversized_prompt_is_never_sent(config: Config, mini_csv: Path) -> None:
    from evtx_triage.llm.interpret import UserPrompt

    group, packed, result = _first_group(config, mini_csv)
    client = FakeLLM([_good(group.group_id, packed.included_row_ids[0])])
    huge = UserPrompt(text="x " * 100_000, neutralized_control_tokens=0)

    outcome = interpret_group(
        client,
        group,
        packed,
        context=result.context_by_group[group.group_id],
        user_prompt=huge,
        prompt=load_prompt(config.llm.prompt_version),
        budget=make_budget(config),
        max_retries=1,
    )

    assert outcome.status == "skipped"
    assert "input budget" in outcome.reasons[0]
    assert client.calls == []


def test_retry_that_cannot_fit_is_not_sent(config: Config, mini_csv: Path) -> None:
    group, packed, result = _first_group(config, mini_csv)
    budget = make_budget(config)
    system = load_prompt(config.llm.prompt_version).text
    user = result.user_prompt_by_group[group.group_id]
    # A budget the first request fits exactly, leaving no room for any rejection reason.
    exact = budget.prompt_tokens(system, user.text)
    tight = dataclasses.replace(budget, max_input_tokens=exact)
    client = FakeLLM([_bad(group.group_id), _good(group.group_id, packed.included_row_ids[0])])

    outcome = interpret_group(
        client,
        group,
        packed,
        context=result.context_by_group[group.group_id],
        user_prompt=user,
        prompt=load_prompt(config.llm.prompt_version),
        budget=tight,
        max_retries=1,
    )

    assert len(client.calls) == 1
    assert outcome.status == "rejected"
    assert any("do not fit the input budget" in reason for reason in outcome.reasons)
