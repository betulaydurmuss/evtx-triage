"""The viewer only reads a report: no triage logic, no disagreement with the CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evtx_triage.config import Config
from evtx_triage.pipeline import run_deterministic
from evtx_triage.report.json_report import build_report
from evtx_triage.ui import report_view as view

COMPUTING_MODULES = ("pipeline", "pack", "validate", "grouping", "enrich", "ingest", "knowledge", "llm")


def _report(config: Config, csv_path: Path) -> dict[str, Any]:
    """A report like the CLI writes, with one hand-written model answer."""
    result = run_deterministic(config, csv_path)
    group = result.selected[0]
    packed = result.packed_by_group[group.group_id]
    representative = packed.entries[0].row_ids[0]
    outcome = {
        "group_id": group.group_id,
        "status": "accepted",
        "attempts": 1,
        "reasons": [],
        "warnings": ["assessment likely_benign conflicts with the detections: level high."],
        "duration_seconds": 1.5,
        "assessment": "likely_benign",
        "what_happened": [{"text": "Something happened.", "evidence": [representative]}],
        "next_steps": [{"text": "Look at it.", "evidence": [representative], "guidance": []}],
    }
    report = build_report(
        config=config,
        config_path=Path("config/default.toml"),
        input_path=csv_path,
        ingest=result.ingest,
        groups=result.groups,
        selected_ids=result.selected_ids,
        packed_by_group=result.packed_by_group,
        outcomes=[],
        unknown_pairs=result.unknown_pairs,
        unknown_tactics=result.unknown_tactics,
        unknown_techniques=result.unknown_techniques,
        dictionary_entries=len(result.dictionary),
        knowledge_hash=result.knowledge_hash,
        attack_version=result.attack.version,
        llm_enabled=True,
        duration_seconds=0.0,
        prompt_tokens_by_group=result.prompt_tokens_by_group,
        neutralized_by_group={
            gid: user.neutralized_control_tokens for gid, user in result.user_prompt_by_group.items()
        },
        token_provenance=result.token_provenance,
    )
    report["model"]["interpretations"] = [outcome]
    return json.loads(json.dumps(report))  # round trip: the viewer only ever sees JSON


@pytest.fixture
def report(config: Config, mini_csv: Path) -> dict[str, Any]:
    return _report(config, mini_csv)


def test_viewer_does_not_import_the_computing_modules() -> None:
    source = Path(view.__file__).read_text(encoding="utf-8")
    for name in COMPUTING_MODULES:
        assert f"import {name}" not in source and f"from evtx_triage.{name}" not in source


def test_group_rows_repeat_the_report_verbatim(report: dict[str, Any]) -> None:
    rows = view.group_rows(report)
    assert len(rows) == len(report["deterministic"]["groups"])
    for row, group in zip(rows, report["deterministic"]["groups"], strict=True):
        assert row["group"] == group["group_id"]
        assert row["level"] == group["max_level"]
        assert row["events"] == group["event_count"]
        assert row["to model"] == ("yes" if group["selected_for_model"] else "no")
    interpreted = report["model"]["interpretations"][0]
    shown = next(row for row in rows if row["group"] == interpreted["group_id"])
    assert shown["assessment"] == interpreted["assessment"]
    assert shown["status"] == interpreted["status"]
    assert shown["warnings"] == 1


def test_warnings_are_listed_with_their_group(report: dict[str, Any]) -> None:
    warnings = view.all_warnings(report)
    assert warnings == [
        (
            report["model"]["interpretations"][0]["group_id"],
            "assessment likely_benign conflicts with the detections: level high.",
        )
    ]


def test_cited_rows_expand_folded_lines(report: dict[str, Any]) -> None:
    outcome = report["model"]["interpretations"][0]
    group = view.find_group(report, outcome["group_id"])
    assert group is not None
    entry = (group["evidence"])["entries"][0]
    assert view.cited_row_ids(group, outcome) == set(entry["row_ids"])


def test_event_rows_and_filters(report: dict[str, Any]) -> None:
    outcome = report["model"]["interpretations"][0]
    group = view.find_group(report, outcome["group_id"])
    assert group is not None
    cited = view.cited_row_ids(group, outcome)
    shown = set(group["evidence"]["included_row_ids"])
    rows = view.event_rows(group, cited, shown)
    assert len(rows) == group["event_count"]
    assert {row["row"] for row in rows if row["cited"]} == cited

    only_cited = view.filter_events(rows, only_cited=True)
    assert only_cited and all(row["cited"] for row in only_cited)

    level = rows[0]["level"]
    by_level = view.filter_events(rows, levels=[level])
    assert by_level and all(row["level"] == level for row in by_level)

    eid = int(rows[0]["eid"])
    by_eid = view.filter_events(rows, event_ids=[eid])
    assert by_eid and all(int(row["eid"]) == eid for row in by_eid)

    assert view.filter_events(rows, search="no-such-string-anywhere") == []
    assert view.filter_events(rows, search=rows[0]["row"])[0]["row"] == rows[0]["row"]
    assert view.filter_events(rows) == rows  # no filter hides nothing


def test_provenance_rows_come_from_the_report(report: dict[str, Any]) -> None:
    values = dict(view.provenance_rows(report))
    provenance = report["deterministic"]["provenance"]
    assert values["model"] == provenance["model_id"]
    assert values["config hash"] == provenance["config_hash"][:12]
    assert values["token counter"] == provenance["tokens"]["counter"]
    assert values["input sha256"] == report["deterministic"]["input"]["sha256"]


def test_find_reports_and_csv_files(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "report.json").write_text("{}", encoding="utf-8")
    (tmp_path / "b.csv").write_text("x", encoding="utf-8")
    assert [path.name for path in view.find_reports(tmp_path)] == ["report.json"]
    assert [path.name for path in view.find_csv_files(tmp_path)] == ["b.csv"]
    assert view.find_reports(tmp_path / "missing") == []


def test_an_older_report_still_opens(report: dict[str, Any]) -> None:
    """A report from an earlier version of the tool lacks keys the viewer must not require.

    Measured: out/nollm/report.json (Faz 1) has no `attack_version` and crashed the page.
    """
    older = json.loads(json.dumps(report))
    provenance = older["deterministic"]["provenance"]
    for key in ("attack_version", "tokens", "prompt_sha256", "model_id", "hayabusa_flags"):
        provenance.pop(key, None)
    older.pop("schema_version", None)
    group = older["deterministic"]["groups"][0]
    group.pop("evidence", None)
    for event in group["events"]:
        event.pop("dictionary_title", None)
    older["model"]["interpretations"] = []

    assert dict(view.provenance_rows(older))["attack version"] == "-"
    rows = view.group_rows(older)
    assert len(rows) == len(older["deterministic"]["groups"])
    assert rows[0]["assessment"] == "-"
    assert view.all_warnings(older) == []
    events = view.event_rows(group, set(), set())
    assert len(events) == len(group["events"])
    assert events[0]["event"] == "UNKNOWN"
    assert view.evidence_rows(group) == []
