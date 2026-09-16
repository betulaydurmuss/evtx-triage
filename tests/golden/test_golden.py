"""Golden snapshots of the deterministic report for the synthetic fixtures.

A snapshot pins the parsed events, the groups and the evidence lines. Provenance
is excluded on purpose: its hashes change whenever the config or the knowledge
base is edited, which would turn every tuning change into a golden diff and
train us to update snapshots without reading them.

Refresh deliberately, after reading the diff:

    EVTX_TRIAGE_UPDATE_GOLDEN=1 python -m pytest tests/golden
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from evtx_triage.config import Config
from evtx_triage.pipeline import run_deterministic
from evtx_triage.report.json_report import build_report, dump_json

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"
CASES = ["mini", "edge_cases"]


def golden_view(config: Config, csv_path: Path) -> dict[str, Any]:
    """The part of the report a snapshot should pin."""
    result = run_deterministic(config, csv_path)
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
        llm_enabled=False,
        duration_seconds=0.0,
        # Token counts are left out like provenance: they move with every prompt or budget change.
        neutralized_by_group={
            gid: user.neutralized_control_tokens for gid, user in result.user_prompt_by_group.items()
        },
    )
    deterministic = report["deterministic"]
    return {
        "input": {
            "sha256": deterministic["input"]["sha256"],
            "data_rows": deterministic["input"]["data_rows"],
            "parsed_events": deterministic["input"]["parsed_events"],
        },
        "ingest_errors": deterministic["ingest_errors"],
        "coverage": deterministic["coverage"],
        "groups": deterministic["groups"],
    }


@pytest.mark.parametrize("case", CASES)
def test_golden(config: Config, case: str) -> None:
    actual = dump_json(golden_view(config, FIXTURES / f"{case}.csv"))
    snapshot = SNAPSHOTS / f"{case}.json"

    if os.environ.get("EVTX_TRIAGE_UPDATE_GOLDEN") == "1":
        SNAPSHOTS.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(actual, encoding="utf-8")
        pytest.skip(f"golden snapshot refreshed: {snapshot.name}")

    assert snapshot.is_file(), f"missing snapshot {snapshot}; refresh with EVTX_TRIAGE_UPDATE_GOLDEN=1"
    expected = snapshot.read_text(encoding="utf-8")
    assert json.loads(actual) == json.loads(expected)
    assert actual == expected, "snapshot content matches but serialisation differs"
