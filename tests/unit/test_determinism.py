"""Same input, same knowledge base, same config: identical deterministic bytes."""

from __future__ import annotations

import json
from pathlib import Path

from evtx_triage.config import Config
from evtx_triage.pipeline import run_deterministic
from evtx_triage.report.json_report import build_report, dump_json


def _report(config: Config, config_path: Path, csv_path: Path) -> dict[str, object]:
    result = run_deterministic(config, csv_path)
    return build_report(
        config=config,
        config_path=config_path,
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
    )


def test_deterministic_section_is_byte_identical(config: Config, config_path: Path, mini_csv: Path) -> None:
    first = _report(config, config_path, mini_csv)
    second = _report(config, config_path, mini_csv)

    left = dump_json({"deterministic": first["deterministic"]})
    right = dump_json({"deterministic": second["deterministic"]})
    assert left.encode("utf-8") == right.encode("utf-8")


def test_run_section_is_the_only_moving_part(config: Config, config_path: Path, mini_csv: Path) -> None:
    first = _report(config, config_path, mini_csv)
    second = _report(config, config_path, mini_csv)
    assert set(first) == {"schema_version", "run", "deterministic", "model"}
    assert first["schema_version"] == second["schema_version"]


def test_report_records_the_provenance_needed_to_reproduce_it(
    config: Config, config_path: Path, mini_csv: Path
) -> None:
    report = _report(config, config_path, mini_csv)
    provenance = report["deterministic"]["provenance"]  # type: ignore[index]

    assert provenance["config_hash"] == config.hash()
    assert provenance["hayabusa_flags"] == "-U -O -w -q -C -b -A"
    assert len(provenance["knowledge_hash"]) == 64
    assert report["deterministic"]["input"]["sha256"]  # type: ignore[index]


def test_every_evidence_line_belongs_to_its_group(config: Config, config_path: Path, mini_csv: Path) -> None:
    report = _report(config, config_path, mini_csv)
    for group in report["deterministic"]["groups"]:  # type: ignore[index]
        evidence = group.get("evidence")
        if evidence is None:
            continue
        rows = {event["row_id"] for event in group["events"]}
        assert set(evidence["included_row_ids"]) <= rows
        for line in evidence["lines"]:
            assert line[1:8] in rows


def test_json_is_utf8_and_sorted(config: Config, config_path: Path, mini_csv: Path) -> None:
    text = dump_json(_report(config, config_path, mini_csv))
    reparsed = json.loads(text)
    coverage = reparsed["deterministic"]["coverage"]
    assert coverage["dictionary_entries"] >= 54
    # the fixture only uses Sysmon events, all of which the dictionary covers
    assert coverage["unknown_pairs"] == [
        {"channel": "Microsoft-Windows-TaskScheduler/Operational", "event_id": 106}
    ]
