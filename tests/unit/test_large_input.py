"""Large input behaviour (Faz 8).

A timeline is not bounded in size. The measured case: 100,000 synthetic rows parse
without error but produce 15,362 groups above the model threshold, which would be
about 64 hours of model time. The cap in `[selection] max_groups_to_model` keeps a
run finite, deterministically, and the report says what was left out.

20,000 rows here keeps the test quick; the shape is the same.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evtx_triage.config import Config
from evtx_triage.models import LEVEL_RANK
from evtx_triage.pipeline import run_deterministic

HEADER = [
    "Timestamp",
    "RuleTitle",
    "Level",
    "Computer",
    "Channel",
    "EventID",
    "MitreTactics",
    "MitreTags",
    "OtherTags",
    "RecordID",
    "AllFieldInfo",
    "RuleFile",
    "RuleID",
    "EvtxFile",
]
KINDS = [
    ("Proc Exec", "informational", "Microsoft-Windows-Sysmon/Operational", 1),
    ("Potential Credential Dumping Activity Via LSASS", "medium", "Microsoft-Windows-Sysmon/Operational", 10),
    ("Suspicious Service Installation", "high", "System", 7045),
]
SEPARATOR = " \u00a6 "  # the AllFieldInfo separator Hayabusa writes
ROWS = 20_000


def _write_csv(path: Path, rows: int = ROWS) -> Path:
    start = datetime(2024, 5, 1, 8, 0, tzinfo=UTC)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(HEADER)
        for index in range(rows):
            title, level, channel, event_id = KINDS[index % len(KINDS)]
            # A new host every 40 rows and a 30 minute jump every 200 rows make many groups.
            host = f"HOST{index // 40 % 50:02d}.example.local"
            stamp = start + timedelta(seconds=index * 3 + (index // 200) * 1800)
            fields = SEPARATOR.join(
                [
                    "CommandLine: whoami /all",
                    "Image: C:\\Windows\\System32\\whoami.exe",
                    f"User: EXAMPLE\\u{index % 7}",
                ]
            )
            writer.writerow(
                [
                    stamp.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
                    title,
                    level,
                    host,
                    channel,
                    event_id,
                    "",
                    "",
                    "",
                    100000 + index,
                    fields,
                    "Synthetic.yml",
                    "11111111-1111-1111-1111-111111111111",
                    "C:\\samples\\large.evtx",
                ]
            )
    return path


def test_large_timeline_parses_and_the_cap_bounds_the_model_work(config: Config, tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "large.csv")
    capped = config.model_copy(
        update={"selection": config.selection.model_copy(update={"max_groups_to_model": 25})}
    )
    result = run_deterministic(capped, csv_path)

    assert result.ingest.data_rows == ROWS
    assert len(result.events) == ROWS
    assert result.ingest.errors == []
    assert len(result.groups) > 100
    assert result.selection.eligible > 25, "the test input must exercise the cap"

    assert len(result.selected) == 25
    assert len(result.selection.not_sent) == result.selection.eligible - 25
    # only the groups that were sent carry a packed prompt, so the work is bounded too
    assert set(result.packed_by_group) == result.selected_ids
    # the cap keeps the most severe groups
    lowest_sent = min(LEVEL_RANK[group.max_level] for group in result.selected)
    not_sent = set(result.selection.not_sent)
    highest_dropped = max(
        (LEVEL_RANK[group.max_level] for group in result.groups if group.group_id in not_sent), default=-1
    )
    assert lowest_sent >= highest_dropped


def test_the_cap_is_deterministic(config: Config, tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "large.csv", rows=4_000)
    capped = config.model_copy(
        update={"selection": config.selection.model_copy(update={"max_groups_to_model": 10})}
    )
    first = run_deterministic(capped, csv_path)
    second = run_deterministic(capped, csv_path)
    assert [group.group_id for group in first.selected] == [group.group_id for group in second.selected]
    assert first.selection.not_sent == second.selection.not_sent


def test_without_a_cap_every_eligible_group_is_sent(config: Config, tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "large.csv", rows=2_000)
    uncapped = config.model_copy(
        update={"selection": config.selection.model_copy(update={"max_groups_to_model": 0})}
    )
    result = run_deterministic(uncapped, csv_path)
    assert len(result.selected) == result.selection.eligible
    assert result.selection.not_sent == []
