"""Checks against the real EVTX-ATTACK-SAMPLES timelines.

The sample data is GPL licensed and never committed, so these tests skip when
`data/` is absent. Regenerate the CSVs with scripts/generate_sample_csvs.py to run them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evtx_triage.config import Config
from evtx_triage.ingest.hayabusa_csv import InputContractError, read_events
from evtx_triage.pipeline import run_deterministic
from evtx_triage.report.json_report import dump_json

REPO_ROOT = Path(__file__).resolve().parents[2]
CSV_DIR = REPO_ROOT / "data" / "hayabusa_csv"


def _sample_csvs() -> list[Path]:
    if not CSV_DIR.is_dir():
        return []
    # faz0_all.csv and faz0_single.csv were produced without -b on purpose and
    # are used by the rejection test below.
    return sorted(
        path
        for path in [*CSV_DIR.glob("*.csv"), *(CSV_DIR / "by_tactic").glob("*.csv")]
        if not path.name.endswith(("faz0_all.csv", "faz0_single.csv"))
    )


SAMPLES = _sample_csvs()
needs_data = pytest.mark.skipif(not SAMPLES, reason="sample CSVs not generated (data/ is git-ignored)")


@needs_data
@pytest.mark.parametrize("csv_path", SAMPLES, ids=lambda path: path.name)
def test_every_sample_parses_without_errors(csv_path: Path) -> None:
    result = read_events(csv_path, assume_utc=False)
    assert result.data_rows > 0
    assert len(result.events) == result.data_rows
    assert result.errors == []


@needs_data
@pytest.mark.parametrize("csv_path", SAMPLES, ids=lambda path: path.name)
def test_every_sample_is_deterministic(config: Config, csv_path: Path) -> None:
    first = run_deterministic(config, csv_path)
    second = run_deterministic(config, csv_path)
    assert dump_json({"g": [g.model_dump(mode="json") for g in first.groups]}) == dump_json(
        {"g": [g.model_dump(mode="json") for g in second.groups]}
    )


@needs_data
def test_abbreviated_samples_are_rejected() -> None:
    for name in ("faz0_all.csv", "faz0_single.csv"):
        path = CSV_DIR / name
        if not path.is_file():
            pytest.skip(f"{name} not generated")
        with pytest.raises(InputContractError, match="without -b"):
            read_events(path, assume_utc=False)


@needs_data
def test_channels_and_levels_are_all_non_abbreviated() -> None:
    seen_channels: set[str] = set()
    seen_levels: set[str] = set()
    for csv_path in SAMPLES:
        for event in read_events(csv_path, assume_utc=False).events:
            seen_channels.add(event.channel)
            seen_levels.add(event.level.value)
    assert seen_levels <= {"informational", "low", "medium", "high", "critical", "emergency"}
    # Every observed channel is either a full provider path or a plain log name.
    assert all("/" in name or name in {"Security", "System", "Application"} for name in seen_channels)


@needs_data
def test_every_tactic_abbreviation_in_the_samples_is_mapped(config: Config) -> None:
    unmapped: set[str] = set()
    for csv_path in SAMPLES:
        unmapped.update(run_deterministic(config, csv_path).unknown_tactics)
    assert unmapped == set(), f"tactic abbreviations missing from the ATT&CK table: {sorted(unmapped)}"


@needs_data
def test_dictionary_coverage_matches_the_documented_gap(config: Config) -> None:
    """The uncovered pairs must be exactly the ones docs/kb-coverage.md explains.

    BITS-Client 59 was added on 2026-09-15; nine pairs remain by decision.

    A new gap should force a decision (write the entry, or document why not),
    not slip through unnoticed.
    """
    documented = {
        ("Application", 325),
        ("Application", 326),
        ("Application", 327),
        ("Application", 1040),
        ("Application", 1042),
        ("Application", 15457),
        ("Application", 33205),
        ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149),
        ("System", 104),
    }
    found: set[tuple[str, int]] = set()
    for csv_path in SAMPLES:
        found.update(run_deterministic(config, csv_path).unknown_pairs)
    assert found == documented


@needs_data
def test_every_attack_tag_in_the_samples_resolves(config: Config) -> None:
    unresolved: set[str] = set()
    for csv_path in SAMPLES:
        unresolved.update(run_deterministic(config, csv_path).unknown_techniques)
    assert unresolved == set(), f"ATT&CK identifiers missing from the catalogue: {sorted(unresolved)}"
