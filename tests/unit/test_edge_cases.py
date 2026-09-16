"""Awkward but legal CSV shapes, and the ones that must be reported rather than dropped."""

from __future__ import annotations

from pathlib import Path

from evtx_triage.config import Config
from evtx_triage.ingest.hayabusa_csv import read_events
from evtx_triage.pipeline import run_deterministic

EDGE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic" / "edge_cases.csv"


def _events() -> dict[str, object]:
    result = read_events(EDGE, assume_utc=False)
    return {event.row_id: event for event in result.events}


def test_quoted_comma_and_doubled_quote_survive() -> None:
    events = _events()
    first = events["R000001"]
    assert first.rule_title == "Rule, with comma"  # type: ignore[union-attr]
    assert first.field_text("CommandLine") == 'powershell -c "Write-Host a,b"'  # type: ignore[union-attr]


def test_empty_all_field_info_and_missing_record_id() -> None:
    events = _events()
    second = events["R000002"]
    assert second.fields == {}  # type: ignore[union-attr]
    assert second.record_id is None  # type: ignore[union-attr]


def test_repeated_keys_and_colons_inside_values() -> None:
    events = _events()
    third = events["R000003"]
    assert third.fields["Hashes"] == ["SHA256=AABB", "MD5=CCDD"]  # type: ignore[index,union-attr]
    assert third.field_text("Image") == r"C:\tools\x.exe"  # type: ignore[union-attr]
    assert third.mitre_tactics == ["Exec", "Stealth"]  # type: ignore[union-attr]
    assert third.mitre_tags == ["T1059.001", "T1027"]  # type: ignore[union-attr]


def test_separator_inside_a_value_is_reported_not_silently_mangled() -> None:
    # A command line that itself contains " | " (the Hayabusa separator) cannot be
    # told apart from a field boundary. The fragment must surface as an ingest
    # error; the rest of the row still parses.
    result = read_events(EDGE, assume_utc=False)
    errors = [error for error in result.errors if error.row_id == "R000004"]
    assert len(errors) == 1
    assert errors[0].reason == "all_field_info"

    event = next(event for event in result.events if event.row_id == "R000004")
    assert event.field_text("Image") == r"C:\Windows\cmd.exe"


def test_unknown_level_and_bad_event_id_are_row_errors() -> None:
    result = read_events(EDGE, assume_utc=False)
    reasons = {error.row_id: error.reason for error in result.errors}
    assert reasons["R000005"] == "level"
    assert reasons["R000006"] == "event_id"

    parsed = {event.row_id for event in result.events}
    assert "R000005" not in parsed
    assert "R000006" not in parsed
    # every other row still made it through
    assert parsed == {"R000001", "R000002", "R000003", "R000004", "R000007"}


def test_bom_is_tolerated(tmp_path: Path) -> None:
    # Hayabusa never writes a BOM, but a round trip through a spreadsheet adds one.
    target = tmp_path / "bom.csv"
    target.write_bytes(b"\xef\xbb\xbf" + EDGE.read_bytes())
    assert read_events(target, assume_utc=False).data_rows == 7


def test_crlf_input_is_tolerated(tmp_path: Path) -> None:
    target = tmp_path / "crlf.csv"
    target.write_bytes(EDGE.read_bytes().replace(b"\n", b"\r\n"))
    result = read_events(target, assume_utc=False)
    assert result.data_rows == 7
    assert len(result.events) == 5


def test_unknown_attack_identifiers_are_listed_not_guessed(config: Config) -> None:
    result = run_deterministic(config, EDGE)
    assert "Teleport" in result.unknown_tactics
    assert "T9999" in result.unknown_techniques
    # known abbreviations still resolve to their ATT&CK names
    third = next(event for event in result.events if event.row_id == "R000003")
    assert third.tactics_resolved == ["Execution", "Stealth"]
