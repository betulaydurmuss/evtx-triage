"""Ingest behaviour, checked against the shapes measured in Faz 0 (ADR-0002)."""

from __future__ import annotations

from pathlib import Path

import pytest

from evtx_triage.ingest.hayabusa_csv import EXPECTED_COLUMNS, InputContractError, read_events
from evtx_triage.ingest.normalize import parse_all_field_info, parse_timestamp
from evtx_triage.models import Level


def test_reads_every_row_and_reports_the_broken_one(mini_csv: Path) -> None:
    result = read_events(mini_csv, assume_utc=False)

    assert result.data_rows == 7
    assert len(result.events) == 6
    assert len(result.errors) == 1

    error = result.errors[0]
    assert error.row_id == "R000006"
    assert error.reason == "timestamp"


def test_row_ids_follow_file_order_not_timeline_order(mini_csv: Path) -> None:
    result = read_events(mini_csv, assume_utc=False)
    ids = [event.row_id for event in result.events]
    assert ids == ["R000001", "R000002", "R000003", "R000004", "R000005", "R000007"]


def test_empty_field_value_keeps_the_key(mini_csv: Path) -> None:
    # `RuleName: ` followed by the separator arrives as the chunk `RuleName:`,
    # because ` ¦ ` swallowed the trailing space. The key must survive.
    result = read_events(mini_csv, assume_utc=False)
    first = result.events[0]
    assert "RuleName" in first.fields
    assert first.fields["RuleName"] == ""
    assert first.fields["CommandLine"] == "whoami /all"


def test_all_three_timestamp_shapes_parse(mini_csv: Path) -> None:
    result = read_events(mini_csv, assume_utc=False)
    by_id = {event.row_id: event for event in result.events}

    assert by_id["R000001"].timestamp.microsecond == 0  # six fractional digits, all zero
    assert by_id["R000002"].timestamp.microsecond == 123456
    assert by_id["R000003"].timestamp.second == 0  # no fractional part at all
    assert by_id["R000005"].timestamp.microsecond == 500000  # three fractional digits


def test_values_and_levels_are_non_abbreviated(mini_csv: Path) -> None:
    result = read_events(mini_csv, assume_utc=False)
    levels = {event.level for event in result.events}
    assert levels <= {Level.informational, Level.low, Level.medium, Level.high}
    assert all("/" in e.channel or e.channel in {"Security", "System", "Application"} for e in result.events)


def _write_csv(path: Path, rows: list[list[str]]) -> Path:
    import csv

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(EXPECTED_COLUMNS)
        writer.writerows(rows)
    return path


def _row(level: str = "medium", channel: str = "Microsoft-Windows-Sysmon/Operational") -> list[str]:
    return [
        "2024-01-01T10:00:00.000000Z",
        "Some Rule",
        level,
        "HOSTA",
        channel,
        "1",
        "",
        "",
        "",
        "1",
        "Image: C:\\x.exe",
        "r.yml",
        "id",
        "a.evtx",
    ]


def test_abbreviated_level_is_rejected_with_the_right_command(tmp_path: Path) -> None:
    path = _write_csv(tmp_path / "abbrev.csv", [_row(level="med")])
    with pytest.raises(InputContractError) as caught:
        read_events(path, assume_utc=False)
    assert "-b" in str(caught.value)
    assert "all-field-info-verbose" in str(caught.value)


def test_abbreviated_channel_is_rejected(tmp_path: Path) -> None:
    path = _write_csv(tmp_path / "abbrev_channel.csv", [_row(channel="Sec")])
    with pytest.raises(InputContractError):
        read_events(path, assume_utc=False)


def test_unexpected_header_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "wrong.csv"
    path.write_text('"Timestamp","Computer"\n"2024-01-01T00:00:00Z","HOSTA"\n', encoding="utf-8")
    with pytest.raises(InputContractError) as caught:
        read_events(path, assume_utc=False)
    assert "expected columns" in str(caught.value)


def test_naive_timestamp_needs_an_explicit_flag() -> None:
    with pytest.raises(ValueError, match="no UTC offset"):
        parse_timestamp("2024-01-01T10:00:00", assume_utc=False)
    assert parse_timestamp("2024-01-01T10:00:00", assume_utc=True).tzinfo is not None


def test_repeated_field_keys_become_a_list() -> None:
    fields, errors = parse_all_field_info("Hashes: a ¦ Hashes: b ¦ Image: C:\\x.exe")
    assert fields["Hashes"] == ["a", "b"]
    assert errors == []


def test_unparseable_chunk_is_reported_not_dropped() -> None:
    fields, errors = parse_all_field_info("Image: C:\\x.exe ¦ garbage-without-separator")
    assert fields == {"Image": "C:\\x.exe"}
    assert len(errors) == 1


def test_service_accounts_are_recognised_with_their_domain_prefix() -> None:
    r"""Sysmon writes "NT AUTHORITY\SYSTEM" as one string, the Security log splits
    it across two fields. Both must fold to "system", otherwise service activity
    looks like a person and pulls groups apart.
    """
    from evtx_triage.ingest.normalize import normalize_user

    assert normalize_user(r"NT AUTHORITY\SYSTEM") == "system"
    assert normalize_user(r"NT AUTHORITY\NETWORK SERVICE") == "system"
    assert normalize_user(r"NT AUTHORITY\LOCAL SERVICE") == "system"
    assert normalize_user(r"EXAMPLE\WS01$") == "system"
    assert normalize_user("SYSTEM") == "system"
    assert normalize_user("-") == "system"

    # ordinary accounts keep their domain, from either shape
    assert normalize_user(r"MSEDGEWIN10\IEUser") == "msedgewin10\\ieuser"
    assert normalize_user("administrator", "EXAMPLE") == "example\\administrator"
