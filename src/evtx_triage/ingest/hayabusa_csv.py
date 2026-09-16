"""Reader for Hayabusa `all-field-info-verbose` CSV timelines.

Everything here follows measured behaviour, not documentation: the column set and
order, the encoding, the line ending, the selective quoting and the timestamp
shapes were all taken from real output in Faz 0 (ADR-0002).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

from ..models import ABBREVIATED_CHANNELS, ABBREVIATED_LEVELS, Event, IngestError, Level
from .normalize import normalize_host, parse_all_field_info, parse_timestamp, split_multi_value

EXPECTED_COLUMNS = [
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

REQUIRED_COMMAND = (
    "hayabusa.exe dfir-timeline -f <EVTX> -p all-field-info-verbose -U -O -w -q -C -b -A -o <CSV>"
)


class InputContractError(Exception):
    """The CSV does not satisfy the input contract; the message says how to fix it."""


@dataclass
class IngestResult:
    events: list[Event]
    errors: list[IngestError] = field(default_factory=list)
    data_rows: int = 0


def _fail_header(found: list[str]) -> None:
    raise InputContractError(
        "unexpected CSV header.\n"
        f"  expected columns: {', '.join(EXPECTED_COLUMNS)}\n"
        f"  found columns:    {', '.join(found)}\n"
        f"  produce the input with: {REQUIRED_COMMAND}"
    )


def _fail_abbreviated(what: str, value: str) -> None:
    raise InputContractError(
        f"this CSV was produced without -b: {what} column contains the abbreviated value {value!r}.\n"
        "  Channel abbreviations are lossy (AppLocker maps back to four channels), so the\n"
        "  dictionary key (channel, event_id) cannot be resolved (ADR-0002 section 5).\n"
        f"  re-run: {REQUIRED_COMMAND}"
    )


def read_events(path: Path, *, assume_utc: bool) -> IngestResult:
    """Parse a Hayabusa CSV into events, collecting per-row failures instead of dropping them."""
    result = IngestResult(events=[])

    # Hayabusa writes UTF-8 with no BOM and LF endings (ADR-0002 section 4).
    # utf-8-sig is used to stay liberal on input: a file that made a round trip
    # through a spreadsheet gains a BOM, and that should not break the header
    # check. newline="" lets the csv module handle quoting and both endings.
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            raise InputContractError(f"CSV file is empty: {path}") from None

        if header != EXPECTED_COLUMNS:
            if sorted(header) == sorted(EXPECTED_COLUMNS):
                # Same columns in a different order: bind by name, do not trust position.
                pass
            else:
                _fail_header(header)

        index = {name: position for position, name in enumerate(header)}

        for line_number, row in enumerate(reader, start=2):
            result.data_rows += 1
            row_id = f"R{result.data_rows:06d}"

            if len(row) != len(header):
                result.errors.append(
                    IngestError(
                        row_id=row_id,
                        line_number=line_number,
                        reason="column_count",
                        detail=f"expected {len(header)} columns, found {len(row)}",
                    )
                )
                continue

            cell = {name: row[position] for name, position in index.items()}

            level_raw = cell["Level"].strip()
            if level_raw in ABBREVIATED_LEVELS:
                _fail_abbreviated("Level", level_raw)
            channel_raw = cell["Channel"].strip()
            if channel_raw in ABBREVIATED_CHANNELS:
                _fail_abbreviated("Channel", channel_raw)

            try:
                timestamp = parse_timestamp(cell["Timestamp"], assume_utc=assume_utc)
            except ValueError as exc:
                result.errors.append(
                    IngestError(row_id=row_id, line_number=line_number, reason="timestamp", detail=str(exc))
                )
                continue

            try:
                level = Level(level_raw)
            except ValueError:
                result.errors.append(
                    IngestError(
                        row_id=row_id,
                        line_number=line_number,
                        reason="level",
                        detail=f"unknown level {level_raw!r}",
                    )
                )
                continue

            try:
                event_id = int(cell["EventID"].strip())
            except ValueError:
                result.errors.append(
                    IngestError(
                        row_id=row_id,
                        line_number=line_number,
                        reason="event_id",
                        detail=f"non-numeric EventID {cell['EventID']!r}",
                    )
                )
                continue

            record_raw = cell["RecordID"].strip()
            try:
                record_id = int(record_raw) if record_raw else None
            except ValueError:
                record_id = None
                result.errors.append(
                    IngestError(
                        row_id=row_id,
                        line_number=line_number,
                        reason="record_id",
                        detail=f"non-numeric RecordID {record_raw!r}",
                    )
                )

            fields, field_errors = parse_all_field_info(cell["AllFieldInfo"])
            for detail in field_errors:
                result.errors.append(
                    IngestError(
                        row_id=row_id, line_number=line_number, reason="all_field_info", detail=detail
                    )
                )

            result.events.append(
                Event(
                    row_id=row_id,
                    timestamp=timestamp,
                    rule_title=cell["RuleTitle"],
                    level=level,
                    computer=cell["Computer"],
                    host_norm=normalize_host(cell["Computer"]),
                    channel=channel_raw,
                    event_id=event_id,
                    mitre_tactics=split_multi_value(cell["MitreTactics"]),
                    mitre_tags=split_multi_value(cell["MitreTags"]),
                    other_tags=split_multi_value(cell["OtherTags"]),
                    record_id=record_id,
                    fields=fields,
                    rule_file=cell["RuleFile"],
                    rule_id=cell["RuleID"],
                    evtx_file=cell["EvtxFile"],
                )
            )

    return result
