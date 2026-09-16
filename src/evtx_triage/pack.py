"""Turn a group into the evidence block that goes into the prompt.

Repeated events are folded into one line, because a group often contains the same
detection dozens of times and spending the whole context budget on copies of one
line buys nothing. The report expands every folded line back to the full list of
row ids, so nothing is hidden from the analyst.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .models import LEVEL_RANK, Event, Group, Level
from .sanitize import neutralize
from .tokens import TokenCounter


@dataclass
class PackedEntry:
    """One evidence line, standing for one or more identical events."""

    row_ids: list[str]
    line: str
    level: Level
    first: datetime
    last: datetime
    # Control tokens found in the log values of this line and defused (sanitize.py).
    neutralized_control_tokens: int = 0

    @property
    def count(self) -> int:
        return len(self.row_ids)

    @property
    def representative(self) -> str:
        return self.row_ids[0]


@dataclass
class PackResult:
    entries: list[PackedEntry] = field(default_factory=list)
    dropped_row_ids: list[str] = field(default_factory=list)
    note: str | None = None

    @property
    def lines(self) -> list[str]:
        return [entry.line for entry in self.entries]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @property
    def included_row_ids(self) -> list[str]:
        """Every row the evidence block stands for, folded rows expanded."""
        return [row_id for entry in self.entries for row_id in entry.row_ids]

    @property
    def cited_row_ids(self) -> set[str]:
        """The ids the prompt actually shows, which is what the model may cite."""
        return {entry.representative for entry in self.entries}

    @property
    def folded_count(self) -> int:
        return sum(1 for entry in self.entries if entry.count > 1)

    @property
    def neutralized_control_tokens(self) -> int:
        return sum(entry.neutralized_control_tokens for entry in self.entries)


def _truncate(value: str, limit: int) -> str:
    collapsed = " ".join(value.split())
    if len(collapsed) <= limit:
        return collapsed
    return f"{collapsed[:limit]}...[truncated {len(collapsed) - limit} chars]"


def _field_names(event: Event) -> list[str]:
    if event.description is not None:
        return [name for name in event.description.key_fields if name in event.fields]
    # Unknown pair: show everything rather than picking fields by guesswork.
    return sorted(event.fields)


def _signature(event: Event, *, max_field_value_chars: int) -> tuple[object, ...]:
    """Two events fold together when their identifying content is identical."""
    values = tuple(
        (name, _truncate(event.field_text(name), max_field_value_chars)) for name in _field_names(event)
    )
    return (event.channel, event.event_id, event.rule_title, event.level, values)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def render_entry(events: list[Event], *, max_field_value_chars: int) -> str:
    """One evidence line for a run of identical events, before neutralisation."""
    first = events[0]
    title = first.description.title if first.description is not None else "UNKNOWN"
    pairs = ", ".join(
        f"{name}={_truncate(first.field_text(name), max_field_value_chars)}" for name in _field_names(first)
    )

    if len(events) == 1:
        marker = f"[{first.row_id}] {_stamp(first.timestamp)}"
    else:
        marker = f"[{first.row_id} x{len(events)}, {_stamp(first.timestamp)}..{_stamp(events[-1].timestamp)}]"

    return (
        f"{marker} | {first.level.value} | "
        f'{first.channel} EID {first.event_id} "{title}" | '
        f"rule: {first.rule_title}" + (f" | {pairs}" if pairs else "")
    )


def fold_events(
    group: Group, *, max_field_value_chars: int, added_tokens: tuple[str, ...]
) -> list[PackedEntry]:
    """Collapse identical events, keeping the order of their first appearance.

    Every line is neutralised here, before its tokens are counted, so the budget
    is spent on exactly the text the model receives (rule: log content is untrusted).
    """
    order: list[tuple[object, ...]] = []
    buckets: dict[tuple[object, ...], list[Event]] = {}

    for event in group.events:
        key = _signature(event, max_field_value_chars=max_field_value_chars)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(event)

    entries: list[PackedEntry] = []
    for key in order:
        members = buckets[key]
        line, replaced = neutralize(
            render_entry(members, max_field_value_chars=max_field_value_chars), added_tokens
        )
        entries.append(
            PackedEntry(
                row_ids=[member.row_id for member in members],
                line=line,
                level=members[0].level,
                first=members[0].timestamp,
                last=members[-1].timestamp,
                neutralized_control_tokens=replaced,
            )
        )
    return entries


def pack_group(
    group: Group,
    *,
    budget_tokens: int,
    counter: TokenCounter,
    max_field_value_chars: int,
    keep_from_level: Level = Level.medium,
) -> PackResult:
    """Fold the group's events and drop the least important lines if needed.

    A line costs its own tokens plus one for the newline. The pipeline still
    counts the assembled prompt afterwards, because tokens can merge across a
    line break; this sum is the first cut, not the guarantee.
    """
    entries = fold_events(
        group, max_field_value_chars=max_field_value_chars, added_tokens=counter.added_tokens
    )
    costs = {id(entry): counter.count(entry.line) + 1 for entry in entries}

    def cost(entry: PackedEntry) -> int:
        return costs[id(entry)]

    if sum(cost(entry) for entry in entries) <= budget_tokens:
        return PackResult(entries=entries)

    threshold = LEVEL_RANK[keep_from_level]
    kept: list[PackedEntry] = []
    used = 0

    for important in (True, False):
        for entry in entries:
            if (LEVEL_RANK[entry.level] >= threshold) is not important or entry in kept:
                continue
            if used + cost(entry) > budget_tokens:
                continue
            kept.append(entry)
            used += cost(entry)

    kept_ids = {id(entry) for entry in kept}
    ordered = [entry for entry in entries if id(entry) in kept_ids]
    dropped = [row_id for entry in entries if id(entry) not in kept_ids for row_id in entry.row_ids]
    return PackResult(entries=ordered, dropped_row_ids=dropped, note=drop_note(len(dropped), budget_tokens))


def drop_note(dropped_rows: int, budget_tokens: int) -> str:
    """The NOTE line added to the prompt when rows were dropped."""
    return (
        f"{dropped_rows} evidence rows did not fit the context budget "
        f"({budget_tokens} tokens); lowest-severity rows were dropped first"
    )


# The widest note the prompt can carry. The evidence budget reserves room for it
# up front, so dropping rows can never push the prompt past max_input_tokens.
WIDEST_DROP_NOTE = drop_note(999_999, 999_999)
