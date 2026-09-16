"""Total ordering of events.

The sort key is written correctly from day one because it is cheap and because
every later stage (grouping, evidence numbering, determinism) depends on it.
"""

from __future__ import annotations

from .models import Event


def sort_key(event: Event) -> tuple[object, ...]:
    # record_id may be absent; -1 keeps the key total and comparable.
    return (
        event.timestamp,
        event.host_norm,
        event.evtx_file,
        event.record_id if event.record_id is not None else -1,
        event.row_id,
    )


def build_timeline(events: list[Event]) -> list[Event]:
    """Return the events in a total, reproducible order."""
    return sorted(events, key=sort_key)
