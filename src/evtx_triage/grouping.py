"""Group events into activity windows: host, then time proximity, then account.

All thresholds come from the config, never from a constant in this file
(rule: no hidden defaults).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .models import LEVEL_RANK, Event, Group, Level

SYSTEM_USER = "system"


def _max_level(events: list[Event]) -> Level:
    return max((e.level for e in events), key=lambda level: LEVEL_RANK[level])


def _time_clusters(events: list[Event], *, gap_limit: timedelta, span_limit: timedelta) -> list[list[Event]]:
    """Split one host's timeline wherever the silence or the span gets too large."""
    clusters: list[list[Event]] = []
    current: list[Event] = []
    for event in events:
        if current:
            too_far = event.timestamp - current[-1].timestamp > gap_limit
            too_long = event.timestamp - current[0].timestamp > span_limit
            if too_far or too_long:
                clusters.append(current)
                current = []
        current.append(event)
    if current:
        clusters.append(current)
    return clusters


def _human(event: Event) -> str | None:
    """The account for a user split, or None for system and unattributed events."""
    user = event.principal_user
    if user is None or user == SYSTEM_USER:
        return None
    return user


def split_by_user(cluster: list[Event]) -> list[tuple[str | None, list[Event]]]:
    """Split a time cluster by principal user (grouping step 3).

    One human account in the window means the window is about that account, and
    the service and machine activity in it belongs to the same story. Two or more
    accounts means each gets its own group and the unattributed events are kept
    separately rather than being assigned to a guess.
    """
    humans = sorted({user for user in (_human(event) for event in cluster) if user is not None})

    if len(humans) <= 1:
        return [(humans[0] if humans else SYSTEM_USER, cluster)]

    by_user: dict[str, list[Event]] = defaultdict(list)
    shared: list[Event] = []
    for event in cluster:
        user = _human(event)
        if user is None:
            shared.append(event)
        else:
            by_user[user].append(event)

    parts: list[tuple[str | None, list[Event]]] = [(user, by_user[user]) for user in humans]
    if shared:
        parts.append((SYSTEM_USER, shared))
    return parts


def build_groups(events: list[Event], *, gap_minutes: int, max_span_minutes: int) -> list[Group]:
    """Cluster timeline-ordered events by host, time proximity and account."""
    gap_limit = timedelta(minutes=gap_minutes)
    span_limit = timedelta(minutes=max_span_minutes)

    by_host: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_host[event.host_norm].append(event)

    parts: list[tuple[str | None, list[Event]]] = []
    for host in sorted(by_host):
        for cluster in _time_clusters(by_host[host], gap_limit=gap_limit, span_limit=span_limit):
            parts.extend(split_by_user(cluster))

    # Group ids follow the first event's position in the timeline.
    parts.sort(key=lambda part: (part[1][0].timestamp, part[1][0].host_norm, part[1][0].row_id))

    return [
        Group(
            group_id=f"G{position:04d}",
            host=members[0].host_norm,
            start=members[0].timestamp,
            end=members[-1].timestamp,
            max_level=_max_level(members),
            events=members,
            principal_user=user,
        )
        for position, (user, members) in enumerate(parts, start=1)
    ]
