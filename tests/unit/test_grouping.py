"""Grouping boundaries, driven by config thresholds rather than constants."""

from __future__ import annotations

from pathlib import Path

from evtx_triage.config import Config
from evtx_triage.grouping import build_groups
from evtx_triage.ingest.hayabusa_csv import read_events
from evtx_triage.models import LEVEL_RANK, Level
from evtx_triage.pipeline import run_deterministic
from evtx_triage.select import select_groups
from evtx_triage.timeline import build_timeline


def test_host_split_and_time_gap(config: Config, mini_csv: Path) -> None:
    result = run_deterministic(config, mini_csv)

    assert [g.group_id for g in result.groups] == ["G0001", "G0002", "G0003"]

    first, second, third = result.groups
    # Same host, events 10:00 to 10:03, the 10:30 event falls past gap_minutes.
    assert first.host == "hosta"
    assert first.row_ids == ["R000001", "R000002", "R000003", "R000007"]
    assert first.max_level is Level.medium

    assert second.host == "hostb"
    assert second.row_ids == ["R000005"]
    assert second.max_level is Level.high

    assert third.host == "hosta"
    assert third.row_ids == ["R000004"]
    assert third.max_level is Level.informational


def test_group_ids_follow_first_event_time(config: Config, mini_csv: Path) -> None:
    result = run_deterministic(config, mini_csv)
    starts = [group.start for group in result.groups]
    assert starts == sorted(starts)


def test_selection_uses_the_configured_level(config: Config, mini_csv: Path) -> None:
    result = run_deterministic(config, mini_csv)
    assert result.selected_ids == {"G0001", "G0002"}

    events = build_timeline(read_events(mini_csv, assume_utc=False).events)
    groups = build_groups(events, gap_minutes=10, max_span_minutes=120)
    everything = select_groups(groups, model_min_level=Level.informational, max_groups=0)
    assert len(everything.selected) == 3 and everything.eligible == 3 and not everything.capped
    nothing = select_groups(groups, model_min_level=Level.emergency, max_groups=0)
    assert nothing.selected == []
    capped = select_groups(groups, model_min_level=Level.informational, max_groups=1)
    assert len(capped.selected) == 1 and capped.capped and len(capped.not_sent) == 2
    # the cap keeps the most severe group, and the report can say what was left out
    assert capped.selected[0].max_level == max((group.max_level for group in groups), key=LEVEL_RANK.get)


def test_max_span_forces_a_split(mini_csv: Path) -> None:
    events = build_timeline(read_events(mini_csv, assume_utc=False).events)
    # A one-minute ceiling must break the 10:00 to 10:03 run apart.
    groups = build_groups(events, gap_minutes=10, max_span_minutes=1)
    hosta = [group for group in groups if group.host == "hosta"]
    assert len(hosta) > 2


def test_unknown_pair_is_listed(config: Config, mini_csv: Path) -> None:
    result = run_deterministic(config, mini_csv)
    assert ("Microsoft-Windows-TaskScheduler/Operational", 106) in result.unknown_pairs
    known = [e for e in result.events if e.description is not None]
    assert {e.event_id for e in known} == {1, 10, 11}
