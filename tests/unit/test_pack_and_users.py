"""User splitting and evidence folding."""

from __future__ import annotations

from pathlib import Path

from evtx_triage.config import Config
from evtx_triage.models import Level
from evtx_triage.pack import pack_group
from evtx_triage.pipeline import run_deterministic
from evtx_triage.tokens import EstimateCounter

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
MULTI = FIXTURES / "multi_user.csv"


def test_two_humans_in_one_window_get_their_own_groups(config: Config) -> None:
    result = run_deterministic(config, MULTI)
    by_user = {(group.host, group.principal_user): group for group in result.groups}

    assert ("ws01", "example\\alice") in by_user
    assert ("ws01", "example\\bob") in by_user
    # events without a human account stay in their own bucket instead of being
    # attached to one of the two accounts by guesswork
    assert ("ws01", "system") in by_user


def test_single_human_window_keeps_service_events_together(config: Config) -> None:
    result = run_deterministic(config, MULTI)
    carol = next(group for group in result.groups if group.principal_user == "example\\carol")
    assert carol.host == "ws02"
    assert len(carol.events) == 2  # the file-create event has no user and still belongs here


def test_machine_account_counts_as_system(config: Config) -> None:
    result = run_deterministic(config, MULTI)
    system_group = next(
        group for group in result.groups if group.host == "ws01" and group.principal_user == "system"
    )
    # R000012 runs as EXAMPLE\WS01$, a machine account
    assert "R000012" in system_group.row_ids


def test_identical_events_fold_into_one_line(config: Config) -> None:
    result = run_deterministic(config, MULTI)
    group = next(group for group in result.selected if group.principal_user == "system")
    packed = result.packed_by_group[group.group_id]

    folded = [entry for entry in packed.entries if entry.count > 1]
    assert len(folded) == 1
    assert folded[0].count == 8
    assert "x8" in folded[0].line
    # the line names the span the folded rows cover
    assert "2024-03-01T08:00:10Z..2024-03-01T08:00:17Z" in folded[0].line


def test_folding_hides_nothing_from_the_report(config: Config) -> None:
    result = run_deterministic(config, MULTI)
    group = next(group for group in result.selected if group.principal_user == "system")
    packed = result.packed_by_group[group.group_id]

    # three lines stand for ten rows, and every row id is still reported
    assert len(packed.entries) == 3
    assert len(packed.included_row_ids) == 10
    assert set(packed.included_row_ids) == set(group.row_ids)


def test_only_shown_ids_may_be_cited(config: Config) -> None:
    result = run_deterministic(config, MULTI)
    group = next(group for group in result.selected if group.principal_user == "system")
    packed = result.packed_by_group[group.group_id]

    # the prompt shows one representative per folded line
    assert packed.cited_row_ids == {"R000002", "R000010", "R000012"}
    assert "R000003" in packed.included_row_ids
    assert "R000003" not in packed.cited_row_ids


def test_budget_drops_low_severity_first(config: Config) -> None:
    result = run_deterministic(config, MULTI)
    group = next(group for group in result.selected if group.principal_user == "system")

    # Wide enough for the medium line, too narrow for everything.
    packed = pack_group(
        group,
        budget_tokens=200,
        counter=EstimateCounter(config.pack.chars_per_token),
        max_field_value_chars=config.pack.max_field_value_chars,
    )

    assert packed.dropped_row_ids
    assert packed.note is not None
    kept_levels = {entry.level for entry in packed.entries}
    assert Level.medium in kept_levels
    assert Level.informational not in kept_levels
