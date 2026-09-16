"""Decide which groups are worth a model interpretation."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import LEVEL_RANK, Group, Level


def is_selected(group: Group, *, model_min_level: Level) -> bool:
    return LEVEL_RANK[group.max_level] >= LEVEL_RANK[model_min_level]


@dataclass
class Selection:
    """Which groups go to the model, and which were left out because of the cap."""

    selected: list[Group] = field(default_factory=list)
    eligible: int = 0
    not_sent: list[str] = field(default_factory=list)

    @property
    def capped(self) -> bool:
        return bool(self.not_sent)


def select_groups(groups: list[Group], *, model_min_level: Level, max_groups: int) -> Selection:
    """Groups reaching the configured level, at most `max_groups` of them.

    The cap exists because the input size is not bounded: a 100,000 row timeline
    produced 15,362 groups above the threshold in the Faz 8 test, which is about
    64 hours of model time on the reference hardware. Without a cap the tool would
    simply run for days; with it the run is finite and the report says what was
    left out.

    The cap keeps the most severe groups, earliest first, so the choice is
    deterministic and the same input always yields the same report.
    """
    eligible = [group for group in groups if is_selected(group, model_min_level=model_min_level)]
    if max_groups <= 0 or len(eligible) <= max_groups:
        return Selection(selected=eligible, eligible=len(eligible))

    ranked = sorted(eligible, key=lambda group: (-LEVEL_RANK[group.max_level], group.start, group.group_id))
    keep = {group.group_id for group in ranked[:max_groups]}
    return Selection(
        selected=[group for group in eligible if group.group_id in keep],
        eligible=len(eligible),
        not_sent=[group.group_id for group in eligible if group.group_id not in keep],
    )
