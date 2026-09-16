"""Grouping metrics against the evaluation labels.

Answers one question per sample: did the grouping tell the story the label says
it should? Most labels expect their key events in one group. A label can also
describe several separate stories (`expected_groups`), for example two accounts
doing reconnaissance independently: each story must stay together, and the
stories must not be merged. Labels use matchers rather than row numbers, so
regenerating the CSVs does not invalidate them.

    python eval/metrics.py
    python eval/metrics.py --csv-dir data/hayabusa_csv/eval --verbose

Read docs/eval-dataset.md before trusting the numbers: the labels were drafted by
the same party that wrote the tool.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import yaml  # noqa: E402

from evtx_triage.config import load_config  # noqa: E402
from evtx_triage.models import Event, Group  # noqa: E402
from evtx_triage.pipeline import run_deterministic  # noqa: E402


def matches(event: Event, matcher: dict[str, Any]) -> bool:
    if matcher.get("channel") and event.channel != matcher["channel"]:
        return False
    if matcher.get("event_id") is not None and event.event_id != int(matcher["event_id"]):
        return False
    if matcher.get("principal_user") and event.principal_user != matcher["principal_user"]:
        return False
    needle = matcher.get("rule_title_contains")
    if needle and needle.lower() not in event.rule_title.lower():
        return False
    for name, fragment in (matcher.get("fields_contain") or {}).items():
        if str(fragment).lower() not in event.field_text(name).lower():
            return False
    return True


@dataclass
class StoryResult:
    """One set of key events that should share a group."""

    name: str
    group_ids: set[str] = field(default_factory=set)
    missing: list[int] = field(default_factory=list)

    @property
    def together(self) -> bool:
        return not self.missing and len(self.group_ids) == 1


@dataclass
class SampleResult:
    name: str
    detections: int
    groups: int
    selected: int
    stories: list[StoryResult]
    expect_single_group: bool

    @property
    def all_matchers_found(self) -> bool:
        return all(not story.missing for story in self.stories)

    @property
    def as_labelled(self) -> bool:
        if not self.all_matchers_found or not all(story.together for story in self.stories):
            return False
        if self.expect_single_group:
            return len(self.stories) == 1
        # Separate stories must land in pairwise different groups.
        placed = [next(iter(story.group_ids)) for story in self.stories]
        return len(set(placed)) == len(placed)

    def verdict(self) -> str:
        if not self.all_matchers_found:
            missing = {story.name: story.missing for story in self.stories if story.missing}
            return f"MISSING matcher(s) {missing}"
        placement = "; ".join(f"{story.name}: {', '.join(sorted(story.group_ids))}" for story in self.stories)
        return f"{'ok' if self.as_labelled else 'NOT AS LABELLED'} ({placement})"


def _stories(label: dict[str, Any]) -> tuple[list[tuple[str, list[dict[str, Any]]]], bool]:
    if label.get("key_events_same_group", True):
        return [("key events", label.get("key_events", []))], True
    sets = label.get("expected_groups") or []
    if not sets:
        raise ValueError("key_events_same_group is false but expected_groups is empty")
    return [(item["name"], item["key_events"]) for item in sets], False


def evaluate(label: dict[str, Any], csv_dir: Path, config: Any) -> SampleResult | None:
    csv_path = csv_dir / label["csv"]
    if not csv_path.is_file():
        return None

    result = run_deterministic(config, csv_path)
    group_of: dict[str, Group] = {event.row_id: group for group in result.groups for event in group.events}

    story_specs, single = _stories(label)
    stories: list[StoryResult] = []
    for name, matchers in story_specs:
        story = StoryResult(name=name)
        for position, matcher in enumerate(matchers, start=1):
            hits = [event for event in result.events if matches(event, matcher)]
            if not hits:
                story.missing.append(position)
                continue
            story.group_ids.update(group_of[event.row_id].group_id for event in hits)
        stories.append(story)

    return SampleResult(
        name=csv_path.stem,
        detections=len(result.events),
        groups=len(result.groups),
        selected=len(result.selected),
        stories=stories,
        expect_single_group=single,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", default="eval/labels/expected")
    parser.add_argument("--csv-dir", default="data/hayabusa_csv/eval")
    parser.add_argument("--config", default="config/default.toml")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    config = load_config(Path(args.config))
    label_paths = sorted(Path(args.labels).glob("*.yaml"))
    if not label_paths:
        print(f"no labels in {args.labels}", file=sys.stderr)
        return 2

    results: list[SampleResult] = []
    skipped: list[str] = []

    print(f"{'sample':<52} {'events':>6} {'groups':>6} {'sel':>4}  grouping")
    for label_path in label_paths:
        label = yaml.safe_load(label_path.read_text(encoding="utf-8"))
        try:
            outcome = evaluate(label, Path(args.csv_dir), config)
        except OSError as exc:
            skipped.append(f"{label_path.name}: unreadable CSV ({exc.strerror or exc})")
            continue
        if outcome is None:
            skipped.append(f"{label_path.name}: CSV not generated ({label['csv']})")
            continue

        results.append(outcome)
        print(
            f"{outcome.name[:52]:<52} {outcome.detections:>6} {outcome.groups:>6} "
            f"{outcome.selected:>4}  {outcome.verdict()}"
        )
        if args.verbose:
            for story in outcome.stories:
                print(f"    {story.name}: groups={sorted(story.group_ids)} missing={story.missing}")

    usable = [item for item in results if item.all_matchers_found]
    satisfied = [item for item in usable if item.as_labelled]
    single = [item for item in usable if item.expect_single_group]
    single_ok = [item for item in single if item.as_labelled]

    print()
    print(f"samples evaluated        : {len(results)}")
    print(f"matchers resolved        : {len(usable)}/{len(results)}")
    if usable:
        share = 100 * len(satisfied) / len(usable)
        print(f"grouping as labelled     : {len(satisfied)}/{len(usable)} ({share:.0f}%)")
    if single:
        print(f"  key events in one group: {len(single_ok)}/{len(single)}")
    split = len(usable) - len(single)
    if split:
        print(f"  separate stories kept apart: {len(satisfied) - len(single_ok)}/{split}")
    for line in skipped:
        print(f"skipped {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
