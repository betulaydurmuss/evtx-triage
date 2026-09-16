"""Simplified views for verifying the evaluation labels by hand (open debt, see README).

    python eval/verification_views.py                 # writes out/verification/INDEX.md and one file per item
    python eval/verification_views.py --no-retrieval  # skip the golden-query items (no embedding model needed)

One Markdown file per item, in the order the checks matter most:
1. the four priority labels and the other Faz 4 labels (docs/eval-dataset.md section 4);
2. the three golden queries with partial hits, Q07, Q14 and Q16 (section 5);
3. the sixteen Faz 7 draft labels (section 7).

Each view shows what the label claims, what to check, and a compact table of the
sample's detections with the rows each key-event matcher hits. The model's answer is
left out on purpose: seeing it first would steer the check (section 3, risk 4).

The views contain detection data from GPL samples, so they go to out/, which is never committed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from metrics import matches  # noqa: E402

from evtx_triage.config import Config, load_config  # noqa: E402
from evtx_triage.models import LEVEL_RANK, Event, Group, Level  # noqa: E402
from evtx_triage.pipeline import DeterministicResult, run_deterministic  # noqa: E402

PRIORITY_LABELS = [
    (
        "ad_group_recon",
        "The expectation was changed after the tool split this sample (risk 3). Do user01's network logon "
        "(4624) and share access (5140) come from the same source as administrator's activity? If one operator "
        "used both accounts, 'two separate stories' is wrong.",
    ),
    (
        "roguepotato_privesc",
        "The group is filed under 'system'. The exploit starts as LOCAL SERVICE and ends in a SYSTEM shell; "
        "both normalise to 'system', so the escalation is not visible in the group header. Is that acceptable?",
    ),
    (
        "sharprdp_lateral_movement",
        "Written right after the user-normalisation fix (risk 2). The key Sysmon 12/13 events carry no user and "
        "join ieuser's group only through the single-human rule. Is the whole window really one RDP session?",
    ),
    (
        "dumpert_andrewspecial_memdump",
        "Every budget decision was measured on this sample and the model's answer was seen before the label "
        "(risk 4). Are the key events the right ones, and do the keyword lists make sense without the model?",
    ),
]
OTHER_FAZ4_LABELS = [
    "dcsync_right_granted",
    "uacme_akagi_bypass",
    "mshta_rundll32_execution",
    "malseclogon_token_theft",
    "security_log_cleared",
    "system_log_cleared_unknown_event",
]
GOLDEN_QUERIES = {
    "Q07": "Expected G-016 and G-015; the scheduled-task note G-017 ranked first. Is G-017 maybe the better answer?",
    "Q14": "Expected G-026 and G-032; G-026 was not in the top 3. Are both expectations right for this group?",
    "Q16": "Expected G-002 and G-016; G-001 ranked instead of G-016. Is G-001 an acceptable answer here?",
}
CHECKLIST = [
    "Key events: do the matched rows (K1, K2 ...) show the behaviour the label names?",
    "Grouping: should these rows really be in one group (or apart, where the label says so)?",
    "Assessments: is every accepted assessment defensible from the rows alone?",
    "Keywords: would an analyst's summary of this sample use at least one must_mention word?",
]
MAX_ROWS = 40


def _short(text: str, limit: int) -> str:
    flat = " ".join(str(text).split()).replace("|", "/")
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _field_summary(event: Event) -> str:
    names = event.description.key_fields if event.description else sorted(event.fields)[:3]
    parts = [f"{name}={_short(event.field_text(name), 60)}" for name in names if event.field_text(name)]
    return "; ".join(parts[:3])


def _header_comments(path: Path) -> list[str]:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            break
        lines.append(line.lstrip("#").strip())
    return [line for line in lines if line]


def _matcher_text(matcher: dict[str, Any]) -> str:
    parts = []
    if matcher.get("channel"):
        parts.append(matcher["channel"].split("/")[0].replace("Microsoft-Windows-", ""))
    if matcher.get("event_id") is not None:
        parts.append(f"EID {matcher['event_id']}")
    if matcher.get("principal_user"):
        parts.append(f"user {matcher['principal_user']}")
    if matcher.get("rule_title_contains"):
        parts.append(f"rule contains '{matcher['rule_title_contains']}'")
    for name, value in (matcher.get("fields_contain") or {}).items():
        parts.append(f"{name} contains '{value}'")
    return ", ".join(parts)


def _stories(label: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    if label.get("key_events_same_group", True):
        return [("all key events in ONE group", label.get("key_events", []))]
    return [
        (f"story '{item['name']}' in its own group", item["key_events"]) for item in label["expected_groups"]
    ]


def _groups_table(result: DeterministicResult) -> list[str]:
    selected = result.selected_ids
    lines = [
        "| group | host | user | time (UTC) | highest level | events | to model |",
        "|---|---|---|---|---|---:|---|",
    ]
    for group in result.groups:
        lines.append(
            f"| {group.group_id} | {group.host} | {group.principal_user or '-'} | "
            f"{group.start.strftime('%H:%M:%S')}–{group.end.strftime('%H:%M:%S')} | {group.max_level.value} | "
            f"{len(group.events)} | {'yes' if group.group_id in selected else 'no'} |"
        )
    return lines


def _events_table(
    result: DeterministicResult, tags: dict[str, list[str]], only_group: str | None = None
) -> list[str]:
    group_of: dict[str, Group] = {event.row_id: group for group in result.groups for event in group.events}
    events = [
        event
        for event in result.events
        if only_group is None or group_of[event.row_id].group_id == only_group
    ]
    shown = events
    hidden = 0
    if len(events) > MAX_ROWS:
        shown = [e for e in events if LEVEL_RANK[e.level] >= LEVEL_RANK[Level.medium] or e.row_id in tags]
        hidden = len(events) - len(shown)
    lines = [
        "| match | row | time | level | channel | EID | rule | user | group | key fields |",
        "|---|---|---|---|---|---:|---|---|---|---|",
    ]
    for event in shown:
        lines.append(
            f"| {' '.join(tags.get(event.row_id, []))} | {event.row_id} | {event.timestamp.strftime('%H:%M:%S')} | "
            f"{event.level.value} | {event.channel.split('/')[0].replace('Microsoft-Windows-', '')} | "
            f"{event.event_id} | {_short(event.rule_title, 60)} | {event.principal_user or '-'} | "
            f"{group_of[event.row_id].group_id} | {_field_summary(event)} |"
        )
    if hidden:
        lines.append(f"\n_{hidden} low and informational rows without a key-event match are hidden._")
    return lines


def label_view(number: int, path: Path, config: Config, csv_dir: Path, focus: str | None) -> tuple[str, str]:
    label = yaml.safe_load(path.read_text(encoding="utf-8"))
    csv_path = csv_dir / label["csv"]
    result = run_deterministic(config, csv_path)

    tags: dict[str, list[str]] = {}
    lines = [f"# {number:02d}. Label `{path.stem}`", ""]
    comments = _header_comments(path)
    draft = any("DRAFT" in line for line in comments)
    lines += [
        f"- **Sample:** `{label['sample']}`",
        f"- **CSV:** `{label['csv']}` ({len(result.events)} detections, {len(result.groups)} groups)",
        f"- **Tactic folder:** {label.get('tactic')}",
        f"- **Status:** {'Faz 7 draft' if draft else 'Faz 4 label'}, not verified",
        "",
    ]
    if comments:
        lines += ["**What the label file says:**", ""] + [f"> {line}" for line in comments] + [""]
    if focus:
        lines += [f"**Check first:** {focus}", ""]

    lines += ["## What the label claims", ""]
    counter = 0
    for story, matchers in _stories(label):
        lines.append(f"- {story}:")
        for matcher in matchers:
            counter += 1
            tag = f"K{counter}"
            hits = [event.row_id for event in result.events if matches(event, matcher)]
            for row_id in hits:
                tags.setdefault(row_id, []).append(tag)
            lines.append(f"  - **{tag}** {_matcher_text(matcher)} → {len(hits)} row(s)")
    lines += [
        f"- acceptable assessments: {', '.join(label.get('acceptable_assessments', []))}",
        f"- must mention one of: {', '.join(label.get('must_mention_any', []))}",
        f"- must not mention: {', '.join(label.get('must_not_mention', [])) or '(nothing)'}",
        "",
        "## Checklist",
        "",
    ]
    lines += [f"- [ ] {item}" for item in CHECKLIST]
    lines += ["", "## Groups", ""] + _groups_table(result)
    lines += ["", "## Detections", ""] + _events_table(result, tags)
    lines += [
        "",
        "## When done",
        "",
        f"Add `# verified-by: <name>, <date>` as the first line of `eval/labels/expected/{path.name}`. "
        "If something is wrong, note what and the label is corrected before the metrics are rerun.",
        "",
    ]
    return f"{number:02d}_{path.stem}.md", "\n".join(lines)


def query_view(
    number: int, query: dict[str, Any], config: Config, csv_root: Path, retriever: Any
) -> tuple[str, str]:
    from evtx_triage.knowledge.guidance import load_guidance, query_for_group

    csv_path = csv_root / query["csv"]
    result = run_deterministic(config, csv_path)
    group = next(g for g in result.groups if g.group_id == query["group"])
    corpus = load_guidance(config.resolve(config.knowledge.guidance_dir))
    lines = [
        f"# {number:02d}. Golden query `{query['id']}` (guidance retrieval)",
        "",
        f"- **CSV:** `{query['csv']}`, group **{group.group_id}** ({group.host}, {group.principal_user or '-'}, "
        f"{len(group.events)} events, highest {group.max_level.value})",
        f"- **Why these notes were expected:** {query['why']}",
        f"- **Check first:** {GOLDEN_QUERIES[query['id']]}",
        "",
        "## Expected notes",
        "",
    ]
    for note_id in query["expected"]:
        note = corpus.by_id(note_id)
        lines.append(f"- **{note_id}** {note.title if note else '(missing)'}")
    lines += ["", "## What retrieval returns today (top 5)", ""]
    ranked = retriever.retrieve(group, top_k=5, min_score=config.retrieval.min_score)
    for position, item in enumerate(ranked, start=1):
        mark = "expected" if item.note.id in query["expected"] else ""
        lines.append(f"{position}. **{item.note.id}** {item.note.title} (score {item.score:.3f}) {mark}")
    lines += [
        "",
        "## The query text built from the group",
        "",
        "```",
        query_for_group(group).text,
        "```",
        "",
        "## Checklist",
        "",
        "- [ ] Do the expected notes fit this group's detections?",
        "- [ ] Would a note that ranked above them be an equally good or better answer?",
        "- [ ] Should `expected` in eval/golden_queries.yaml change?",
        "",
        f"## Detections of {group.group_id}",
        "",
    ]
    lines += _events_table(result, {}, only_group=group.group_id)
    lines += [
        "",
        "## When done",
        "",
        "Add a `verified_by: <name>, <date>` key to this query in eval/golden_queries.yaml, "
        "or change `expected` and rerun eval/retrieval_eval.py.",
        "",
    ]
    return f"{number:02d}_{query['id']}.md", "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--config", type=Path, default=Path("config/default.toml"))
    parser.add_argument("--labels", type=Path, default=Path("eval/labels/expected"))
    parser.add_argument("--csv-dir", type=Path, default=Path("data/hayabusa_csv/eval"))
    parser.add_argument("--csv-root", type=Path, default=Path("data/hayabusa_csv"))
    parser.add_argument("--queries", type=Path, default=Path("eval/golden_queries.yaml"))
    parser.add_argument("--out", type=Path, default=Path("out/verification"))
    parser.add_argument("--no-retrieval", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    config = config.model_copy(update={"pack": config.pack.model_copy(update={"token_counter": "estimate"})})
    args.out.mkdir(parents=True, exist_ok=True)

    items: list[tuple[str, str, str]] = []  # (file, title, why)
    number = 0
    labels = {path.stem: path for path in args.labels.glob("*.yaml")}

    for stem, focus in PRIORITY_LABELS:
        number += 1
        name, text = label_view(number, labels[stem], config, args.csv_dir, focus)
        (args.out / name).write_text(text, encoding="utf-8")
        items.append((name, f"label {stem}", "priority (eval-dataset §4)"))
    for stem in OTHER_FAZ4_LABELS:
        number += 1
        name, text = label_view(number, labels[stem], config, args.csv_dir, None)
        (args.out / name).write_text(text, encoding="utf-8")
        items.append((name, f"label {stem}", "Faz 4 label, lower priority"))

    if not args.no_retrieval:
        from evtx_triage.cli import ensure_models, open_retriever

        ensure_models(config, chat=False)
        retriever = open_retriever(config)
        queries = {
            item["id"]: item for item in yaml.safe_load(args.queries.read_text(encoding="utf-8"))["queries"]
        }
        for query_id in GOLDEN_QUERIES:
            number += 1
            name, text = query_view(number, queries[query_id], config, args.csv_root, retriever)
            (args.out / name).write_text(text, encoding="utf-8")
            items.append((name, f"golden query {query_id}", "partial hit (eval-dataset §5)"))

    known = {stem for stem, _ in PRIORITY_LABELS} | set(OTHER_FAZ4_LABELS)
    for stem in sorted(set(labels) - known):
        number += 1
        name, text = label_view(number, labels[stem], config, args.csv_dir, None)
        (args.out / name).write_text(text, encoding="utf-8")
        items.append((name, f"label {stem}", "Faz 7 draft (eval-dataset §7)"))

    index = [
        "# Label verification",
        "",
        "Work top to bottom. Each file shows what a label claims and the detections it rests on; "
        "the model's answers are deliberately not shown.",
        "",
        "| # | item | why | done |",
        "|---:|---|---|---|",
    ]
    for position, (name, title, why) in enumerate(items, start=1):
        index.append(f"| {position} | [{title}]({name}) | {why} | [ ] |")
    index.append("")
    (args.out / "INDEX.md").write_text("\n".join(index), encoding="utf-8")
    print(f"{len(items)} views written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
