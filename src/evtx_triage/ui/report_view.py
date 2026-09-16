"""Read-only views over a report.json the CLI wrote.

The viewer computes nothing about the data: grouping, evidence, guidance, model
answers and warnings are read from the report exactly as the CLI produced them.
Everything here is selection, ordering and formatting, so the viewer can never
disagree with `evtx-triage triage`. A unit test keeps this module free of the
modules that do the computing.

No Streamlit import: these functions are plain data and are unit tested.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

LEVEL_ORDER = ["critical", "high", "medium", "low", "informational", "emergency"]


def load_report(path: Path) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    return payload


def provenance_rows(report: dict[str, Any]) -> list[tuple[str, str]]:
    """The 'where did this come from' table, straight from the report.

    Every field is optional: a report written by an older version of the tool must
    still open. Missing values show as "-" instead of breaking the page.
    """
    deterministic = report.get("deterministic", {})
    provenance = deterministic.get("provenance", {})
    tokens = provenance.get("tokens") or {}
    retrieval = provenance.get("retrieval") or {}
    input_section = deterministic.get("input", {})
    run = report.get("run", {})

    def text(value: Any, cut: int = 0) -> str:
        if value is None:
            return "-"
        return str(value)[:cut] if cut else str(value)

    return [
        ("schema version", text(report.get("schema_version"))),
        ("input", text(input_section.get("path"))),
        ("input sha256", text(input_section.get("sha256"))),
        ("rows parsed", f"{input_section.get('parsed_events', '-')} / {input_section.get('data_rows', '-')}"),
        ("ingest errors", str(len(deterministic.get("ingest_errors", [])))),
        ("tool version", text(provenance.get("tool_version"))),
        ("model", text(provenance.get("model_id"))),
        ("prompt", f"{text(provenance.get('prompt_version'))} ({text(provenance.get('prompt_sha256'), 12)})"),
        ("config hash", text(provenance.get("config_hash"), 12)),
        ("knowledge hash", text(provenance.get("knowledge_hash"), 12)),
        ("attack version", text(provenance.get("attack_version"))),
        ("hayabusa", f"{text(provenance.get('hayabusa_profile'))} {text(provenance.get('hayabusa_flags'))}"),
        ("token counter", text(tokens.get("counter", "-"))),
        ("retrieval", text(retrieval.get("embedding_model_id", retrieval.get("retriever", "-")))),
        ("generated at", text(run.get("generated_at"))),
        ("duration (s)", text(run.get("duration_seconds"))),
    ]


def outcomes(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["group_id"]: item for item in report.get("model", {}).get("interpretations", [])}


def groups(report: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = report.get("deterministic", {}).get("groups", [])
    return found


def group_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per group for the overview table."""
    by_group = outcomes(report)
    rows = []
    for group in groups(report):
        outcome = by_group.get(group["group_id"], {})
        evidence = group.get("evidence") or {}
        rows.append(
            {
                "group": group["group_id"],
                "level": group.get("max_level", "-"),
                "host": group.get("host", "-"),
                "user": group.get("principal_user") or "-",
                "start": str(group.get("start", ""))[11:19],
                "end": str(group.get("end", ""))[11:19],
                "events": group.get("event_count", len(group.get("events", []))),
                "to model": "yes" if group.get("selected_for_model") else "no",
                "status": outcome.get("status", "-"),
                "assessment": outcome.get("assessment", "-"),
                "warnings": len(outcome.get("warnings", [])),
                "defused tokens": evidence.get("neutralized_control_tokens") or 0,
                "prompt tokens": evidence.get("prompt_tokens") or 0,
            }
        )
    return rows


def all_warnings(report: dict[str, Any]) -> list[tuple[str, str]]:
    """(group id, warning) for every group, in group order. These are the deterministic
    warnings the CLI attached to an accepted answer, not something the viewer decides."""
    by_group = outcomes(report)
    found = []
    for group in groups(report):
        for warning in by_group.get(group["group_id"], {}).get("warnings", []):
            found.append((group["group_id"], warning))
    return found


def find_group(report: dict[str, Any], group_id: str) -> dict[str, Any] | None:
    for group in groups(report):
        if group["group_id"] == group_id:
            found: dict[str, Any] = group
            return found
    return None


def cited_row_ids(group: dict[str, Any], outcome: dict[str, Any]) -> set[str]:
    """Rows the model cited, folded lines expanded to every row they stand for."""
    entries = (group.get("evidence") or {}).get("entries", [])
    represented = {entry["row_ids"][0]: entry["row_ids"] for entry in entries}
    cited: set[str] = set()
    for item in outcome.get("what_happened", []) + outcome.get("next_steps", []):
        for row_id in item.get("evidence", []):
            cited.update(represented.get(row_id, [row_id]))
    return cited


def evidence_rows(group: dict[str, Any]) -> list[dict[str, Any]]:
    """The evidence block as the prompt showed it, one row per folded line."""
    evidence = group.get("evidence") or {}
    return [
        {
            "cite as": entry["row_ids"][0],
            "rows": entry["count"],
            "level": entry["level"],
            "first": entry["first"][11:19],
            "last": entry["last"][11:19],
            "line": entry["line"],
        }
        for entry in evidence.get("entries", [])
    ]


def _field_text(value: Any) -> str:
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    return str(value)


def event_rows(group: dict[str, Any], cited: set[str], shown: set[str]) -> list[dict[str, Any]]:
    """Every event of the group, flattened for a table."""
    rows = []
    for event in group.get("events", []):
        fields = event.get("fields") or {}
        rows.append(
            {
                "row": event["row_id"],
                "time": str(event.get("timestamp", ""))[11:19],
                "level": event.get("level", "-"),
                "channel": event.get("channel", "-"),
                "eid": event.get("event_id", 0),
                "rule": event.get("rule_title", "-"),
                "event": event.get("dictionary_title") or "UNKNOWN",
                "user": event.get("principal_user") or "-",
                "cited": event["row_id"] in cited,
                "in prompt": event["row_id"] in shown,
                "fields": "; ".join(
                    f"{name}={_field_text(value)}" for name, value in sorted(fields.items()) if value
                ),
            }
        )
    return rows


def filter_events(
    rows: list[dict[str, Any]],
    *,
    levels: list[str] | None = None,
    channels: list[str] | None = None,
    event_ids: list[int] | None = None,
    search: str = "",
    only_cited: bool = False,
    only_in_prompt: bool = False,
) -> list[dict[str, Any]]:
    """Filter the event table. Presentation only: no row is changed, just hidden."""
    needle = search.strip().lower()
    result = []
    for row in rows:
        if levels and row["level"] not in levels:
            continue
        if channels and row["channel"] not in channels:
            continue
        if event_ids and row["eid"] not in event_ids:
            continue
        if only_cited and not row["cited"]:
            continue
        if only_in_prompt and not row["in prompt"]:
            continue
        if needle:
            haystack = " ".join(
                str(row[key]) for key in ("row", "rule", "event", "user", "fields", "channel", "eid")
            ).lower()
            if needle not in haystack:
                continue
        result.append(row)
    return result


def level_options(rows: list[dict[str, Any]]) -> list[str]:
    present = {row["level"] for row in rows}
    return [level for level in LEVEL_ORDER if level in present]


def channel_options(rows: list[dict[str, Any]]) -> list[str]:
    return sorted({row["channel"] for row in rows})


def event_id_options(rows: list[dict[str, Any]]) -> list[int]:
    return sorted({int(row["eid"]) for row in rows})


def guidance_rows(group: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "note": item["id"],
            "title": item["title"],
            "score": item["score"],
            "matched": "evidence" if item["matched_prefilter"] else "closest in corpus",
            "sources": " ".join(item["sources"]),
        }
        for item in (group.get("guidance") or [])
    ]


def find_reports(root: Path) -> list[Path]:
    """report.json files under a directory, newest first."""
    root = Path(root)
    if not root.is_dir():
        return []
    found = list(root.rglob("report.json"))
    return sorted(found, key=lambda path: path.stat().st_mtime, reverse=True)


def find_csv_files(root: Path) -> list[Path]:
    root = Path(root)
    if not root.is_dir():
        return []
    return sorted(root.rglob("*.csv"), key=lambda path: path.as_posix())
