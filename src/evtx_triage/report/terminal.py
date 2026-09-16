"""Terminal renderer: the group list an analyst reads first."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

LEVEL_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "dim",
}
STATUS_STYLE = {"accepted": "green", "rejected": "yellow", "skipped": "yellow"}


def _shorten(text: str, limit: int = 96) -> str:
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def render_terminal(report: dict[str, Any], console: Console) -> None:
    deterministic = report["deterministic"]
    outcomes = {item["group_id"]: item for item in report.get("model", {}).get("interpretations", [])}

    header = Table.grid(padding=(0, 2))
    header.add_row("input", deterministic["input"]["path"])
    header.add_row(
        "rows",
        f"{deterministic['input']['parsed_events']} parsed / {deterministic['input']['data_rows']} "
        f"({len(deterministic['ingest_errors'])} ingest errors)",
    )
    header.add_row("groups", str(len(deterministic["groups"])))
    console.print(header)
    console.print()

    table = Table(show_lines=False)
    table.add_column("group")
    table.add_column("level")
    table.add_column("time (UTC)")
    table.add_column("host / user")
    table.add_column("events", justify="right")
    table.add_column("assessment")

    for group in deterministic["groups"]:
        outcome = outcomes.get(group["group_id"])
        assessment = "-"
        if outcome is not None:
            if "assessment" in outcome:
                assessment = outcome["assessment"]
                if outcome.get("warnings"):
                    assessment = f"{assessment} [bold yellow]⚠[/]"
            else:
                status = outcome["status"]
                assessment = f"[{STATUS_STYLE.get(status, 'white')}]{status}[/]"
        level = group["max_level"]
        table.add_row(
            group["group_id"],
            f"[{LEVEL_STYLE.get(level, 'white')}]{level}[/]",
            f"{group['start'][11:19]} - {group['end'][11:19]}",
            f"{group['host']} / {group.get('principal_user') or '?'}",
            str(group["event_count"]),
            assessment,
        )
    console.print(table)

    for group in deterministic["groups"]:
        outcome = outcomes.get(group["group_id"])
        if outcome is None or not outcome.get("what_happened"):
            continue
        console.print()
        console.print(f"[bold]{group['group_id']}[/bold] {group['host']}")
        for warning in outcome.get("warnings", []):
            console.print(f"  [bold yellow]warning:[/] {warning}")
        for claim in outcome["what_happened"][:2]:
            refs = ", ".join(claim["evidence"][:3])
            more = "..." if len(claim["evidence"]) > 3 else ""
            console.print(f"  - {_shorten(claim['text'])} [dim]({refs}{more})[/dim]")
        for step in outcome["next_steps"][:1]:
            console.print(f"  [dim]next:[/dim] {_shorten(step['text'])}")

    coverage = deterministic["coverage"]
    if coverage["unknown_pairs"]:
        console.print()
        console.print(
            f"[dim]{len(coverage['unknown_pairs'])} (channel, event id) pairs have no dictionary "
            f"entry and are reported as UNKNOWN[/dim]"
        )
