"""Markdown report.

The deterministic part is always printed, whatever the model said or failed to
say. Model claims link to the evidence line they cite, so a reader can check any
statement without leaving the page.
"""

from __future__ import annotations

import re
from typing import Any

ROW_REFERENCE = re.compile(r"\b(R\d{6})\b")


def _anchor(row_id: str) -> str:
    return row_id.lower()


def _link_rows(text: str, known: set[str]) -> str:
    """Turn row ids inside model text into links to their evidence line."""
    return ROW_REFERENCE.sub(
        lambda match: (
            f"[{match.group(1)}](#{_anchor(match.group(1))})" if match.group(1) in known else match.group(1)
        ),
        text,
    )


def _evidence_refs(row_ids: list[str], known: set[str]) -> str:
    return ", ".join(f"[{row_id}](#{_anchor(row_id)})" if row_id in known else row_id for row_id in row_ids)


def render_markdown(report: dict[str, Any]) -> str:
    deterministic = report["deterministic"]
    provenance = deterministic["provenance"]
    model_section = report.get("model", {})
    outcomes = {item["group_id"]: item for item in model_section.get("interpretations", [])}

    lines: list[str] = []
    add = lines.append

    add("# Triage report")
    add("")
    add(f"- Input: `{deterministic['input']['path']}`")
    add(f"- Input SHA256: `{deterministic['input']['sha256']}`")
    add(
        f"- Rows: {deterministic['input']['data_rows']} parsed, "
        f"{len(deterministic['ingest_errors'])} ingest errors"
    )
    add(f"- Groups: {len(deterministic['groups'])}")
    add(
        f"- Tool {provenance['tool_version']}, config `{provenance['config_hash'][:12]}`, "
        f"knowledge `{provenance['knowledge_hash'][:12]}`, ATT&CK {provenance['attack_version']}"
    )
    if model_section.get("enabled"):
        add(f"- Model: `{provenance['model_id']}`, prompt `{provenance['prompt_version']}`")
    else:
        add("- Model: not used (`--no-llm`)")
    add("")

    for group in deterministic["groups"]:
        outcome = outcomes.get(group["group_id"])
        add(f"## {group['group_id']} - {group['host']} - {group.get('principal_user') or 'unknown user'}")
        add("")
        add("| | |")
        add("|---|---|")
        add(f"| Time (UTC) | {group['start']} to {group['end']} |")
        add(f"| Events | {group['event_count']} |")
        add(f"| Highest level | **{group['max_level']}** |")
        add(f"| Sent to model | {'yes' if group['selected_for_model'] else 'no'} |")
        if outcome is not None:
            add(f"| Model outcome | {outcome['status']} |")
            if "assessment" in outcome:
                flag = " ⚠ see warning" if outcome.get("warnings") else ""
                add(f"| Assessment | **{outcome['assessment']}**{flag} |")
        add("")
        for warning in (outcome or {}).get("warnings", []):
            add(f"> **Warning:** {warning}")
            add("")

        evidence = group.get("evidence")
        known = set(evidence["included_row_ids"]) if evidence else set()

        if outcome is not None and outcome.get("what_happened"):
            add("### What appears to have happened")
            add("")
            for claim in outcome["what_happened"]:
                refs = _evidence_refs(claim["evidence"], known)
                add(f"- {_link_rows(claim['text'], known)}  \n  Evidence: {refs}")
            add("")

        if outcome is not None and outcome.get("next_steps"):
            add("### Suggested next steps")
            add("")
            for step in outcome["next_steps"]:
                refs = _evidence_refs(step["evidence"], known)
                guidance = f" Guidance: {', '.join(step['guidance'])}." if step.get("guidance") else ""
                add(f"- {_link_rows(step['text'], known)}  \n  Evidence: {refs}.{guidance}")
            add("")

        guidance = group.get("guidance")
        if guidance:
            add("### Investigation guidance")
            add("")
            for item in guidance:
                where = (
                    "matched this group's evidence" if item["matched_prefilter"] else "closest in the corpus"
                )
                sources = ", ".join(f"<{url}>" for url in item["sources"])
                heading = f"- **{item['id']}** {item['title']} (score {item['score']:.3f}, {where})"
                add(f"{heading}  \n  Sources: {sources}")
            add("")
        elif guidance is not None:
            add("_No guidance note was retrieved for this group._")
            add("")

        if outcome is not None and outcome["status"] in {"rejected", "skipped"} and outcome["reasons"]:
            add(f"> Model interpretation {outcome['status']}: " + "; ".join(outcome["reasons"]))
            add("")

        if evidence:
            add("### Evidence")
            add("")
            if evidence.get("neutralized_control_tokens"):
                add(
                    f"> **Warning:** {evidence['neutralized_control_tokens']} chat control token(s) "
                    "such as `<|im_end|>` were found in this group's log data and defused before "
                    "the prompt. Someone may have tried to steer the model; read the raw events."
                )
                add("")
            for entry in evidence["entries"]:
                anchors = "".join(f'<a id="{_anchor(row_id)}"></a>' for row_id in entry["row_ids"])
                suffix = (
                    f"  _({entry['count']} rows: {', '.join(entry['row_ids'])})_"
                    if entry["count"] > 1
                    else ""
                )
                add(f"- {anchors}`{entry['line']}`{suffix}")
            if evidence["dropped_row_ids"]:
                add("")
                add(f"> {evidence['note']}")
                add(f"> Dropped rows: {', '.join(evidence['dropped_row_ids'])}")
            add("")
        else:
            add("_Below the model threshold; deterministic summary only._")
            add("")
            add("| Row | Time | Level | Event | Rule |")
            add("|---|---|---|---|---|")
            for event in group["events"]:
                title = event["dictionary_title"] or "UNKNOWN"
                add(
                    f"| {event['row_id']} | {event['timestamp']} | {event['level']} | "
                    f"{event['channel']} EID {event['event_id']} - {title} | {event['rule_title']} |"
                )
            add("")

    coverage = deterministic["coverage"]
    add("## Appendix")
    add("")
    add(f"- Dictionary entries: {coverage['dictionary_entries']}")
    if coverage["unknown_pairs"]:
        pairs = ", ".join(f"{item['channel']} EID {item['event_id']}" for item in coverage["unknown_pairs"])
        add(f"- Events with no dictionary entry: {pairs}")
    if coverage["unknown_tactic_abbreviations"]:
        add(f"- Unmapped tactics: {', '.join(coverage['unknown_tactic_abbreviations'])}")
    if coverage["unknown_technique_ids"]:
        add(f"- Unmapped ATT&CK identifiers: {', '.join(coverage['unknown_technique_ids'])}")
    if deterministic["ingest_errors"]:
        add("")
        add("### Ingest errors")
        add("")
        add("| Row | Line | Reason | Detail |")
        add("|---|---|---|---|")
        for error in deterministic["ingest_errors"]:
            add(f"| {error['row_id']} | {error['line_number']} | {error['reason']} | {error['detail']} |")
    add("")

    return "\n".join(lines)
