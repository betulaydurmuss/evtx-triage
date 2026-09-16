"""Canonical JSON report.

The `deterministic` subtree is a pure function of the input CSV, the knowledge
base and the config, so two runs produce byte-identical bytes there. Anything
that cannot be reproduced (wall clock, durations) lives under `run`.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import Config
from ..ingest.hayabusa_csv import IngestResult
from ..knowledge.guidance import RetrievedNote
from ..models import SCHEMA_VERSION, Event, Group, InterpretationOutcome
from ..pack import PackResult


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _event_json(event: Event) -> dict[str, Any]:
    return {
        "row_id": event.row_id,
        "timestamp": _iso(event.timestamp),
        "level": event.level.value,
        "computer": event.computer,
        "host": event.host_norm,
        "channel": event.channel,
        "event_id": event.event_id,
        "record_id": event.record_id,
        "rule_title": event.rule_title,
        "rule_id": event.rule_id,
        "evtx_file": event.evtx_file,
        "dictionary_title": event.description.title if event.description else None,
        "known_event": event.description is not None,
        "principal_user": event.principal_user,
        "mitre_tactics": event.mitre_tactics,
        "tactics_resolved": event.tactics_resolved,
        "mitre_tags": event.mitre_tags,
        "techniques_resolved": event.techniques_resolved,
        "other_tags": event.other_tags,
        "fields": event.fields,
    }


def _group_json(
    group: Group,
    *,
    selected: bool,
    packed: PackResult | None,
    guidance: list[RetrievedNote] | None,
    prompt_tokens: int | None,
    neutralized: int | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "group_id": group.group_id,
        "host": group.host,
        "start": _iso(group.start),
        "end": _iso(group.end),
        "max_level": group.max_level.value,
        "principal_user": group.principal_user,
        "event_count": len(group.events),
        "selected_for_model": selected,
        "events": [_event_json(event) for event in group.events],
    }
    if packed is not None:
        payload["evidence"] = {
            "lines": packed.lines,
            "entries": [
                {
                    "line": entry.line,
                    "row_ids": entry.row_ids,
                    "count": entry.count,
                    "level": entry.level.value,
                    "first": _iso(entry.first),
                    "last": _iso(entry.last),
                }
                for entry in packed.entries
            ],
            "included_row_ids": packed.included_row_ids,
            "cited_row_ids": sorted(packed.cited_row_ids),
            "dropped_row_ids": packed.dropped_row_ids,
            "folded_lines": packed.folded_count,
            "note": packed.note,
            # Chat-template markers found in log values and defused before the prompt
            # (sanitize.py). Non-zero means someone wrote them into the log: look closer.
            "neutralized_control_tokens": neutralized,
            "prompt_tokens": prompt_tokens,
        }
    if guidance is not None:
        payload["guidance"] = [
            {
                "id": item.note.id,
                "title": item.note.title,
                # Rounded so the deterministic section does not carry float noise.
                "score": round(item.score, 6),
                "matched_prefilter": item.matched_prefilter,
                "sources": item.note.sources,
            }
            for item in guidance
        ]
    return payload


def _outcome_json(outcome: InterpretationOutcome) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "group_id": outcome.group_id,
        "status": outcome.status,
        "attempts": outcome.attempts,
        "reasons": outcome.reasons,
        "warnings": outcome.warnings,
        "duration_seconds": outcome.duration_seconds,
    }
    if outcome.interpretation is not None:
        payload["assessment"] = outcome.interpretation.assessment.value
        payload["what_happened"] = [
            {"text": claim.text, "evidence": claim.evidence} for claim in outcome.interpretation.what_happened
        ]
        payload["next_steps"] = [
            {"text": step.text, "evidence": step.evidence, "guidance": step.guidance}
            for step in outcome.interpretation.next_steps
        ]
    return payload


def build_report(
    *,
    config: Config,
    config_path: Path,
    input_path: Path,
    ingest: IngestResult,
    groups: list[Group],
    selected_ids: set[str],
    selection: dict[str, Any] | None = None,
    packed_by_group: dict[str, PackResult],
    outcomes: list[InterpretationOutcome],
    unknown_pairs: list[tuple[str, int]],
    unknown_tactics: list[str],
    unknown_techniques: list[str],
    dictionary_entries: int,
    knowledge_hash: str,
    attack_version: str,
    llm_enabled: bool,
    duration_seconds: float,
    retrieved_by_group: dict[str, list[RetrievedNote]] | None = None,
    retrieval_provenance: dict[str, object] | None = None,
    prompt_sha256: str | None = None,
    audit: list[dict[str, Any]] | None = None,
    prompt_tokens_by_group: dict[str, int] | None = None,
    neutralized_by_group: dict[str, int] | None = None,
    token_provenance: dict[str, object] | None = None,
) -> dict[str, Any]:
    deterministic: dict[str, Any] = {
        "provenance": {
            "tool_version": __version__,
            "prompt_version": config.llm.prompt_version if llm_enabled else None,
            "prompt_sha256": prompt_sha256 if llm_enabled else None,
            "config_path": str(config_path),
            "config_hash": config.hash(),
            "config_values": config.effective_values(),
            "knowledge_hash": knowledge_hash,
            "attack_version": attack_version,
            "hayabusa_profile": "all-field-info-verbose",
            "hayabusa_flags": "-U -O -w -q -C -b -A",
            "model_id": config.llm.model_id if llm_enabled else None,
            "retrieval": retrieval_provenance or {"retriever": "none"},
            "tokens": token_provenance or {},
        },
        "input": {
            "path": str(input_path),
            "sha256": file_sha256(input_path),
            "data_rows": ingest.data_rows,
            "parsed_events": len(ingest.events),
        },
        "ingest_errors": [error.model_dump(mode="json") for error in ingest.errors],
        "coverage": {
            "dictionary_entries": dictionary_entries,
            "unknown_pairs": [{"channel": channel, "event_id": eid} for channel, eid in unknown_pairs],
            "unknown_tactic_abbreviations": unknown_tactics,
            "unknown_technique_ids": unknown_techniques,
        },
        # Which groups the model saw, and which eligible ones the cap left out.
        "selection": selection or {},
        "groups": [
            _group_json(
                group,
                selected=group.group_id in selected_ids,
                packed=packed_by_group.get(group.group_id),
                guidance=(retrieved_by_group or {}).get(group.group_id)
                if group.group_id in selected_ids
                else None,
                prompt_tokens=(prompt_tokens_by_group or {}).get(group.group_id),
                neutralized=(neutralized_by_group or {}).get(group.group_id),
            )
            for group in groups
        ],
    }

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "generated_at": _iso(datetime.now(UTC)),
            "duration_seconds": round(duration_seconds, 3),
            "llm_enabled": llm_enabled,
        },
        "deterministic": deterministic,
        "model": {
            "enabled": llm_enabled,
            "interpretations": [_outcome_json(outcome) for outcome in outcomes],
        },
    }
    if audit is not None:
        # Raw prompts and responses: useful for review, never part of the deterministic section.
        report["audit"] = audit
    return report


def dump_json(payload: dict[str, Any]) -> str:
    """Canonical serialisation: sorted keys, stable spacing, UTF-8 text preserved."""
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def write_report(payload: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "report.json"
    target.write_text(dump_json(payload), encoding="utf-8")
    return target
