"""Deterministic validation of model output.

Structural rules:
  1. valid JSON after stripping reasoning blocks, matching schema, the right group;
  2. every entry cites at least one evidence row;
  3. every evidence id was shown in the prompt, every guidance id was retrieved.

Content rules, applied to the free text of every entry:
  4. `EID <n>` mentions name an event id present in the group;
  5. ATT&CK technique ids appear in the group's tags or in a retrieved note;
  6. IPv4 addresses appear somewhere in the group's field values.

What this does NOT check, and cannot: that a cited row supports the sentence
next to it, or that a retrieved note fits the group. A citation passing here
exists; it is not thereby correct (README, "Sınırlılıklar").
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from .knowledge.guidance import TECHNIQUE_ID, RetrievedNote
from .models import LEVEL_RANK, Assessment, Group, GroupInterpretation, InterpretationOutcome, Level
from .pack import PackResult

THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
FENCED_JSON = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

EID_MENTION = re.compile(r"\bEID\s*[:#]?\s*(\d{1,6})\b", re.IGNORECASE)
TECHNIQUE_MENTION = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = re.compile(rf"(?<!\d)(?<!\d\.){_OCTET}(?:\.{_OCTET}){{3}}(?!\d)(?!\.\d)")


@dataclass(frozen=True)
class ValidationContext:
    """Everything the validator may accept for one group, derived from the evidence."""

    group_id: str
    row_ids: frozenset[str]  # representative ids shown in the prompt
    guidance_ids: frozenset[str]  # notes retrieved for this group
    event_ids: frozenset[int]  # every event id in the group
    techniques: frozenset[str]  # group technique tags plus the retrieved notes' techniques
    ipv4: frozenset[str]  # every IPv4 address in the group's field values


def build_context(group: Group, packed: PackResult, retrieved: list[RetrievedNote]) -> ValidationContext:
    techniques = {tag for event in group.events for tag in event.mitre_tags if TECHNIQUE_ID.match(tag)}
    for item in retrieved:
        techniques.update(item.note.applies_to.techniques)

    addresses: set[str] = set()
    for event in group.events:
        for value in event.fields.values():
            for text in value if isinstance(value, list) else [value]:
                addresses.update(IPV4.findall(text))

    return ValidationContext(
        group_id=group.group_id,
        row_ids=frozenset(packed.cited_row_ids),
        guidance_ids=frozenset(item.note.id for item in retrieved),
        event_ids=frozenset(event.event_id for event in group.events),
        techniques=frozenset(techniques),
        ipv4=frozenset(addresses),
    )


def context_from_report(group: dict[str, Any], note_techniques: dict[str, list[str]]) -> ValidationContext:
    """The same context, rebuilt from a group in report.json (`deterministic.groups[]`).

    Lets a stored model answer be re-validated, or mutated and re-validated
    (eval/validator_injection.py), exactly against what its prompt showed.
    `note_techniques` maps guidance note ids to their `applies_to.techniques`.
    A unit test keeps this in step with build_context.
    """
    events = group["events"]
    techniques = {
        tag for event in events for tag in event.get("mitre_tags", []) if TECHNIQUE_ID.match(str(tag))
    }
    guidance = [item["id"] for item in group.get("guidance") or []]
    for note_id in guidance:
        techniques.update(note_techniques.get(note_id, []))

    addresses: set[str] = set()
    for event in events:
        for value in event["fields"].values():
            for text in value if isinstance(value, list) else [value]:
                addresses.update(IPV4.findall(str(text)))

    return ValidationContext(
        group_id=group["group_id"],
        row_ids=frozenset((group.get("evidence") or {}).get("cited_row_ids", [])),
        guidance_ids=frozenset(guidance),
        event_ids=frozenset(int(event["event_id"]) for event in events),
        techniques=frozenset(techniques),
        ipv4=frozenset(addresses),
    )


def extract_json(text: str) -> str:
    """Strip reasoning blocks and code fences, then isolate the JSON object."""
    cleaned = THINK_BLOCK.sub("", text).strip()
    fenced = FENCED_JSON.search(cleaned)
    if fenced:
        cleaned = fenced.group(1).strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end < start:
        return cleaned
    return cleaned[start : end + 1]


def _technique_allowed(mentioned: str, allowed: frozenset[str]) -> bool:
    """A parent id is fine when a sub-technique of it is present; a sub-technique of a parent is not."""
    return mentioned in allowed or any(item.startswith(mentioned + ".") for item in allowed)


def _content_errors(location: str, text: str, context: ValidationContext) -> list[str]:
    errors: list[str] = []
    for match in EID_MENTION.finditer(text):
        event_id = int(match.group(1))
        if event_id not in context.event_ids:
            errors.append(f"{location} mentions EID {event_id}, which is not an event in this group")
    for mentioned in sorted(set(TECHNIQUE_MENTION.findall(text))):
        if not _technique_allowed(mentioned, context.techniques):
            errors.append(
                f"{location} mentions {mentioned}, which is neither tagged on this group nor in its guidance"
            )
    for address in sorted(set(IPV4.findall(text))):
        if address not in context.ipv4:
            errors.append(f"{location} mentions IP {address}, which does not appear in this group's evidence")
    return errors


def validate_interpretation(
    raw_text: str, context: ValidationContext
) -> tuple[GroupInterpretation | None, list[str]]:
    """Return the accepted interpretation, or None plus every reason it was rejected."""
    payload = extract_json(raw_text)

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        return None, [f"output is not valid JSON: {exc}"]

    try:
        interpretation = GroupInterpretation(**parsed)
    except (ValidationError, TypeError) as exc:
        return None, [f"output does not match the required schema: {_short(exc)}"]

    errors: list[str] = []

    if interpretation.group_id != context.group_id:
        errors.append(f"group_id is {interpretation.group_id!r}, expected {context.group_id!r}")

    for position, claim in enumerate(interpretation.what_happened, start=1):
        location = f"what_happened[{position}]"
        for row_id in claim.evidence:
            if row_id not in context.row_ids:
                errors.append(f"{location} cites {row_id}, which was not shown for this group")
        errors.extend(_content_errors(location, claim.text, context))

    for position, step in enumerate(interpretation.next_steps, start=1):
        location = f"next_steps[{position}]"
        for row_id in step.evidence:
            if row_id not in context.row_ids:
                errors.append(f"{location} cites {row_id}, which was not shown for this group")
        for note_id in step.guidance:
            if note_id not in context.guidance_ids:
                errors.append(f"{location} cites guidance {note_id}, which was not retrieved for this group")
        errors.extend(_content_errors(location, step.text, context))

    if errors:
        return None, errors
    return interpretation, []


def assessment_warnings(
    outcome: InterpretationOutcome,
    group: Group,
    *,
    min_level: Level,
    assessments: list[Assessment],
    neutralized_control_tokens: int,
) -> list[str]:
    """Warnings for an accepted answer that the rules above cannot reject.

    Measured (ADR-0001 section 9c.3): one sentence in a log value turned the model's
    assessment of an LSASS dump from likely_malicious to likely_benign, and the answer
    passed every rule, because the assessment is a free class no rule ties to evidence.
    A benign verdict on a group with high-severity detections is therefore flagged.
    """
    interpretation = outcome.interpretation
    if outcome.status != "accepted" or interpretation is None:
        return []
    warnings: list[str] = []
    if interpretation.assessment in assessments and LEVEL_RANK[group.max_level] >= LEVEL_RANK[min_level]:
        warnings.append(
            f"assessment {interpretation.assessment.value} conflicts with the detections: this group reaches "
            f"level {group.max_level.value}. Text inside log data can steer the model; read the evidence."
        )
    if neutralized_control_tokens:
        warnings.append(
            f"the log data of this group contained {neutralized_control_tokens} chat control token(s), "
            "defused before the prompt: someone may have tried to steer the model"
        )
    return warnings


def _short(exc: Exception) -> str:
    text = str(exc).replace("\n", "; ")
    return text[:400]
