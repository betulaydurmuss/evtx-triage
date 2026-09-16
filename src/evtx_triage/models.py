"""Core data structures shared by every stage of the pipeline."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1"


class Level(StrEnum):
    """Hayabusa detection levels, non-abbreviated spelling (ADR-0002 section 5)."""

    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    emergency = "emergency"


LEVEL_RANK: dict[Level, int] = {
    Level.informational: 0,
    Level.low: 1,
    Level.medium: 2,
    Level.high: 3,
    Level.critical: 4,
    Level.emergency: 5,
}

# Abbreviated spellings that only appear when -b was omitted. Seeing one of
# these is proof the CSV was produced with the wrong Hayabusa command.
ABBREVIATED_LEVELS = {"info", "med", "crit", "emer"}
ABBREVIATED_CHANNELS = {"Sec", "Sysmon", "App", "Sys", "PwSh", "BitsCli", "Defender", "RDS-RCM"}


class PrincipalUserSpec(BaseModel):
    """Which AllFieldInfo keys name the account an event is about."""

    model_config = ConfigDict(extra="forbid")

    user_field: str
    domain_field: str | None = None


class EventDescription(BaseModel):
    """One dictionary entry: what a (channel, event_id) pair means."""

    model_config = ConfigDict(extra="forbid")

    channel: str
    event_id: int
    title: str
    summary: str
    key_fields: list[str]
    sources: list[str]
    principal_user: PrincipalUserSpec | None = None


class Event(BaseModel):
    """One Hayabusa detection row, after parsing and enrichment."""

    model_config = ConfigDict(extra="forbid")

    row_id: str
    timestamp: datetime
    rule_title: str
    level: Level
    computer: str
    host_norm: str
    channel: str
    event_id: int
    mitre_tactics: list[str]
    mitre_tags: list[str]
    other_tags: list[str]
    record_id: int | None
    fields: dict[str, str | list[str]]
    rule_file: str
    rule_id: str
    evtx_file: str
    # Filled in by enrich; None means the pair is not in the dictionary.
    description: EventDescription | None = None
    principal_user: str | None = None
    # Canonical ATT&CK names for the abbreviations Hayabusa emits. Abbreviations
    # or technique ids we do not carry are left out rather than guessed.
    tactics_resolved: list[str] = Field(default_factory=list)
    techniques_resolved: list[str] = Field(default_factory=list)

    def field_text(self, key: str) -> str:
        """Return a field value as a single string, joining repeated keys."""
        value = self.fields.get(key)
        if value is None:
            return ""
        if isinstance(value, list):
            return " | ".join(value)
        return value


class IngestError(BaseModel):
    """A row, or part of a row, that could not be parsed. Never silently dropped."""

    model_config = ConfigDict(extra="forbid")

    row_id: str
    line_number: int
    reason: str
    detail: str


class Group(BaseModel):
    """Events from one host that belong to the same activity window."""

    model_config = ConfigDict(extra="forbid")

    group_id: str
    host: str
    start: datetime
    end: datetime
    max_level: Level
    events: list[Event]
    # The human account the group is about, "system" for service and machine
    # activity, None when the cluster carried no usable account at all.
    principal_user: str | None = None

    @property
    def row_ids(self) -> list[str]:
        return [event.row_id for event in self.events]

    @property
    def event_ids(self) -> set[int]:
        return {event.event_id for event in self.events}


class Claim(BaseModel):
    """A model statement about what happened, tied to evidence rows."""

    model_config = ConfigDict(extra="forbid")

    text: str
    evidence: list[str] = Field(min_length=1)


class NextStep(BaseModel):
    """A model suggestion for the analyst, tied to evidence and guidance notes."""

    model_config = ConfigDict(extra="forbid")

    text: str
    evidence: list[str] = Field(min_length=1)
    guidance: list[str] = Field(default_factory=list)


class Assessment(StrEnum):
    likely_malicious = "likely_malicious"
    suspicious = "suspicious"
    likely_benign = "likely_benign"
    insufficient_evidence = "insufficient_evidence"


class GroupInterpretation(BaseModel):
    """The model's output for one group, before validation."""

    model_config = ConfigDict(extra="forbid")

    group_id: str
    assessment: Assessment
    what_happened: list[Claim]
    next_steps: list[NextStep]


class InterpretationOutcome(BaseModel):
    """What happened when we asked the model about one group."""

    model_config = ConfigDict(extra="forbid")

    group_id: str
    status: str  # accepted | rejected | skipped | not_selected
    interpretation: GroupInterpretation | None = None
    reasons: list[str] = Field(default_factory=list)
    attempts: int = 0
    # Deterministic warnings about an accepted answer (validate.assessment_warnings); never a rejection.
    warnings: list[str] = Field(default_factory=list)
    # Wall clock for all attempts together; model section only, never deterministic.
    duration_seconds: float = 0.0
