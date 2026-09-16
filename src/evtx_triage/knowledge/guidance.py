"""Investigation guidance notes: the RAG corpus.

A note is a Markdown file with YAML front matter. The front matter says which
evidence the note applies to, and every note cites its sources. Loading and
validating notes is pure code; nothing here calls a model.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..models import Group
from .attack import AttackCatalog
from .dictionary import EventDictionary

NOTE_ID = re.compile(r"^G-\d{3}$")
EVENT_REFERENCE = re.compile(r"^(?P<channel>.+):(?P<event_id>\d+)$")
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class GuidanceError(Exception):
    """A guidance note is missing, malformed or inconsistent."""


class AppliesTo(BaseModel):
    """Which evidence a note is about.

    `events` entries are `channel:event_id` pairs rather than separate channel
    and event id lists: a note about Security 4624 must not match Sysmon event 1
    just because both lists happen to be non-empty.
    """

    model_config = ConfigDict(extra="forbid")

    events: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)

    @field_validator("events")
    @classmethod
    def _event_format(cls, values: list[str]) -> list[str]:
        for value in values:
            if not EVENT_REFERENCE.match(value):
                raise ValueError(f"event reference {value!r} must look like 'Channel:EventID'")
        return values

    @field_validator("techniques")
    @classmethod
    def _technique_format(cls, values: list[str]) -> list[str]:
        for value in values:
            if not TECHNIQUE_ID.match(value):
                raise ValueError(f"technique {value!r} must look like T1234 or T1234.001")
        return values

    def event_pairs(self) -> set[tuple[str, int]]:
        pairs: set[tuple[str, int]] = set()
        for value in self.events:
            match = EVENT_REFERENCE.match(value)
            assert match is not None  # guaranteed by the validator
            pairs.add((match.group("channel"), int(match.group("event_id"))))
        return pairs


class GuidanceNote(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    applies_to: AppliesTo
    sources: list[str] = Field(min_length=1)
    body: str
    file: str

    @field_validator("id")
    @classmethod
    def _id_format(cls, value: str) -> str:
        if not NOTE_ID.match(value):
            raise ValueError(f"note id {value!r} must look like G-001")
        return value

    @field_validator("sources")
    @classmethod
    def _https_sources(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value.startswith("https://"):
                raise ValueError(f"source {value!r} is not an https URL")
        return values

    def embedding_text(self) -> str:
        """What the index embeds for this note."""
        return f"{self.title}\n\n{self.body.strip()}"

    def prompt_text(self, limit: int) -> str:
        """What the prompt shows for this note, cut at a whole line where possible."""
        text = " ".join(self.body.split())
        if len(text) <= limit:
            return text
        cut = text[:limit]
        space = cut.rfind(" ")
        return (cut[:space] if space > limit // 2 else cut) + " ..."


@dataclass
class GuidanceCorpus:
    notes: list[GuidanceNote]
    content_hash: str

    def by_id(self, note_id: str) -> GuidanceNote | None:
        return next((note for note in self.notes if note.id == note_id), None)

    @property
    def ids(self) -> list[str]:
        return [note.id for note in self.notes]


def _split_front_matter(text: str, path: Path) -> tuple[dict[str, object], str]:
    normalised = text.replace("\r\n", "\n")
    if not normalised.startswith("---\n"):
        raise GuidanceError(f"{path}: a note must start with a '---' front matter block")
    end = normalised.find("\n---\n", 4)
    if end == -1:
        raise GuidanceError(f"{path}: front matter is not closed with '---'")
    header = yaml.safe_load(normalised[4:end])
    if not isinstance(header, dict):
        raise GuidanceError(f"{path}: front matter must be a mapping")
    return header, normalised[end + 5 :]


def load_guidance(directory: Path) -> GuidanceCorpus:
    """Load every `G-*.md` note, sorted by id, with a hash over their exact bytes."""
    if not directory.is_dir():
        raise GuidanceError(f"guidance directory not found: {directory}")

    notes: list[GuidanceNote] = []
    digest = hashlib.sha256()
    seen: dict[str, str] = {}

    for path in sorted(directory.glob("G-*.md")):
        raw = path.read_bytes()
        digest.update(path.name.encode("utf-8"))
        digest.update(raw)
        header, body = _split_front_matter(raw.decode("utf-8"), path)
        try:
            note = GuidanceNote.model_validate({**header, "body": body, "file": path.name})
        except (ValidationError, TypeError) as exc:
            raise GuidanceError(f"{path}: note does not match the schema:\n{exc}") from exc
        if note.id in seen:
            raise GuidanceError(f"{path}: duplicate note id {note.id} (also in {seen[note.id]})")
        if not path.name.startswith(note.id):
            raise GuidanceError(f"{path}: file name must start with the note id {note.id}")
        seen[note.id] = path.name
        notes.append(note)

    notes.sort(key=lambda note: note.id)
    return GuidanceCorpus(notes=notes, content_hash=digest.hexdigest())


@dataclass
class GuidanceCheck:
    errors: list[str]
    notes: list[str]


def check_guidance(
    corpus: GuidanceCorpus, attack: AttackCatalog, dictionary: EventDictionary
) -> GuidanceCheck:
    """Cross-check notes against the ATT&CK catalogue and the event dictionary.

    Unknown technique ids and tactic names are errors: the pre-filter would never
    match them. Retired technique ids are allowed (Sigma rules still emit them)
    and events missing from the dictionary are allowed (a note may cover an
    event we deliberately leave UNKNOWN); both are reported as notes.
    """
    errors: list[str] = []
    notes: list[str] = []
    tactic_names = attack.tactic_names
    for note in corpus.notes:
        for technique_id in note.applies_to.techniques:
            technique = attack.technique(technique_id)
            if technique is None:
                errors.append(f"{note.id}: technique {technique_id} is not in ATT&CK {attack.version}")
            elif technique.retired:
                notes.append(
                    f"{note.id}: {technique_id} is retired in ATT&CK {attack.version} (kept for matching)"
                )
        for tactic in note.applies_to.tactics:
            if tactic not in tactic_names:
                errors.append(f"{note.id}: tactic {tactic!r} is not an ATT&CK tactic name")
        for channel, event_id in sorted(note.applies_to.event_pairs()):
            if dictionary.lookup(channel, event_id) is None:
                notes.append(f"{note.id}: {channel} {event_id} has no dictionary entry")
        if not (note.applies_to.events or note.applies_to.techniques or note.applies_to.tactics):
            errors.append(f"{note.id}: applies_to is empty, the note could only ever be a fallback")
    return GuidanceCheck(errors=errors, notes=notes)


@dataclass(frozen=True)
class RetrievalQuery:
    """Everything retrieval needs to know about a group, and nothing else.

    Built deterministically from the group, so a golden query file can store it
    without depending on how groups are numbered.
    """

    text: str
    event_pairs: frozenset[tuple[str, int]]
    techniques: frozenset[str]
    tactics: frozenset[str]


def query_for_group(group: Group) -> RetrievalQuery:
    """The deterministic query template one group is turned into."""
    rules = sorted({event.rule_title for event in group.events})
    titles = sorted({event.description.title for event in group.events if event.description is not None})
    tactics = sorted({name for event in group.events for name in event.tactics_resolved})
    techniques = sorted(
        {tag for event in group.events for tag in event.mitre_tags if TECHNIQUE_ID.match(tag)}
    )

    lines = [f"Detections: {'; '.join(rules)}"]
    if titles:
        lines.append(f"Events: {'; '.join(titles)}")
    if tactics:
        lines.append(f"Tactics: {'; '.join(tactics)}")
    return RetrievalQuery(
        text="\n".join(lines),
        event_pairs=frozenset((event.channel, event.event_id) for event in group.events),
        techniques=frozenset(techniques),
        tactics=frozenset(tactics),
    )


@dataclass(frozen=True)
class RetrievedNote:
    note: GuidanceNote
    score: float
    matched_prefilter: bool


class Retriever(Protocol):
    def retrieve(self, group: Group, *, top_k: int, min_score: float) -> list[RetrievedNote]:
        """Return the notes that apply to this group, best match first."""
        ...

    def provenance(self) -> dict[str, object]:
        """What the report needs to reproduce this retrieval."""
        ...


class NullRetriever:
    """No corpus: no notes and no citations. Used by tests that pin the evidence block."""

    def retrieve(self, group: Group, *, top_k: int, min_score: float) -> list[RetrievedNote]:
        return []

    def provenance(self) -> dict[str, object]:
        return {"retriever": "none"}
