"""The event dictionary: what a (channel, event_id) pair means.

Exact match only. A pair that is not in the dictionary stays UNKNOWN; no layer
is allowed to guess (rule: unknown stays unknown).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..models import EventDescription


class DictionaryError(Exception):
    """A dictionary file is missing or does not match the schema."""


class EventDictionary:
    def __init__(self, entries: dict[tuple[str, int], EventDescription], content_hash: str) -> None:
        self._entries = entries
        self.content_hash = content_hash

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, channel: str, event_id: int) -> EventDescription | None:
        return self._entries.get((channel, event_id))

    @property
    def keys(self) -> list[tuple[str, int]]:
        return sorted(self._entries)


def load_dictionary(directory: Path) -> EventDictionary:
    """Load every YAML file in `directory` into an exact-match dictionary."""
    if not directory.is_dir():
        raise DictionaryError(f"dictionary directory not found: {directory}")

    entries: dict[tuple[str, int], EventDescription] = {}
    digest = hashlib.sha256()

    for path in sorted(directory.glob("*.yaml")):
        raw_text = path.read_text(encoding="utf-8")
        digest.update(path.name.encode("utf-8"))
        digest.update(raw_text.encode("utf-8"))

        documents = yaml.safe_load(raw_text)
        if documents is None:
            continue
        if not isinstance(documents, list):
            raise DictionaryError(f"{path}: expected a list of entries, found {type(documents).__name__}")

        for position, item in enumerate(documents, start=1):
            try:
                description = EventDescription(**item)
            except (ValidationError, TypeError) as exc:
                raise DictionaryError(f"{path}: entry {position} does not match the schema:\n{exc}") from exc
            if not description.sources:
                raise DictionaryError(f"{path}: entry {position} has no sources; a source URL is mandatory")
            key = (description.channel, description.event_id)
            if key in entries:
                raise DictionaryError(f"{path}: duplicate entry for {key}")
            entries[key] = description

    return EventDictionary(entries, digest.hexdigest())
