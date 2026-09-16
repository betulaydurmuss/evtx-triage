"""Attach dictionary and ATT&CK knowledge to events. No guessing: unknown stays unknown."""

from __future__ import annotations

from .ingest.normalize import normalize_user
from .knowledge.attack import AttackCatalog
from .knowledge.dictionary import EventDictionary
from .models import Event

# Used only when the dictionary entry does not name a principal user field.
GENERIC_USER_FIELDS = ("TargetUserName", "SubjectUserName", "User", "AccountName")
GENERIC_DOMAIN_FIELDS = {
    "TargetUserName": "TargetDomainName",
    "SubjectUserName": "SubjectDomainName",
}


def _principal_user(event: Event) -> str | None:
    description = event.description
    if description is not None and description.principal_user is not None:
        spec = description.principal_user
        raw = event.field_text(spec.user_field)
        if raw:
            domain = event.field_text(spec.domain_field) if spec.domain_field else None
            return normalize_user(raw, domain)
        return None

    for name in GENERIC_USER_FIELDS:
        raw = event.field_text(name)
        if raw:
            domain_field = GENERIC_DOMAIN_FIELDS.get(name)
            domain = event.field_text(domain_field) if domain_field else None
            return normalize_user(raw, domain)
    return None


def enrich(
    events: list[Event],
    dictionary: EventDictionary,
    attack: AttackCatalog | None = None,
) -> list[Event]:
    """Fill in description, principal user and ATT&CK names in place."""
    for event in events:
        event.description = dictionary.lookup(event.channel, event.event_id)
        event.principal_user = _principal_user(event)

        if attack is None:
            continue
        event.tactics_resolved = [
            tactic.name
            for tactic in (attack.tactic(abbrev) for abbrev in event.mitre_tactics)
            if tactic is not None
        ]
        event.techniques_resolved = [
            technique.name
            for technique in (attack.technique(tag) for tag in event.mitre_tags)
            if technique is not None
        ]
    return events


def unknown_pairs(events: list[Event]) -> list[tuple[str, int]]:
    """(channel, event_id) pairs that the dictionary does not cover."""
    return sorted({(e.channel, e.event_id) for e in events if e.description is None})


def unknown_tactics(events: list[Event], attack: AttackCatalog | None) -> list[str]:
    """Tactic abbreviations the ATT&CK table does not cover."""
    if attack is None:
        return []
    return sorted(
        {abbrev for event in events for abbrev in event.mitre_tactics if attack.tactic(abbrev) is None}
    )


def unknown_techniques(events: list[Event], attack: AttackCatalog | None) -> list[str]:
    """Technique ids from MitreTags that the technique list does not cover."""
    if attack is None:
        return []
    return sorted({tag for event in events for tag in event.mitre_tags if attack.technique(tag) is None})
