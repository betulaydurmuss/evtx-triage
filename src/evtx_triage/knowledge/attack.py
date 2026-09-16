"""MITRE ATT&CK lookups.

Faz 2 resolves the tactic abbreviations that Hayabusa always emits. Faz 3 adds
technique lookups from `techniques.json`. Both are exact-match: an identifier we
do not carry stays unknown rather than being guessed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError


class AttackError(Exception):
    """An ATT&CK knowledge file is missing or malformed."""


class Tactic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    abbreviation: str
    name: str
    attack_id: str
    note: str | None = None


class Technique(BaseModel):
    """A technique, group or software entry from ATT&CK.

    Hayabusa puts all three kinds into MitreTags, so the catalogue carries all
    three and `kind` says which one a tag resolved to.
    """

    model_config = ConfigDict(extra="forbid")

    attack_id: str
    name: str
    kind: str = "technique"
    retired: bool = False  # deprecated or revoked in the pinned ATT&CK version
    tactics: list[str] = []
    is_subtechnique: bool = False
    url: str | None = None


class AttackCatalog:
    def __init__(
        self,
        tactics: dict[str, Tactic],
        techniques: dict[str, Technique],
        version: str,
        content_hash: str,
    ) -> None:
        self._tactics = tactics
        self._techniques = techniques
        self.version = version
        self.content_hash = content_hash

    def tactic(self, abbreviation: str) -> Tactic | None:
        return self._tactics.get(abbreviation)

    def technique(self, attack_id: str) -> Technique | None:
        return self._techniques.get(attack_id.upper())

    @property
    def tactic_names(self) -> set[str]:
        return {tactic.name for tactic in self._tactics.values()}

    @property
    def tactic_count(self) -> int:
        return len(self._tactics)

    @property
    def technique_count(self) -> int:
        return len(self._techniques)


def load_attack(directory: Path) -> AttackCatalog:
    """Load the tactic abbreviation table and, when present, the technique list."""
    if not directory.is_dir():
        raise AttackError(f"attack directory not found: {directory}")

    digest = hashlib.sha256()
    tactics: dict[str, Tactic] = {}
    version = "unknown"

    tactics_path = directory / "tactics_abbrev.yaml"
    if not tactics_path.is_file():
        raise AttackError(f"tactic table not found: {tactics_path}")

    raw_text = tactics_path.read_text(encoding="utf-8")
    digest.update(raw_text.encode("utf-8"))
    document = yaml.safe_load(raw_text)
    if not isinstance(document, dict) or "tactics" not in document:
        raise AttackError(f"{tactics_path}: expected a mapping with a 'tactics' list")
    version = str(document.get("attack_version", "unknown"))

    for position, item in enumerate(document["tactics"], start=1):
        try:
            tactic = Tactic(**item)
        except (ValidationError, TypeError) as exc:
            raise AttackError(f"{tactics_path}: tactic {position} is invalid:\n{exc}") from exc
        if tactic.abbreviation in tactics:
            raise AttackError(f"{tactics_path}: duplicate abbreviation {tactic.abbreviation}")
        tactics[tactic.abbreviation] = tactic

    techniques: dict[str, Technique] = {}
    techniques_path = directory / "techniques.json"
    if techniques_path.is_file():
        raw_json = techniques_path.read_text(encoding="utf-8")
        digest.update(raw_json.encode("utf-8"))
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise AttackError(f"{techniques_path}: invalid JSON: {exc}") from exc
        entries = payload.get("techniques", payload) if isinstance(payload, dict) else payload
        for item in entries:
            try:
                technique = Technique(**item)
            except (ValidationError, TypeError) as exc:
                raise AttackError(f"{techniques_path}: invalid technique entry:\n{exc}") from exc
            techniques[technique.attack_id.upper()] = technique

    return AttackCatalog(tactics, techniques, version, digest.hexdigest())
