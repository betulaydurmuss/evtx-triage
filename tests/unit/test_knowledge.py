"""The knowledge base must load, cite its sources, and never guess."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from evtx_triage.config import Config
from evtx_triage.knowledge.attack import AttackError, load_attack
from evtx_triage.knowledge.dictionary import DictionaryError, load_dictionary


def _dictionary(config: Config):
    return load_dictionary(config.resolve(config.knowledge.eventids_dir))


def _attack(config: Config):
    return load_attack(config.resolve(config.knowledge.attack_dir))


def test_dictionary_loads_and_every_entry_cites_a_source(config: Config) -> None:
    dictionary = _dictionary(config)
    assert len(dictionary) >= 54

    directory = config.resolve(config.knowledge.eventids_dir)
    for path in sorted(directory.glob("*.yaml")):
        for entry in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            assert entry["sources"], f"{path.name}: {entry['event_id']} has no source"
            for url in entry["sources"]:
                assert url.startswith("https://"), f"{path.name}: {entry['event_id']} source is not a URL"


def test_dictionary_channels_are_never_abbreviated(config: Config) -> None:
    # An abbreviated channel in the dictionary would silently fail to match any
    # event, because the tool only accepts -b output (ADR-0002 section 5).
    for channel, _ in _dictionary(config).keys:
        assert "/" in channel or channel in {"Security", "System", "Application"}


def test_lookup_is_exact_match_only(config: Config) -> None:
    dictionary = _dictionary(config)
    assert dictionary.lookup("Microsoft-Windows-Sysmon/Operational", 1) is not None
    assert dictionary.lookup("Sysmon", 1) is None
    assert dictionary.lookup("Microsoft-Windows-Sysmon/Operational", 999999) is None


def test_duplicate_entries_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "dup.yaml").write_text(
        "- {channel: Security, event_id: 4624, title: a, summary: b, key_fields: [], sources: ['https://x']}\n"
        "- {channel: Security, event_id: 4624, title: c, summary: d, key_fields: [], sources: ['https://x']}\n",
        encoding="utf-8",
    )
    with pytest.raises(DictionaryError, match="duplicate"):
        load_dictionary(tmp_path)


def test_entry_without_sources_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "nosource.yaml").write_text(
        "- {channel: Security, event_id: 4624, title: a, summary: b, key_fields: [], sources: []}\n",
        encoding="utf-8",
    )
    with pytest.raises(DictionaryError, match="source"):
        load_dictionary(tmp_path)


def test_unknown_yaml_key_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "extra.yaml").write_text(
        "- {channel: Security, event_id: 4624, title: a, summary: b, key_fields: [], "
        "sources: ['https://x'], severity: high}\n",
        encoding="utf-8",
    )
    with pytest.raises(DictionaryError):
        load_dictionary(tmp_path)


def test_attack_catalog_is_pinned_and_complete(config: Config) -> None:
    attack = _attack(config)
    assert attack.version == "19.2"
    assert attack.tactic_count == 15
    assert attack.technique_count > 1500

    stealth = attack.tactic("Stealth")
    assert stealth is not None
    assert stealth.attack_id == "TA0005"
    impair = attack.tactic("DefImpair")
    assert impair is not None
    assert impair.attack_id == "TA0112"


def test_attack_catalog_carries_groups_and_software(config: Config) -> None:
    attack = _attack(config)
    mimikatz = attack.technique("S0002")
    assert mimikatz is not None and mimikatz.kind == "software"
    technique = attack.technique("T1003.001")
    assert technique is not None and technique.kind == "technique"


def test_retired_identifiers_resolve_and_are_flagged(config: Config) -> None:
    # Sigma rules still reference identifiers ATT&CK has retired; resolving them
    # with a flag beats reporting them as unknown.
    retired = _attack(config).technique("T1070.001")
    assert retired is not None
    assert retired.retired is True
    assert retired.name == "Clear Windows Event Logs"


def test_missing_tactic_table_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(AttackError, match="tactic table"):
        load_attack(tmp_path)


def test_knowledge_hash_changes_when_content_changes(config: Config, tmp_path: Path) -> None:
    first = _dictionary(config).content_hash
    (tmp_path / "one.yaml").write_text(
        "- {channel: Security, event_id: 4624, title: a, summary: b, key_fields: [], sources: ['https://x']}\n",
        encoding="utf-8",
    )
    assert load_dictionary(tmp_path).content_hash != first
