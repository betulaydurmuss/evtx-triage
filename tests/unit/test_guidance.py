"""Guidance notes: loading, validation, and the shipped corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

from evtx_triage.config import Config
from evtx_triage.knowledge.attack import load_attack
from evtx_triage.knowledge.dictionary import load_dictionary
from evtx_triage.knowledge.guidance import GuidanceError, check_guidance, load_guidance

VALID = """---
id: G-900
title: Test note
applies_to:
  events: ["Security:4624"]
  techniques: ["T1021"]
  tactics: ["Lateral Movement"]
sources: ["https://example.org/a"]
---

Body text.
"""


def _corpus(config: Config):
    return load_guidance(config.resolve(config.knowledge.guidance_dir))


def _write(directory: Path, name: str, text: str) -> None:
    (directory / name).write_text(text, encoding="utf-8")


def test_shipped_corpus_loads_and_passes_the_cross_check(config: Config) -> None:
    corpus = _corpus(config)
    assert len(corpus.notes) >= 30
    assert corpus.ids == sorted(corpus.ids)

    checked = check_guidance(
        corpus,
        load_attack(config.resolve(config.knowledge.attack_dir)),
        load_dictionary(config.resolve(config.knowledge.eventids_dir)),
    )
    assert checked.errors == []


def test_every_shipped_note_cites_https_sources_and_applies_to_something(config: Config) -> None:
    for note in _corpus(config).notes:
        assert note.sources and all(url.startswith("https://") for url in note.sources)
        assert note.applies_to.events or note.applies_to.techniques or note.applies_to.tactics
        assert note.body.strip()


def test_log_clearing_note_matches_both_current_and_legacy_ids(config: Config) -> None:
    # Sigma rules emit T1070.001 even though ATT&CK 19.2 moved it to T1685.005.
    note = _corpus(config).by_id("G-024")
    assert note is not None
    assert {"T1685.005", "T1070.001"} <= set(note.applies_to.techniques)


def test_valid_note_loads(tmp_path: Path) -> None:
    _write(tmp_path, "G-900-test.md", VALID)
    corpus = load_guidance(tmp_path)
    note = corpus.notes[0]
    assert note.id == "G-900"
    assert note.applies_to.event_pairs() == {("Security", 4624)}
    assert note.body.strip() == "Body text."


def test_corpus_hash_follows_content(tmp_path: Path) -> None:
    _write(tmp_path, "G-900-test.md", VALID)
    first = load_guidance(tmp_path).content_hash
    _write(tmp_path, "G-900-test.md", VALID.replace("Body text.", "Changed."))
    assert load_guidance(tmp_path).content_hash != first


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        (("id: G-900", "id: X-1"), "G-001"),
        (('events: ["Security:4624"]', 'events: ["Security 4624"]'), "Channel:EventID"),
        (('techniques: ["T1021"]', 'techniques: ["1021"]'), "T1234"),
        (('sources: ["https://example.org/a"]', 'sources: ["http://example.org/a"]'), "https"),
        (('sources: ["https://example.org/a"]', "sources: []"), "sources"),
    ],
)
def test_schema_violations_are_rejected(tmp_path: Path, replacement: tuple[str, str], message: str) -> None:
    _write(tmp_path, "G-900-test.md", VALID.replace(*replacement))
    with pytest.raises(GuidanceError, match=message):
        load_guidance(tmp_path)


def test_missing_front_matter_is_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "G-900-test.md", "just text\n")
    with pytest.raises(GuidanceError, match="front matter"):
        load_guidance(tmp_path)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "G-900-a.md", VALID)
    _write(tmp_path, "G-900-b.md", VALID)
    with pytest.raises(GuidanceError, match="duplicate"):
        load_guidance(tmp_path)


def test_file_name_must_match_id(tmp_path: Path) -> None:
    _write(tmp_path, "G-901-wrong.md", VALID)
    with pytest.raises(GuidanceError, match="file name"):
        load_guidance(tmp_path)


def test_cross_check_flags_unknown_technique_and_tactic(config: Config, tmp_path: Path) -> None:
    text = VALID.replace('techniques: ["T1021"]', 'techniques: ["T9999"]').replace(
        'tactics: ["Lateral Movement"]', 'tactics: ["Teleportation"]'
    )
    _write(tmp_path, "G-900-test.md", text)
    checked = check_guidance(
        load_guidance(tmp_path),
        load_attack(config.resolve(config.knowledge.attack_dir)),
        load_dictionary(config.resolve(config.knowledge.eventids_dir)),
    )
    assert any("T9999" in line for line in checked.errors)
    assert any("Teleportation" in line for line in checked.errors)


def test_prompt_text_is_cut_on_a_word_boundary(tmp_path: Path) -> None:
    _write(tmp_path, "G-900-test.md", VALID.replace("Body text.", "alpha beta gamma delta epsilon " * 20))
    text = load_guidance(tmp_path).notes[0].prompt_text(50)
    assert len(text) <= 54
    assert text.endswith(" ...")
    assert not text[:-4].endswith(" ")


def test_golden_queries_reference_existing_notes(config: Config) -> None:
    """The retrieval golden set must not point at notes that do not exist."""
    import yaml

    path = Path(__file__).resolve().parents[2] / "eval" / "golden_queries.yaml"
    queries = yaml.safe_load(path.read_text(encoding="utf-8"))["queries"]
    ids = [item["id"] for item in queries]
    assert len(ids) == len(set(ids))

    known = set(_corpus(config).ids)
    for item in queries:
        assert item["expected"], f"{item['id']} has no expected notes"
        assert set(item["expected"]) <= known, f"{item['id']} expects unknown notes"
        assert {"csv", "group", "host", "rule_hint"} <= set(item)
