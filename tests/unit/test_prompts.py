"""Released prompts are immutable: editing one must fail, adding a version must be explicit."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from evtx_triage.config import Config
from evtx_triage.llm import interpret
from evtx_triage.llm.interpret import PromptError, load_prompt


def test_every_prompt_file_is_registered_with_its_hash() -> None:
    released = json.loads(interpret.VERSIONS_FILE.read_text(encoding="utf-8"))
    files = {path.stem: path for path in interpret.PROMPTS_DIR.glob("triage_v*.md")}
    assert set(files) == set(released), "every prompt file needs an entry in versions.json and vice versa"
    for version, path in files.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == released[version], (
            f"{version} was edited after release; add a new version instead"
        )


def test_configured_prompt_loads(config: Config) -> None:
    prompt = load_prompt(config.llm.prompt_version)
    assert prompt.version == config.llm.prompt_version
    assert "untrusted" in prompt.text.lower()


def test_edited_prompt_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "triage_v9.md").write_text("original", encoding="utf-8")
    (tmp_path / "versions.json").write_text(
        json.dumps({"triage_v9": hashlib.sha256(b"original").hexdigest()}), encoding="utf-8"
    )
    monkeypatch.setattr(interpret, "PROMPTS_DIR", tmp_path)
    monkeypatch.setattr(interpret, "VERSIONS_FILE", tmp_path / "versions.json")

    assert load_prompt("triage_v9").text == "original"
    (tmp_path / "triage_v9.md").write_text("edited in place", encoding="utf-8")
    with pytest.raises(PromptError, match="changed after release"):
        load_prompt("triage_v9")


def test_unknown_or_unregistered_prompt_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "triage_v8.md").write_text("draft", encoding="utf-8")
    (tmp_path / "versions.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(interpret, "PROMPTS_DIR", tmp_path)
    monkeypatch.setattr(interpret, "VERSIONS_FILE", tmp_path / "versions.json")
    with pytest.raises(PromptError, match="not registered"):
        load_prompt("triage_v8")
    with pytest.raises(PromptError, match="not found"):
        load_prompt("triage_v7")


def test_trailer_is_split_from_the_system_message_and_repeated_after_the_evidence(
    config: Config, mini_csv: Path
) -> None:
    from evtx_triage.pipeline import run_deterministic

    v3 = load_prompt("triage_v3")
    assert interpret.TRAILER_MARKER not in v3.text
    assert v3.trailer.startswith("Reminder:")
    assert "untrusted" in v3.text.lower()

    configured = config.model_copy(
        update={"llm": config.llm.model_copy(update={"prompt_version": "triage_v3"})}
    )
    result = run_deterministic(configured, mini_csv)
    user = result.user_prompt_by_group[result.selected[0].group_id].text
    assert user.index("END EVIDENCE>>>") < user.index(v3.trailer) < user.index("Answer with the JSON object")


def test_prompts_without_a_trailer_are_unchanged() -> None:
    for version in ("triage_v1", "triage_v2"):
        prompt = load_prompt(version)
        assert prompt.trailer == ""
        assert prompt.text == (interpret.PROMPTS_DIR / f"{version}.md").read_text(encoding="utf-8")
