"""The config schema has no defaults and only accepts loopback endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest

from evtx_triage.config import ConfigError, load_config


def test_shipped_config_loads(config_path: Path) -> None:
    config = load_config(config_path)
    assert config.llm.max_input_tokens + config.llm.max_output_tokens <= config.llm.context_tokens
    # Measured ceiling in Faz 0 was 5505 prompt tokens (ADR-0001 section 5).
    assert config.llm.context_tokens <= 5505


def test_missing_key_is_a_hard_error(tmp_path: Path, config_path: Path) -> None:
    text = config_path.read_text(encoding="utf-8")
    broken = "\n".join(line for line in text.splitlines() if not line.startswith("gap_minutes"))
    target = tmp_path / "broken.toml"
    target.write_text(broken, encoding="utf-8")

    with pytest.raises(ConfigError) as caught:
        load_config(target)
    assert "grouping.gap_minutes" in str(caught.value)


def test_non_loopback_endpoint_is_rejected(tmp_path: Path, config_path: Path) -> None:
    text = config_path.read_text(encoding="utf-8").replace(
        'endpoint = "http://127.0.0.1:5273/v1"', 'endpoint = "http://10.0.0.5:5273/v1"'
    )
    target = tmp_path / "remote.toml"
    target.write_text(text, encoding="utf-8")

    with pytest.raises(ConfigError) as caught:
        load_config(target)
    assert "loopback" in str(caught.value)


def test_unknown_key_is_rejected(tmp_path: Path, config_path: Path) -> None:
    text = config_path.read_text(encoding="utf-8") + "\n[surprise]\nvalue = 1\n"
    target = tmp_path / "extra.toml"
    target.write_text(text, encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(target)


def test_config_hash_is_stable_and_sensitive(tmp_path: Path, config_path: Path) -> None:
    first = load_config(config_path)
    second = load_config(config_path)
    assert first.hash() == second.hash()

    text = config_path.read_text(encoding="utf-8").replace("gap_minutes = 10", "gap_minutes = 11")
    target = tmp_path / "changed.toml"
    target.write_text(text, encoding="utf-8")
    assert load_config(target).hash() != first.hash()
