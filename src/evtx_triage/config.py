"""Configuration loading.

The schema deliberately carries no defaults: every tunable value must be present
in the TOML file, so a run can never silently fall back to a hidden constant
(rule: no hidden defaults). Relative paths resolve against the config file's directory.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from .models import Assessment, Level

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class ConfigError(Exception):
    """Raised with an actionable message when the config file is unusable."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KnowledgeConfig(_Strict):
    eventids_dir: str
    guidance_dir: str
    attack_dir: str


class IngestConfig(_Strict):
    assume_utc: bool


class GroupingConfig(_Strict):
    gap_minutes: int
    max_span_minutes: int


class SelectionConfig(_Strict):
    model_min_level: Level
    max_groups_to_model: int


class PackConfig(_Strict):
    token_counter: Literal["tokenizer", "estimate"]
    chars_per_token: float
    max_field_value_chars: int


class LlmConfig(_Strict):
    endpoint: str
    model_id: str
    prompt_version: str
    tokenizer_file: str
    chat_template_overhead_tokens: int
    context_tokens: int
    max_input_tokens: int
    retry_feedback_tokens: int
    max_output_tokens: int
    temperature: float
    seed: int
    max_retries: int
    timeout_seconds: int

    @field_validator("endpoint")
    @classmethod
    def _loopback_only(cls, value: str) -> str:
        host = urlparse(value).hostname
        if host not in LOOPBACK_HOSTS:
            raise ValueError(
                f"llm.endpoint must stay on the loopback interface, got host {host!r}. "
                f"Allowed hosts: {sorted(LOOPBACK_HOSTS)}"
            )
        return value


class RetrievalConfig(_Strict):
    embedding_model_id: str
    embedding_dim: int
    normalized: bool
    embedding_batch_size: int
    index_path: str
    query_instruction: str
    top_k: int
    min_score: float
    prompt_note_chars: int


class RuntimeConfig(_Strict):
    auto_load_models: bool
    foundry_cli: str
    model_load_timeout_seconds: int
    max_gpu_used_before_chat_load_mib: int
    warm_up_at_full_budget: bool


class AssessmentCheckConfig(_Strict):
    min_level: Level
    assessments: list[Assessment]


class Config(_Strict):
    knowledge: KnowledgeConfig
    ingest: IngestConfig
    grouping: GroupingConfig
    selection: SelectionConfig
    pack: PackConfig
    llm: LlmConfig
    retrieval: RetrievalConfig
    runtime: RuntimeConfig
    assessment_check: AssessmentCheckConfig

    # Not part of the file: where it was loaded from, used to resolve paths.
    source_dir: Path

    def resolve(self, relative: str) -> Path:
        """Relative paths hang off the config directory; `~` means the user's home."""
        return (self.source_dir / Path(relative).expanduser()).resolve()

    def hash(self) -> str:
        """Stable hash of the effective values, written into the report."""
        payload = self.model_dump(mode="json", exclude={"source_dir"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def effective_values(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"source_dir"})


def load_config(path: Path) -> Config:
    """Read and validate a config file, raising ConfigError with a usable message."""
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"config file is not valid TOML: {path}\n  {exc}") from exc

    try:
        return Config(source_dir=path.parent.resolve(), **raw)
    except ValidationError as exc:
        lines = [f"invalid configuration in {path}:"]
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"])
            if error["type"] == "missing":
                lines.append(f"  missing required key: {location}")
            else:
                lines.append(f"  {location}: {error['msg']}")
        raise ConfigError("\n".join(lines)) from exc
