"""Token counting for the prompt budget.

Two counters share one interface:

- `TokenizerCounter` reads the chat model's own `tokenizer.json` and runs its
  byte-level BPE in pure Python. Measured against the Foundry Local API on 12
  real prompts, content tokens plus a constant chat-template overhead matched
  `usage.prompt_tokens` exactly (ADR-0001 section 5).
- `EstimateCounter` divides characters by a ratio. It is a fallback: to stay an
  upper bound it has to over-count dense log text by roughly 45%, which wastes
  evidence budget.

Deliberately not the `tokenizers` package: it pulls in `huggingface-hub`, a
library with telemetry and network code, and the loopback-only rule keeps those out.
Only `regex` is needed, for the `\\p{L}` and `\\p{N}` classes the pre-tokenizer uses.
This module is pure and deterministic; it never touches the network.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

import regex


class TokenizerError(Exception):
    """The tokenizer file is missing or is not a byte-level BPE this module supports."""


class TokenCounter(Protocol):
    @property
    def name(self) -> str:
        """Which counter this is, for the report's provenance."""
        ...

    @property
    def added_tokens(self) -> tuple[str, ...]:
        """Strings the model tokenises as one unit wherever they appear, bypassing BPE.

        Control tokens such as `<|im_end|>` are among them; sanitize.neutralize
        defuses every one of these in untrusted text.
        """
        ...

    def count(self, text: str) -> int:
        """Number of tokens the model will see for this text."""
        ...


class EstimateCounter:
    name = "estimate"
    added_tokens: tuple[str, ...] = ()

    def __init__(self, chars_per_token: float) -> None:
        self.chars_per_token = chars_per_token

    def count(self, text: str) -> int:
        return math.ceil(len(text) / self.chars_per_token)


def _bytes_to_unicode() -> dict[int, str]:
    """The GPT-2 byte-to-printable-character table used by byte-level BPE."""
    printable = (
        list(range(ord("!"), ord("~") + 1))
        + list(range(ord("¡"), ord("¬") + 1))
        + list(range(ord("®"), ord("ÿ") + 1))
    )
    codes = printable[:]
    extra = 0
    for byte in range(256):
        if byte not in printable:
            printable.append(byte)
            codes.append(256 + extra)
            extra += 1
    return dict(zip(printable, (chr(code) for code in codes), strict=True))


BYTE_TO_UNICODE = _bytes_to_unicode()


class TokenizerCounter:
    """Exact token counts from a Hugging Face `tokenizer.json` (byte-level BPE)."""

    name = "tokenizer"

    def __init__(self, tokenizer_file: Path) -> None:
        if not tokenizer_file.is_file():
            raise TokenizerError(
                f"tokenizer file not found: {tokenizer_file}\n"
                "  it ships with the chat model in the Foundry Local cache; set llm.tokenizer_file,\n"
                '  or set pack.token_counter = "estimate"'
            )
        raw = tokenizer_file.read_bytes()
        self.path = tokenizer_file
        self.sha256 = hashlib.sha256(raw).hexdigest()
        try:
            spec = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TokenizerError(f"{tokenizer_file}: not a JSON tokenizer file ({exc})") from exc
        model = spec.get("model", {})
        if model.get("type") != "BPE" or model.get("byte_fallback") or model.get("ignore_merges"):
            raise TokenizerError(f"{tokenizer_file}: only plain byte-level BPE tokenizers are supported")

        normalizer = spec.get("normalizer") or {}
        self._nfc = normalizer.get("type") == "NFC"
        if normalizer and not self._nfc:
            raise TokenizerError(f"{tokenizer_file}: unsupported normalizer {normalizer.get('type')!r}")

        self._pattern = regex.compile(self._split_pattern(spec, tokenizer_file))
        self._ranks: dict[tuple[str, str], int] = {}
        for rank, merge in enumerate(model["merges"]):
            left, right = merge if isinstance(merge, list) else merge.split(" ", 1)
            self._ranks[(left, right)] = rank

        # Longest first, so a token that contains another one wins the match.
        added = sorted({item["content"] for item in spec.get("added_tokens", [])}, key=lambda t: (-len(t), t))
        self.added_tokens: tuple[str, ...] = tuple(added)
        self._special = regex.compile("|".join(regex.escape(token) for token in added)) if added else None
        self._bpe_len: Callable[[str], int] = lru_cache(maxsize=65536)(self._bpe_length)

    @staticmethod
    def _split_pattern(spec: dict[str, object], path: Path) -> str:
        pre = spec.get("pre_tokenizer")
        steps = pre.get("pretokenizers", [pre]) if isinstance(pre, dict) else []
        for step in steps:
            if isinstance(step, dict) and step.get("type") == "Split":
                pattern = step.get("pattern", {})
                if isinstance(pattern, dict) and "Regex" in pattern and step.get("behavior") == "Isolated":
                    return str(pattern["Regex"])
        raise TokenizerError(f"{path}: expected an isolated Split pre-tokenizer with a regex")

    def _bpe_length(self, piece: str) -> int:
        symbols = [BYTE_TO_UNICODE[byte] for byte in piece.encode("utf-8")]
        ranks = self._ranks
        while len(symbols) > 1:
            best_rank = None
            best_index = -1
            for index in range(len(symbols) - 1):
                rank = ranks.get((symbols[index], symbols[index + 1]))
                if rank is not None and (best_rank is None or rank < best_rank):
                    best_rank, best_index = rank, index
            if best_rank is None:
                break
            pair = (symbols[best_index], symbols[best_index + 1])
            merged: list[str] = []
            index = 0
            while index < len(symbols):
                if index < len(symbols) - 1 and (symbols[index], symbols[index + 1]) == pair:
                    merged.append(symbols[index] + symbols[index + 1])
                    index += 2
                else:
                    merged.append(symbols[index])
                    index += 1
            symbols = merged
        return len(symbols)

    def _count_plain(self, text: str) -> int:
        if not text:
            return 0
        if self._nfc:
            text = unicodedata.normalize("NFC", text)
        return sum(self._bpe_len(piece) for piece in self._pattern.findall(text))

    def count(self, text: str) -> int:
        if self._special is None:
            return self._count_plain(text)
        total = 0
        position = 0
        for match in self._special.finditer(text):
            total += self._count_plain(text[position : match.start()]) + 1
            position = match.end()
        return total + self._count_plain(text[position:])


@lru_cache(maxsize=4)
def load_tokenizer_counter(path: str) -> TokenizerCounter:
    """Parsing an 11 MB tokenizer file takes a moment; do it once per process."""
    return TokenizerCounter(Path(path))


@dataclass(frozen=True)
class PromptBudget:
    """How many tokens one request may carry, and how to count them.

    Foundry Local wraps the two messages in the chat template, which adds the same
    number of tokens to every request (measured: 13 for qwen2.5, ADR-0001 section 5).
    """

    counter: TokenCounter
    max_input_tokens: int
    template_overhead_tokens: int

    def prompt_tokens(self, system: str, user: str) -> int:
        return self.counter.count(system) + self.counter.count(user) + self.template_overhead_tokens

    def fits(self, system: str, user: str) -> bool:
        return self.prompt_tokens(system, user) <= self.max_input_tokens
