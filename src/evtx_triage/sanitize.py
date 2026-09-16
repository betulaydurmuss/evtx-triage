"""Neutralise chat-template control tokens inside untrusted text (log content is untrusted).

Measured on Foundry Local (qwen2.5-7b): the server tokenises `<|im_end|>` and
`<|im_start|>` inside message CONTENT as real control tokens. A log field such as
a command line containing `<|im_end|><|im_start|>system ...` therefore closes the
user turn and opens a new one; asked to repeat such a message verbatim, the model
repeated only the part before `<|im_end|>` (ADR-0001 section 9c).

Every string that reaches the prompt from a log record passes through here. The
replacement is visible and ASCII so an analyst reading the prompt or the audit
record can see that an injection attempt was defused. The raw value stays
untouched in the report's per-event fields.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Qwen, ChatML and most recent chat templates use `<|name|>`.
GENERIC_CONTROL_TOKEN = re.compile(r"<\|[^|<>\s]{1,64}\|>")


def _replacement(token: str) -> str:
    # The replacement must not contain the token again: `<tool_call>` becomes
    # `[control-token:tool_call]`, never `[control-token:<tool_call>]`.
    name = token.strip("<|>") or "?"
    return f"[control-token:{name.replace('<', '').replace('>', '').replace('|', '')}]"


def neutralize(text: str, extra_tokens: Iterable[str] = ()) -> tuple[str, int]:
    """Return the text with control tokens defused, and how many were replaced.

    `extra_tokens` are the tokenizer's added tokens (TokenCounter.added_tokens);
    the generic `<|name|>` pattern applies whether or not they are known.
    """
    tokens = sorted({token for token in extra_tokens if token}, key=lambda t: (-len(t), t))
    for token in tokens:
        if "<" not in token:
            # Not a log problem: the loop below only provably ends for `<`-delimited tokens.
            raise ValueError(f"cannot neutralise added token {token!r}: it has no '<' delimiter")

    total = 0
    # Repeat until nothing matches: defusing `<|im_<|im_end|>end|>` leaves a new
    # `<|...|>` shape around the replacement. Every replacement removes at least
    # one `<` and adds none, so the loop ends for any input. No pass limit: a
    # limit would let a deeply nested log value crash the run.
    while True:
        text, replaced = _one_pass(text, tokens)
        if replaced == 0:
            return text, total
        total += replaced


def _one_pass(text: str, tokens: list[str]) -> tuple[str, int]:
    count = 0
    for token in tokens:
        if token in text:
            count += text.count(token)
            text = text.replace(token, _replacement(token))

    def swap(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return _replacement(match.group(0))

    return GENERIC_CONTROL_TOKEN.sub(swap, text), count
