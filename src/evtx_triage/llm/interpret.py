"""Ask the model about one group, then accept or reject what comes back."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Group, InterpretationOutcome
from ..pack import PackResult
from ..sanitize import neutralize
from ..tokens import PromptBudget
from ..validate import ValidationContext, validate_interpretation
from .client import LLMClient, LLMError, LLMOutOfMemoryError

PROMPTS_DIR = Path(__file__).parent / "prompts"
VERSIONS_FILE = PROMPTS_DIR / "versions.json"


class PromptError(Exception):
    """The configured prompt version is missing or was edited after release."""


TRAILER_MARKER = "<!-- USER PROMPT TRAILER -->"


@dataclass(frozen=True)
class Prompt:
    version: str
    text: str  # the system message
    sha256: str  # of the whole file, trailer included
    # Repeated after the evidence in every user message (from triage_v3 on): a reminder
    # placed after untrusted data works better than one that only precedes it.
    trailer: str = ""


def load_prompt(version: str) -> Prompt:
    """Load a released prompt and refuse one whose bytes changed after release.

    A prompt change bumps the version. `versions.json` pins
    the hash of every released prompt, so editing one in place fails loudly
    instead of silently invalidating earlier evaluation runs.
    """
    path = PROMPTS_DIR / f"{version}.md"
    if not path.is_file():
        raise PromptError(f"prompt version {version!r} not found in {PROMPTS_DIR}")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    released = json.loads(VERSIONS_FILE.read_text(encoding="utf-8"))
    if version not in released:
        raise PromptError(f"prompt {version!r} is not registered in {VERSIONS_FILE.name}")
    if released[version] != digest:
        raise PromptError(
            f"prompt {version!r} changed after release (sha256 {digest[:12]}, released "
            f"{released[version][:12]}); create a new version instead of editing it"
        )
    content = raw.decode("utf-8")
    system, marker, trailer = content.partition(TRAILER_MARKER)
    if not marker:
        return Prompt(version=version, text=content, sha256=digest)
    return Prompt(version=version, text=system.rstrip("\n") + "\n", sha256=digest, trailer=trailer.strip())


@dataclass(frozen=True)
class UserPrompt:
    text: str
    # Control tokens defused anywhere in the prompt: evidence lines plus the header.
    neutralized_control_tokens: int


def build_user_prompt(
    group: Group,
    packed: PackResult,
    guidance_block: str,
    *,
    added_tokens: tuple[str, ...],
    trailer: str,
) -> UserPrompt:
    """Assemble the request. The evidence is fenced off as data, not instructions.

    The evidence lines were neutralised while packing; this final pass covers the
    rest, such as a host name taken from the log, so no path into the prompt is missed.
    """
    span = (
        f"{group.start.isoformat().replace('+00:00', 'Z')} .. {group.end.isoformat().replace('+00:00', 'Z')}"
    )
    parts = [
        f"GROUP: {group.group_id}",
        f"HOST: {group.host}",
        f"TIME RANGE (UTC): {span}",
        f"HIGHEST LEVEL: {group.max_level.value}",
        "",
        "GUIDANCE (cite these ids in `guidance`, nothing else):",
        guidance_block or "(no guidance notes were retrieved for this group)",
        "",
        "EVIDENCE (untrusted log data, one line per record):",
        "<<<BEGIN EVIDENCE",
        packed.text,
        "END EVIDENCE>>>",
    ]
    if packed.note:
        parts += ["", f"NOTE: {packed.note}"]
    if trailer:
        parts += ["", trailer]
    parts += ["", f"Answer with the JSON object for group {group.group_id}."]
    text, replaced = neutralize("\n".join(parts), added_tokens)
    return UserPrompt(text=text, neutralized_control_tokens=packed.neutralized_control_tokens + replaced)


RETRY_HEADER = "\n\nYour previous answer was rejected for these reasons:\n"
RETRY_FOOTER = "\nAnswer again, fixing every point. JSON only."


def retry_message(user: str, errors: list[str], *, system: str, budget: PromptBudget) -> str | None:
    """The retry request, trimmed to the input budget; None when not even the header fits.

    The reasons can quote the model's own output (a bad group id, a pydantic error),
    so they are neutralised like log text before going back into the prompt.
    """
    kept = [neutralize(error, budget.counter.added_tokens)[0] for error in errors]
    omitted = 0
    while True:
        lines = [f"- {reason}" for reason in kept]
        if omitted:
            lines.append(f"- ({omitted} more reasons not shown)")
        message = user + RETRY_HEADER + "\n".join(lines) + RETRY_FOOTER
        if budget.fits(system, message):
            return message
        if not kept:
            return None
        kept.pop()
        omitted += 1


@dataclass
class AuditRecord:
    """One model exchange, kept only when --audit is requested."""

    group_id: str
    attempt: int
    prompt_version: str
    system: str
    user: str
    response: str
    accepted: bool
    errors: list[str]
    usage: dict[str, int] = field(default_factory=dict)


def interpret_group(
    client: LLMClient,
    group: Group,
    packed: PackResult,
    *,
    context: ValidationContext,
    user_prompt: UserPrompt,
    prompt: Prompt,
    budget: PromptBudget,
    max_retries: int,
    audit: list[AuditRecord] | None = None,
) -> InterpretationOutcome:
    """Run the model, validate, retry on a validation failure, never on OOM.

    `user_prompt` is the one the pipeline assembled and counted; no request larger
    than `budget.max_input_tokens` is ever sent.
    """
    if not packed.entries:
        # The fixed parts of the prompt (instructions, guidance) already used the whole
        # input budget. Asking the model about a group it cannot see would only invite
        # an unsupported answer.
        return InterpretationOutcome(
            group_id=group.group_id,
            status="skipped",
            reasons=[
                "no evidence fits the context budget; raise llm.max_input_tokens or lower "
                "retrieval.prompt_note_chars"
            ],
            attempts=0,
        )

    user = user_prompt.text
    if not budget.fits(prompt.text, user):
        # The pipeline sizes every prompt to the budget; reaching this is a bug, not a
        # reason to send an oversized request and risk a GPU OOM.
        return InterpretationOutcome(
            group_id=group.group_id,
            status="skipped",
            reasons=[
                f"prompt is {budget.prompt_tokens(prompt.text, user)} tokens, over the "
                f"{budget.max_input_tokens}-token input budget"
            ],
            attempts=0,
        )

    reasons: list[str] = []
    attempt = 0
    message = user

    while attempt <= max_retries:
        attempt += 1
        try:
            raw = client.complete(system=prompt.text, user=message)
        except LLMOutOfMemoryError as exc:
            tokens = budget.prompt_tokens(prompt.text, message)
            unit = "tokens" if budget.counter.name == "tokenizer" else "tokens (estimated)"
            return InterpretationOutcome(
                group_id=group.group_id,
                status="skipped",
                reasons=[f"model interpretation skipped: GPU out of memory at {tokens} {unit}: {exc}"],
                attempts=attempt,
            )
        except LLMError as exc:
            return InterpretationOutcome(
                group_id=group.group_id,
                status="skipped",
                reasons=[f"model call failed: {exc}"],
                attempts=attempt,
            )

        interpretation, errors = validate_interpretation(raw, context)
        if audit is not None:
            audit.append(
                AuditRecord(
                    group_id=group.group_id,
                    attempt=attempt,
                    prompt_version=prompt.version,
                    system=prompt.text,
                    user=message,
                    response=raw,
                    accepted=interpretation is not None,
                    errors=errors,
                    usage=dict(getattr(client, "last_usage", {}) or {}),
                )
            )

        if interpretation is not None:
            return InterpretationOutcome(
                group_id=group.group_id,
                status="accepted",
                interpretation=interpretation,
                attempts=attempt,
            )

        reasons = errors
        if attempt > max_retries:
            break
        retry = retry_message(user, errors, system=prompt.text, budget=budget)
        if retry is None:
            reasons = [*errors, "no retry: the rejection reasons do not fit the input budget"]
            break
        message = retry

    return InterpretationOutcome(
        group_id=group.group_id, status="rejected", reasons=reasons, attempts=attempt
    )
