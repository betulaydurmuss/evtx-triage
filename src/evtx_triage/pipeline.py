"""The deterministic half of the tool: stages 1 to 7 of the data flow.

Everything here is a pure function of (CSV, knowledge base, config, guidance
index). The chat model is never called from this module. Retrieval embeds one
query per group, which is deterministic for a fixed embedding model; tests
inject a fake embedder or the null retriever.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .config import Config
from .enrich import enrich, unknown_pairs, unknown_tactics, unknown_techniques
from .grouping import build_groups
from .ingest.hayabusa_csv import IngestResult, read_events
from .knowledge.attack import AttackCatalog, load_attack
from .knowledge.dictionary import EventDictionary, load_dictionary
from .knowledge.guidance import NullRetriever, RetrievedNote, Retriever
from .models import Event, Group
from .pack import WIDEST_DROP_NOTE, PackResult, pack_group
from .select import Selection, select_groups
from .timeline import build_timeline
from .tokens import EstimateCounter, PromptBudget, TokenCounter, TokenizerCounter, load_tokenizer_counter
from .validate import ValidationContext, build_context

if TYPE_CHECKING:
    from .llm.interpret import Prompt, UserPrompt


@dataclass
class DeterministicResult:
    ingest: IngestResult
    events: list[Event]
    groups: list[Group]
    selected: list[Group]
    dictionary: EventDictionary
    attack: AttackCatalog
    retrieval_provenance: dict[str, object] = field(default_factory=dict)
    selection: Selection = field(default_factory=Selection)
    packed_by_group: dict[str, PackResult] = field(default_factory=dict)
    retrieved_by_group: dict[str, list[RetrievedNote]] = field(default_factory=dict)
    guidance_block_by_group: dict[str, str] = field(default_factory=dict)
    context_by_group: dict[str, ValidationContext] = field(default_factory=dict)
    user_prompt_by_group: dict[str, UserPrompt] = field(default_factory=dict)
    # system + user + chat template, as counted by the configured counter
    prompt_tokens_by_group: dict[str, int] = field(default_factory=dict)
    token_provenance: dict[str, object] = field(default_factory=dict)

    @property
    def selected_ids(self) -> set[str]:
        return {group.group_id for group in self.selected}

    @property
    def guidance_by_group(self) -> dict[str, list[str]]:
        """Note ids per group: the only guidance ids the model may cite."""
        return {
            group_id: [item.note.id for item in notes] for group_id, notes in self.retrieved_by_group.items()
        }

    @property
    def unknown_pairs(self) -> list[tuple[str, int]]:
        return unknown_pairs(self.events)

    @property
    def unknown_tactics(self) -> list[str]:
        return unknown_tactics(self.events, self.attack)

    @property
    def unknown_techniques(self) -> list[str]:
        return unknown_techniques(self.events, self.attack)

    @property
    def knowledge_hash(self) -> str:
        """One hash over every knowledge file that shaped this report."""
        corpus = str(self.retrieval_provenance.get("corpus_hash", ""))
        return hashlib.sha256(
            (self.dictionary.content_hash + self.attack.content_hash + corpus).encode("utf-8")
        ).hexdigest()


def guidance_block(notes: list[RetrievedNote], *, note_chars: int) -> str:
    """The GUIDANCE part of the prompt: id, title and the start of each note."""
    return "\n".join(
        f"[{item.note.id}] {item.note.title}: {item.note.prompt_text(note_chars)}" for item in notes
    )


def make_counter(config: Config) -> TokenCounter:
    if config.pack.token_counter == "tokenizer":
        return load_tokenizer_counter(str(config.resolve(config.llm.tokenizer_file)))
    return EstimateCounter(config.pack.chars_per_token)


def make_budget(config: Config, counter: TokenCounter | None = None) -> PromptBudget:
    """Raises tokens.TokenizerError when the configured tokenizer file is unusable."""
    return PromptBudget(
        counter=counter if counter is not None else make_counter(config),
        max_input_tokens=config.llm.max_input_tokens,
        template_overhead_tokens=config.llm.chat_template_overhead_tokens,
    )


def first_attempt_limit(config: Config) -> int:
    """The first request leaves room for the rejection reasons a retry appends."""
    reserve = config.llm.retry_feedback_tokens if config.llm.max_retries > 0 else 0
    return max(config.llm.max_input_tokens - reserve, 0)


def evidence_budget(group: Group, config: Config, block: str, *, budget: PromptBudget, prompt: Prompt) -> int:
    """Tokens left for evidence once the fixed parts of the prompt are counted."""
    from .llm.interpret import build_user_prompt

    # Reserve the drop note too: it is only added when rows are dropped, which is
    # exactly when the budget is tight.
    skeleton = build_user_prompt(
        group,
        PackResult(note=WIDEST_DROP_NOTE),
        block,
        added_tokens=budget.counter.added_tokens,
        trailer=prompt.trailer,
    )
    return max(first_attempt_limit(config) - budget.prompt_tokens(prompt.text, skeleton.text), 0)


def pack_to_budget(
    group: Group, config: Config, block: str, *, budget: PromptBudget, prompt: Prompt
) -> tuple[PackResult, UserPrompt, int]:
    """Pack the evidence, then count the assembled prompt and shrink until it fits.

    Per-line costs are an upper bound in practice but not by construction (tokens
    can merge across a line break), so the assembled prompt is what is checked.
    Each round lowers the evidence budget by the overshoot; at zero every row is
    dropped and the group is skipped rather than sent.
    """
    from .llm.interpret import build_user_prompt

    limit = first_attempt_limit(config)
    available = evidence_budget(group, config, block, budget=budget, prompt=prompt)
    while True:
        packed = pack_group(
            group,
            budget_tokens=available,
            counter=budget.counter,
            max_field_value_chars=config.pack.max_field_value_chars,
        )
        user = build_user_prompt(
            group, packed, block, added_tokens=budget.counter.added_tokens, trailer=prompt.trailer
        )
        tokens = budget.prompt_tokens(prompt.text, user.text)
        if tokens <= limit or not packed.entries:
            return packed, user, tokens
        available = max(available - (tokens - limit), 0)


def token_provenance(budget: PromptBudget) -> dict[str, object]:
    counter = budget.counter
    payload: dict[str, object] = {"counter": counter.name}
    if isinstance(counter, TokenizerCounter):
        payload["tokenizer_sha256"] = counter.sha256
    return payload


def run_deterministic(
    config: Config,
    csv_path: Path,
    *,
    retriever: Retriever | None = None,
    budget: PromptBudget | None = None,
) -> DeterministicResult:
    """Run ingest through packing and return everything the report needs."""
    from .llm.interpret import load_prompt

    budget = budget if budget is not None else make_budget(config)
    prompt = load_prompt(config.llm.prompt_version)
    dictionary = load_dictionary(config.resolve(config.knowledge.eventids_dir))
    attack = load_attack(config.resolve(config.knowledge.attack_dir))
    ingested = read_events(csv_path, assume_utc=config.ingest.assume_utc)

    events = enrich(build_timeline(ingested.events), dictionary, attack)
    groups = build_groups(
        events,
        gap_minutes=config.grouping.gap_minutes,
        max_span_minutes=config.grouping.max_span_minutes,
    )
    selection = select_groups(
        groups,
        model_min_level=config.selection.model_min_level,
        max_groups=config.selection.max_groups_to_model,
    )
    selected = selection.selected

    active = retriever if retriever is not None else NullRetriever()
    result = DeterministicResult(
        ingest=ingested,
        events=events,
        groups=groups,
        selected=selected,
        dictionary=dictionary,
        attack=attack,
        retrieval_provenance=active.provenance(),
        token_provenance=token_provenance(budget),
        selection=selection,
    )

    for group in selected:
        notes = active.retrieve(group, top_k=config.retrieval.top_k, min_score=config.retrieval.min_score)
        block = guidance_block(notes, note_chars=config.retrieval.prompt_note_chars)
        result.retrieved_by_group[group.group_id] = notes
        result.guidance_block_by_group[group.group_id] = block
        packed, user, tokens = pack_to_budget(group, config, block, budget=budget, prompt=prompt)
        result.packed_by_group[group.group_id] = packed
        result.user_prompt_by_group[group.group_id] = user
        result.prompt_tokens_by_group[group.group_id] = tokens
        result.context_by_group[group.group_id] = build_context(group, packed, notes)

    return result
