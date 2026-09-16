"""Vector store and retrieval, exercised with a deterministic fake embedder."""

from __future__ import annotations

import hashlib
import math
import re
import sqlite3
from pathlib import Path

import pytest

from evtx_triage.config import Config
from evtx_triage.knowledge.embedder import EmbeddingError
from evtx_triage.knowledge.guidance import GuidanceCorpus, RetrievalQuery, load_guidance, query_for_group
from evtx_triage.knowledge.retrieval import GuidanceRetriever, applies, prefilter
from evtx_triage.knowledge.vector_store import (
    GuidanceIndexError,
    StaleIndexError,
    build_index,
    open_fresh_index,
    read_index,
)
from evtx_triage.pipeline import run_deterministic

DIM = 64
TOKEN = re.compile(r"[a-z0-9]+")


class FakeEmbedder:
    """Hashed bag of words: deterministic, network free, and similar texts score higher."""

    def __init__(self, model_id: str = "fake-embedder-v1", *, normalise: bool = True) -> None:
        self._model_id = model_id
        self._normalise = normalise
        self.calls = 0

    @property
    def model_id(self) -> str:
        return self._model_id

    def embed(self, texts: list[str]) -> list[list[float]]:
        self.calls += 1
        vectors = []
        for text in texts:
            vector = [0.0] * DIM
            for token in TOKEN.findall(text.lower()):
                bucket = int.from_bytes(hashlib.sha256(token.encode()).digest()[:4], "big") % DIM
                vector[bucket] += 1.0
            norm = math.sqrt(sum(value * value for value in vector)) or 1.0
            vectors.append([value / norm for value in vector] if self._normalise else vector)
        return vectors


def _corpus(config: Config) -> GuidanceCorpus:
    return load_guidance(config.resolve(config.knowledge.guidance_dir))


def _retriever(config: Config, index_path: Path, *, use_prefilter: bool = True) -> GuidanceRetriever:
    corpus = _corpus(config)
    embedder = FakeEmbedder()
    build_index(index_path, corpus, embedder, dim=DIM, batch_size=8, expect_normalized=True)
    index = open_fresh_index(index_path, corpus=corpus, model_id=embedder.model_id, dim=DIM)
    return GuidanceRetriever(
        corpus=corpus,
        index=index,
        embedder=embedder,
        query_instruction="Query: ",
        use_prefilter=use_prefilter,
    )


def test_index_round_trip_keeps_ids_order_and_unit_vectors(config: Config, tmp_path: Path) -> None:
    corpus = _corpus(config)
    path = tmp_path / "index.sqlite"
    meta = build_index(path, corpus, FakeEmbedder(), dim=DIM, batch_size=5, expect_normalized=True)

    index = read_index(path)
    assert meta.note_count == len(corpus.notes)
    assert index.ids == corpus.ids
    assert index.matrix.shape == (len(corpus.notes), DIM)
    norms = (index.matrix**2).sum(axis=1)
    assert all(abs(value - 1.0) < 1e-5 for value in norms)


def test_rebuilding_gives_byte_identical_vectors(config: Config, tmp_path: Path) -> None:
    corpus = _corpus(config)
    first, second = tmp_path / "a.sqlite", tmp_path / "b.sqlite"
    build_index(first, corpus, FakeEmbedder(), dim=DIM, batch_size=8, expect_normalized=True)
    build_index(second, corpus, FakeEmbedder(), dim=DIM, batch_size=8, expect_normalized=True)
    assert read_index(first).matrix.tobytes() == read_index(second).matrix.tobytes()


@pytest.mark.parametrize(
    ("model_id", "dim", "reason"),
    [("another-model", DIM, "built with fake-embedder-v1"), ("fake-embedder-v1", 128, "dimension")],
)
def test_model_or_dimension_change_makes_the_index_stale(
    config: Config, tmp_path: Path, model_id: str, dim: int, reason: str
) -> None:
    corpus = _corpus(config)
    path = tmp_path / "index.sqlite"
    build_index(path, corpus, FakeEmbedder(), dim=DIM, batch_size=8, expect_normalized=True)
    with pytest.raises(StaleIndexError, match=reason):
        open_fresh_index(path, corpus=corpus, model_id=model_id, dim=dim)


def test_corpus_change_makes_the_index_stale(config: Config, tmp_path: Path) -> None:
    corpus = _corpus(config)
    path = tmp_path / "index.sqlite"
    build_index(path, corpus, FakeEmbedder(), dim=DIM, batch_size=8, expect_normalized=True)
    changed = GuidanceCorpus(notes=corpus.notes, content_hash="0" * 64)
    with pytest.raises(StaleIndexError, match="notes changed"):
        open_fresh_index(path, corpus=changed, model_id="fake-embedder-v1", dim=DIM)


def test_missing_index_tells_how_to_build_it(config: Config, tmp_path: Path) -> None:
    with pytest.raises(GuidanceIndexError, match="kb build"):
        open_fresh_index(tmp_path / "nope.sqlite", corpus=_corpus(config), model_id="x", dim=DIM)


def test_failed_build_leaves_no_half_written_index(config: Config, tmp_path: Path) -> None:
    path = tmp_path / "index.sqlite"
    with pytest.raises(EmbeddingError, match="norms"):
        build_index(
            path,
            _corpus(config),
            FakeEmbedder(normalise=False),
            dim=DIM,
            batch_size=8,
            expect_normalized=True,
        )
    assert not path.exists()


def test_index_file_is_plain_sqlite(config: Config, tmp_path: Path) -> None:
    path = tmp_path / "index.sqlite"
    build_index(path, _corpus(config), FakeEmbedder(), dim=DIM, batch_size=8, expect_normalized=True)
    with sqlite3.connect(path) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    connection.close()
    assert tables == {"meta", "vectors"}


def _query(**overrides: object) -> RetrievalQuery:
    values: dict[str, object] = {
        "text": "t",
        "event_pairs": frozenset(),
        "techniques": frozenset(),
        "tactics": frozenset(),
    }
    values.update(overrides)
    return RetrievalQuery(**values)  # type: ignore[arg-type]


def test_prefilter_matches_event_pairs_exactly(config: Config) -> None:
    note = _corpus(config).by_id("G-001")  # Sysmon 10
    assert note is not None
    assert applies(note, _query(event_pairs=frozenset({("Microsoft-Windows-Sysmon/Operational", 10)})))
    assert not applies(note, _query(event_pairs=frozenset({("Security", 10)})))


def test_prefilter_matches_sub_techniques_to_parent_notes(config: Config) -> None:
    note = _corpus(config).by_id("G-003")  # lists T1558 and T1558.003
    assert note is not None
    assert applies(note, _query(techniques=frozenset({"T1558.003"})))
    parent_only = note.model_copy(
        update={"applies_to": note.applies_to.model_copy(update={"techniques": ["T1558"]})}
    )
    assert applies(parent_only, _query(techniques=frozenset({"T1558.004"})))
    assert not applies(parent_only, _query(techniques=frozenset({"T155"})))


def test_prefilter_falls_back_to_the_whole_corpus(config: Config) -> None:
    corpus = _corpus(config)
    candidates, matched = prefilter(corpus, _query(event_pairs=frozenset({("Nowhere", 1)})))
    assert matched is False
    assert [note.id for note in candidates] == corpus.ids


def test_retrieval_respects_top_k_min_score_and_prefilter(
    config: Config, mini_csv: Path, tmp_path: Path
) -> None:
    retriever = _retriever(config, tmp_path / "index.sqlite")
    result = run_deterministic(config, mini_csv, retriever=retriever)

    for group in result.selected:
        notes = result.retrieved_by_group[group.group_id]
        assert 0 < len(notes) <= config.retrieval.top_k
        query = query_for_group(group)
        if notes[0].matched_prefilter:
            assert all(applies(item.note, query) for item in notes)
        scores = [item.score for item in notes]
        assert scores == sorted(scores, reverse=True)

    group = result.selected[0]
    assert retriever.retrieve(group, top_k=3, min_score=2.0) == []


class ConstantEmbedder(FakeEmbedder):
    """Every text maps to the same unit vector, so every score ties exactly."""

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[1.0] + [0.0] * (DIM - 1) for _ in texts]


def test_ties_are_broken_by_note_id(config: Config, tmp_path: Path) -> None:
    corpus = _corpus(config)
    embedder = ConstantEmbedder()
    path = tmp_path / "index.sqlite"
    build_index(path, corpus, embedder, dim=DIM, batch_size=8, expect_normalized=True)
    retriever = GuidanceRetriever(
        corpus=corpus,
        index=open_fresh_index(path, corpus=corpus, model_id=embedder.model_id, dim=DIM),
        embedder=embedder,
        query_instruction="Query: ",
        use_prefilter=False,
    )
    ranked = retriever.rank(_query(text="anything"))
    assert {item.score for item in ranked} == {1.0}
    ids = [item.note.id for item in ranked]
    assert ids == sorted(ids)


def test_retrieval_is_deterministic_across_index_rebuilds(
    config: Config, mini_csv: Path, tmp_path: Path
) -> None:
    first = run_deterministic(config, mini_csv, retriever=_retriever(config, tmp_path / "a.sqlite"))
    second = run_deterministic(config, mini_csv, retriever=_retriever(config, tmp_path / "b.sqlite"))
    assert first.guidance_by_group == second.guidance_by_group
    assert first.guidance_block_by_group == second.guidance_block_by_group


def test_guidance_reaches_the_prompt_and_limits_what_may_be_cited(
    config: Config, mini_csv: Path, tmp_path: Path
) -> None:
    result = run_deterministic(config, mini_csv, retriever=_retriever(config, tmp_path / "index.sqlite"))
    group = result.selected[0]
    block = result.guidance_block_by_group[group.group_id]
    for note_id in result.guidance_by_group[group.group_id]:
        assert f"[{note_id}]" in block


def test_query_template_is_deterministic_and_sorted(config: Config, mini_csv: Path) -> None:
    result = run_deterministic(config, mini_csv)
    group = result.selected[0]
    first, second = query_for_group(group), query_for_group(group)
    assert first == second
    detections = first.text.splitlines()[0].removeprefix("Detections: ").split("; ")
    assert detections == sorted(detections)


@pytest.mark.parametrize("counter", ["estimate", "tiny-tokenizer"])
def test_prompt_never_exceeds_the_input_budget(config: Config, tmp_path: Path, counter: str) -> None:
    """With guidance in the prompt and rows being dropped, the counted prompt must stay within budget.

    Checked for both counters, and for the retry: the first request leaves
    retry_feedback_tokens free, and the retry message is trimmed to fit.
    """
    from evtx_triage.llm.interpret import build_user_prompt, load_prompt, retry_message
    from evtx_triage.pack import WIDEST_DROP_NOTE, PackResult
    from evtx_triage.pipeline import make_budget
    from evtx_triage.tokens import TokenizerCounter

    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
    tiny = fixtures.parent / "tokenizer" / "tiny_tokenizer.json"
    prompt = load_prompt(config.llm.prompt_version)
    system = prompt.text
    retriever = _retriever(config, tmp_path / "index.sqlite")

    def budget_for(cfg: Config):
        return make_budget(cfg, TokenizerCounter(tiny) if counter == "tiny-tokenizer" else None)

    base = budget_for(config)
    dropped_somewhere = False
    for csv_name in ("mini.csv", "multi_user.csv", "edge_cases.csv"):
        probe = run_deterministic(config, fixtures / csv_name, retriever=retriever, budget=base)
        for group in probe.selected:
            block = probe.guidance_block_by_group[group.group_id]
            skeleton = build_user_prompt(
                group,
                PackResult(note=WIDEST_DROP_NOTE),
                block,
                added_tokens=base.counter.added_tokens,
                trailer=prompt.trailer,
            )
            fixed = base.prompt_tokens(system, skeleton.text) + config.llm.retry_feedback_tokens
            # Budgets just above the fixed part force rows to be dropped.
            for slack in (40, 120, 400):
                limit = fixed + slack
                tight = config.model_copy(
                    update={"llm": config.llm.model_copy(update={"max_input_tokens": limit})}
                )
                budget = budget_for(tight)
                result = run_deterministic(tight, fixtures / csv_name, retriever=retriever, budget=budget)
                same = next(g for g in result.selected if g.group_id == group.group_id)
                packed = result.packed_by_group[same.group_id]
                user = result.user_prompt_by_group[same.group_id].text
                dropped_somewhere = dropped_somewhere or bool(packed.dropped_row_ids)

                counted = budget.prompt_tokens(system, user)
                assert counted == result.prompt_tokens_by_group[same.group_id]
                assert counted <= limit - tight.llm.retry_feedback_tokens, f"{csv_name} {same.group_id}"

                reasons = [f"what_happened[{n}] cites R{n:06d}, which was not shown" for n in range(1, 200)]
                retry = retry_message(user, reasons, system=system, budget=budget)
                assert retry is not None and budget.fits(system, retry)
    assert dropped_somewhere, "the budgets were not tight enough to exercise dropping"


def test_group_with_no_room_for_evidence_is_skipped_not_sent(config: Config, mini_csv: Path) -> None:
    from evtx_triage.llm.client import FakeLLM
    from evtx_triage.llm.interpret import interpret_group, load_prompt
    from evtx_triage.pipeline import make_budget

    tight = config.model_copy(update={"llm": config.llm.model_copy(update={"max_input_tokens": 50})})
    result = run_deterministic(tight, mini_csv)
    group = result.selected[0]
    client = FakeLLM([])
    outcome = interpret_group(
        client,
        group,
        result.packed_by_group[group.group_id],
        context=result.context_by_group[group.group_id],
        user_prompt=result.user_prompt_by_group[group.group_id],
        prompt=load_prompt(tight.llm.prompt_version),
        budget=make_budget(tight),
        max_retries=1,
    )
    assert outcome.status == "skipped"
    assert "context budget" in outcome.reasons[0]
    assert client.calls == []


def test_context_rebuilt_from_the_report_matches_the_pipeline(config: Config, tmp_path: Path) -> None:
    """validate.context_from_report must stay in step with build_context (validator injection eval)."""
    from evtx_triage.report.json_report import build_report
    from evtx_triage.validate import context_from_report

    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
    corpus = _corpus(config)
    note_techniques = {note.id: list(note.applies_to.techniques) for note in corpus.notes}
    retriever = _retriever(config, tmp_path / "index.sqlite")
    compared = 0
    for csv_name in ("mini.csv", "multi_user.csv", "edge_cases.csv"):
        result = run_deterministic(config, fixtures / csv_name, retriever=retriever)
        report = build_report(
            config=config,
            config_path=Path("config/default.toml"),
            input_path=fixtures / csv_name,
            ingest=result.ingest,
            groups=result.groups,
            selected_ids=result.selected_ids,
            packed_by_group=result.packed_by_group,
            outcomes=[],
            unknown_pairs=result.unknown_pairs,
            unknown_tactics=result.unknown_tactics,
            unknown_techniques=result.unknown_techniques,
            dictionary_entries=len(result.dictionary),
            knowledge_hash=result.knowledge_hash,
            attack_version=result.attack.version,
            llm_enabled=False,
            duration_seconds=0.0,
            retrieved_by_group=result.retrieved_by_group,
        )
        for group in report["deterministic"]["groups"]:
            if group["group_id"] in result.selected_ids:
                rebuilt = context_from_report(group, note_techniques)
                assert rebuilt == result.context_by_group[group["group_id"]]
                compared += 1
    assert compared >= 3
