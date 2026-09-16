"""Guidance retrieval: metadata pre-filter, then exact cosine ranking.

Given the same index, the same corpus and the same query vector, the ranking is
fully determined: ties are broken by note id, never by insertion order.
"""

from __future__ import annotations

import numpy as np

from ..models import Group
from .embedder import Embedder
from .guidance import GuidanceCorpus, GuidanceNote, RetrievalQuery, RetrievedNote, query_for_group
from .vector_store import LoadedIndex, embed_texts


def _technique_matches(note_technique: str, group_techniques: frozenset[str]) -> bool:
    """A note about T1003 applies to a group tagged T1003.001, not the other way round."""
    return any(tag == note_technique or tag.startswith(note_technique + ".") for tag in group_techniques)


def applies(note: GuidanceNote, query: RetrievalQuery) -> bool:
    """True when the note's front matter intersects the group's evidence."""
    scope = note.applies_to
    if scope.event_pairs() & query.event_pairs:
        return True
    if any(_technique_matches(technique, query.techniques) for technique in scope.techniques):
        return True
    return bool(set(scope.tactics) & query.tactics)


def prefilter(corpus: GuidanceCorpus, query: RetrievalQuery) -> tuple[list[GuidanceNote], bool]:
    """Candidate notes, and whether the metadata filter found any.

    When no note intersects the group, the whole corpus is ranked instead of
    returning nothing; the report records which case happened.
    """
    candidates = [note for note in corpus.notes if applies(note, query)]
    if candidates:
        return candidates, True
    return list(corpus.notes), False


class GuidanceRetriever:
    def __init__(
        self,
        *,
        corpus: GuidanceCorpus,
        index: LoadedIndex,
        embedder: Embedder,
        query_instruction: str,
        use_prefilter: bool = True,
    ) -> None:
        self._corpus = corpus
        self._index = index
        self._embedder = embedder
        self._instruction = query_instruction
        self._use_prefilter = use_prefilter

    def provenance(self) -> dict[str, object]:
        return {
            "retriever": "guidance-exact-cosine",
            "embedding_model_id": self._index.meta.model_id,
            "embedding_dim": self._index.meta.dim,
            "corpus_hash": self._corpus.content_hash,
            "note_count": self._index.meta.note_count,
            "query_instruction": self._instruction,
        }

    def rank(self, query: RetrievalQuery) -> list[RetrievedNote]:
        """Every candidate note, best first. `retrieve` applies top_k and min_score."""
        if self._use_prefilter:
            candidates, matched = prefilter(self._corpus, query)
        else:
            candidates, matched = list(self._corpus.notes), False

        vector = embed_texts(
            self._embedder,
            [self._instruction + query.text],
            dim=self._index.meta.dim,
            batch_size=1,
            expect_normalized=self._index.meta.normalized,
        )[0]

        rows = [self._index.row(note.id) for note in candidates]
        scores = self._index.matrix[rows] @ vector if rows else np.zeros(0, dtype=np.float32)

        scored = [
            RetrievedNote(note=note, score=float(score), matched_prefilter=matched)
            for note, score in zip(candidates, scores, strict=True)
        ]
        # Scores are rounded for ordering so float noise in the last bits cannot
        # swap two notes; exact ties fall back to the note id.
        scored.sort(key=lambda item: (-round(item.score, 6), item.note.id))
        return scored

    def retrieve(self, group: Group, *, top_k: int, min_score: float) -> list[RetrievedNote]:
        ranked = self.rank(query_for_group(group))
        return [item for item in ranked if item.score >= min_score][:top_k]
