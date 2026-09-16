"""Guidance retrieval evaluation against eval/golden_queries.yaml (Faz 5 exit criterion).

    python eval/retrieval_eval.py            # needs the embedding model loaded and a fresh index
    python eval/retrieval_eval.py --verbose

Reports recall@k with the production settings, and two ablations that show where
the result comes from: without the metadata pre-filter, and without the query
instruction. It also embeds one query twice and ranks it twice, to check that
retrieval itself is deterministic.

Read docs/eval-dataset.md section 3 first: notes, queries and expected answers
were all written by the same party.
"""

from __future__ import annotations

import argparse
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import yaml  # noqa: E402

from evtx_triage.config import Config, load_config  # noqa: E402
from evtx_triage.knowledge.guidance import load_guidance, query_for_group  # noqa: E402
from evtx_triage.knowledge.retrieval import GuidanceRetriever  # noqa: E402
from evtx_triage.knowledge.vector_store import open_fresh_index  # noqa: E402
from evtx_triage.llm.embeddings import FoundryEmbedder  # noqa: E402
from evtx_triage.pipeline import DeterministicResult, run_deterministic  # noqa: E402


class CachingEmbedder:
    """Embeds each distinct text once, so ablations share query vectors."""

    def __init__(self, inner: FoundryEmbedder) -> None:
        self._inner = inner
        self._cache: dict[str, list[float]] = {}
        self.requests = 0

    @property
    def model_id(self) -> str:
        return self._inner.model_id

    def embed(self, texts: list[str]) -> list[list[float]]:
        missing = [text for text in texts if text not in self._cache]
        if missing:
            self.requests += 1
            for text, vector in zip(missing, self._inner.embed(missing), strict=True):
                self._cache[text] = vector
        return [self._cache[text] for text in texts]


@dataclass
class Variant:
    name: str
    retriever: GuidanceRetriever
    recalls: list[float]
    hits: list[bool]


def recall_at(expected: list[str], ranked: list[str], k: int) -> float:
    top = set(ranked[:k])
    return len(top & set(expected)) / len(expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queries", default="eval/golden_queries.yaml")
    parser.add_argument("--csv-root", default="data/hayabusa_csv")
    parser.add_argument("--config", default="config/default.toml")
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    config: Config = load_config(Path(args.config))
    corpus = load_guidance(config.resolve(config.knowledge.guidance_dir))
    index = open_fresh_index(
        config.resolve(config.retrieval.index_path),
        corpus=corpus,
        model_id=config.retrieval.embedding_model_id,
        dim=config.retrieval.embedding_dim,
    )
    embedder = CachingEmbedder(
        FoundryEmbedder(
            endpoint=config.llm.endpoint,
            model_id=config.retrieval.embedding_model_id,
            timeout_seconds=config.llm.timeout_seconds,
        )
    )

    def make(instruction: str, prefilter: bool) -> GuidanceRetriever:
        return GuidanceRetriever(
            corpus=corpus,
            index=index,
            embedder=embedder,
            query_instruction=instruction,
            use_prefilter=prefilter,
        )

    variants = [
        Variant(
            "production (prefilter + instruction)", make(config.retrieval.query_instruction, True), [], []
        ),
        Variant("no prefilter", make(config.retrieval.query_instruction, False), [], []),
        Variant("no instruction", make("", True), [], []),
    ]

    queries = yaml.safe_load(Path(args.queries).read_text(encoding="utf-8"))["queries"]
    results: dict[str, DeterministicResult] = {}
    fallback_count = 0

    print(f"{'query':<5} {'expected':<16} {'top-' + str(args.k) + ' (production)':<30} recall")
    for item in queries:
        csv_path = Path(args.csv_root) / item["csv"]
        if item["csv"] not in results:
            results[item["csv"]] = run_deterministic(config, csv_path)
        result = results[item["csv"]]
        group = next((g for g in result.selected if g.group_id == item["group"]), None)
        if group is None or group.host != item["host"]:
            print(
                f"{item['id']}: group {item['group']} on {item['host']} not found; grouping changed?",
                file=sys.stderr,
            )
            return 2
        if not any(item["rule_hint"].lower() in event.rule_title.lower() for event in group.events):
            print(
                f"{item['id']}: rule hint {item['rule_hint']!r} not in {item['group']}; grouping changed?",
                file=sys.stderr,
            )
            return 2

        query = query_for_group(group)
        for variant in variants:
            ranked = variant.retriever.rank(query)
            ids = [entry.note.id for entry in ranked]
            recall = recall_at(item["expected"], ids, args.k)
            variant.recalls.append(recall)
            variant.hits.append(recall > 0)
            if variant is variants[0]:
                if ranked and not ranked[0].matched_prefilter:
                    fallback_count += 1
                top = ", ".join(f"{entry.note.id}({entry.score:.2f})" for entry in ranked[: args.k])
                marker = "" if recall == 1 else ("  <- partial" if recall > 0 else "  <- MISS")
                print(f"{item['id']:<5} {','.join(item['expected']):<16} {top:<30} {recall:.2f}{marker}")
                if args.verbose:
                    print(f"      query: {query.text[:160]!r}")

    print()
    for variant in variants:
        mean = statistics.mean(variant.recalls)
        hit_rate = sum(variant.hits) / len(variant.hits)
        print(f"{variant.name:<40} recall@{args.k}={mean:.3f}  hit@{args.k}={hit_rate:.3f}")
    print(f"pre-filter fell back to the whole corpus: {fallback_count}/{len(queries)} queries")
    print(f"embedding requests: {embedder.requests}")

    # Determinism: the same query embedded twice and ranked twice must agree exactly.
    probe = query_for_group(next(iter(results.values())).selected[0])
    uncached = FoundryEmbedder(
        endpoint=config.llm.endpoint,
        model_id=config.retrieval.embedding_model_id,
        timeout_seconds=config.llm.timeout_seconds,
    )
    text = config.retrieval.query_instruction + probe.text
    first, second = uncached.embed([text])[0], uncached.embed([text])[0]
    same_vector = first == second
    ranking_a = [(e.note.id, e.score) for e in make(config.retrieval.query_instruction, True).rank(probe)]
    ranking_b = [(e.note.id, e.score) for e in make(config.retrieval.query_instruction, True).rank(probe)]
    print(f"determinism: query vector identical={same_vector}, ranking identical={ranking_a == ranking_b}")

    production = statistics.mean(variants[0].recalls)
    verdict = "MET" if production >= 0.8 else "NOT MET"
    print(f"\nFaz 5 exit criterion recall@{args.k} >= 0.8: {verdict} ({production:.3f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
