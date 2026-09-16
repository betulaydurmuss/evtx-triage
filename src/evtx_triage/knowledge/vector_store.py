"""SQLite vector store with exact cosine search (ADR-0001 section 4.5).

The corpus is tens of notes, so an approximate index would only add unstable
ordering. Vectors are stored as float32 blobs next to the metadata that decides
whether the index is still valid: embedding model, dimension and corpus hash.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from numpy.typing import NDArray

from .embedder import Embedder, EmbeddingError
from .guidance import GuidanceCorpus

SCHEMA_VERSION = "1"
NORM_TOLERANCE = 1e-3


class GuidanceIndexError(Exception):
    """The index is missing or unreadable."""


class StaleIndexError(GuidanceIndexError):
    """The index was built from a different corpus, model or dimension."""


@dataclass(frozen=True)
class IndexMeta:
    schema_version: str
    model_id: str
    dim: int
    corpus_hash: str
    note_count: int
    normalized: bool


@dataclass
class LoadedIndex:
    meta: IndexMeta
    ids: list[str]
    matrix: NDArray[np.float32]  # one L2-normalised row per note, ordered like `ids`

    def row(self, note_id: str) -> int:
        return self.ids.index(note_id)


def _normalise(matrix: NDArray[np.float32]) -> NDArray[np.float32]:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    if np.any(norms == 0):
        raise EmbeddingError("the embedding model returned an all-zero vector")
    result: NDArray[np.float32] = (matrix / norms).astype(np.float32)
    return result


def embed_texts(
    embedder: Embedder,
    texts: list[str],
    *,
    dim: int,
    batch_size: int,
    expect_normalized: bool,
) -> NDArray[np.float32]:
    """Embed in fixed-size batches, in order, and check what came back."""
    rows: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        batch = texts[start : start + batch_size]
        vectors = embedder.embed(batch)
        if len(vectors) != len(batch):
            raise EmbeddingError(f"asked for {len(batch)} vectors, got {len(vectors)}")
        rows.extend(vectors)

    matrix = np.asarray(rows, dtype=np.float32)
    if matrix.ndim != 2 or matrix.shape[1] != dim:
        raise EmbeddingError(f"expected {dim}-dimensional vectors, got shape {matrix.shape}")

    if expect_normalized:
        norms = np.linalg.norm(matrix, axis=1)
        if np.any(np.abs(norms - 1.0) > NORM_TOLERANCE):
            raise EmbeddingError(
                "retrieval.normalized is true but the model returned vectors with norms "
                f"between {norms.min():.4f} and {norms.max():.4f}; the model may have changed"
            )
    # Normalising again is harmless for unit vectors and makes cosine exact either way.
    return _normalise(matrix)


def build_index(
    path: Path,
    corpus: GuidanceCorpus,
    embedder: Embedder,
    *,
    dim: int,
    batch_size: int,
    expect_normalized: bool,
) -> IndexMeta:
    """Embed every note and write a fresh index, replacing any previous one atomically."""
    if not corpus.notes:
        raise GuidanceIndexError("the guidance corpus is empty; nothing to index")

    matrix = embed_texts(
        embedder,
        [note.embedding_text() for note in corpus.notes],
        dim=dim,
        batch_size=batch_size,
        expect_normalized=expect_normalized,
    )
    meta = IndexMeta(
        schema_version=SCHEMA_VERSION,
        model_id=embedder.model_id,
        dim=dim,
        corpus_hash=corpus.content_hash,
        note_count=len(corpus.notes),
        normalized=expect_normalized,
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    with sqlite3.connect(temporary) as connection:
        connection.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute(
            "CREATE TABLE vectors (note_id TEXT PRIMARY KEY, position INTEGER NOT NULL, vector BLOB NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            [
                ("schema_version", meta.schema_version),
                ("model_id", meta.model_id),
                ("dim", str(meta.dim)),
                ("corpus_hash", meta.corpus_hash),
                ("note_count", str(meta.note_count)),
                ("normalized", "true" if meta.normalized else "false"),
            ],
        )
        connection.executemany(
            "INSERT INTO vectors VALUES (?, ?, ?)",
            [(note.id, position, matrix[position].tobytes()) for position, note in enumerate(corpus.notes)],
        )
    connection.close()
    temporary.replace(path)
    return meta


def read_index(path: Path) -> LoadedIndex:
    if not path.is_file():
        raise GuidanceIndexError(f"guidance index not found: {path}\n  build it with: evtx-triage kb build")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            values = dict(connection.execute("SELECT key, value FROM meta").fetchall())
            rows = connection.execute("SELECT note_id, vector FROM vectors ORDER BY position").fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise GuidanceIndexError(f"guidance index is unreadable: {path}: {exc}") from exc

    meta = IndexMeta(
        schema_version=values.get("schema_version", "?"),
        model_id=values.get("model_id", "?"),
        dim=int(values.get("dim", "0")),
        corpus_hash=values.get("corpus_hash", "?"),
        note_count=int(values.get("note_count", "0")),
        normalized=values.get("normalized") == "true",
    )
    ids = [row[0] for row in rows]
    matrix = (
        np.vstack([np.frombuffer(row[1], dtype=np.float32) for row in rows])
        if rows
        else np.zeros((0, meta.dim), dtype=np.float32)
    )
    return LoadedIndex(meta=meta, ids=ids, matrix=matrix)


def staleness(index: LoadedIndex, *, corpus: GuidanceCorpus, model_id: str, dim: int) -> list[str]:
    """Every reason the index no longer matches the corpus and config; empty when fresh."""
    reasons: list[str] = []
    if index.meta.schema_version != SCHEMA_VERSION:
        reasons.append(f"index schema {index.meta.schema_version}, tool expects {SCHEMA_VERSION}")
    if index.meta.model_id != model_id:
        reasons.append(f"built with {index.meta.model_id}, config uses {model_id}")
    if index.meta.dim != dim:
        reasons.append(f"built with dimension {index.meta.dim}, config says {dim}")
    if index.meta.corpus_hash != corpus.content_hash:
        reasons.append("guidance notes changed since the index was built")
    if index.ids != corpus.ids:
        reasons.append("note ids in the index do not match the corpus")
    return reasons


def open_fresh_index(path: Path, *, corpus: GuidanceCorpus, model_id: str, dim: int) -> LoadedIndex:
    index = read_index(path)
    reasons = staleness(index, corpus=corpus, model_id=model_id, dim=dim)
    if reasons:
        raise StaleIndexError(
            "guidance index is stale:\n"
            + "\n".join(f"  - {reason}" for reason in reasons)
            + "\n  rebuild it with: evtx-triage kb build"
        )
    return index
