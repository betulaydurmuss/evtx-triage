"""The embedding interface.

The deterministic core only depends on this protocol. The Foundry Local
implementation lives in `evtx_triage.llm.embeddings`, because every model access
stays under `llm/`.
"""

from __future__ import annotations

from typing import Protocol


class EmbeddingError(Exception):
    """The embedding model could not be reached or returned something unusable."""


class Embedder(Protocol):
    @property
    def model_id(self) -> str:
        """Identifier stored in the index, so a model change makes the index stale."""
        ...

    def embed(self, texts: list[str]) -> list[list[float]]:
        """One vector per input text, in input order."""
        ...
