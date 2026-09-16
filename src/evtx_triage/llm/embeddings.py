"""Foundry Local embeddings over the loopback OpenAI-compatible endpoint.

Uses the CPU variant of the embedding model: it can stay loaded next to the chat
model without touching GPU memory (ADR-0001 section 7).
"""

from __future__ import annotations

from typing import Any

from ..knowledge.embedder import EmbeddingError
from .client import openai_client


class FoundryEmbedder:
    def __init__(self, *, endpoint: str, model_id: str, timeout_seconds: int) -> None:
        self._client: Any = openai_client(endpoint=endpoint, timeout_seconds=timeout_seconds)
        self._model_id = model_id

    @property
    def model_id(self) -> str:
        return self._model_id

    def embed(self, texts: list[str]) -> list[list[float]]:
        try:
            response = self._client.embeddings.create(model=self._model_id, input=texts)
        except Exception as exc:  # noqa: BLE001 - mapped to our own error type
            raise EmbeddingError(
                f"embedding request failed: {exc}\n  is the model loaded? foundry model load {self._model_id}"
            ) from exc
        data = sorted(response.data, key=lambda item: item.index)
        return [list(item.embedding) for item in data]
