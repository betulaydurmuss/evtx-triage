"""The only place in the package that talks to a model.

Every `openai` / Foundry Local import stays inside `evtx_triage.llm`, so the
deterministic core can be tested without a GPU.
"""

from __future__ import annotations

from typing import Any, Protocol

OOM_MARKERS = (
    "out of memory",
    "failed to allocate memory",
    "bfcarena",
    "cuda failure 2",
)


class LLMError(Exception):
    """The model could not be reached or refused the request."""


class LLMOutOfMemoryError(LLMError):
    """The GPU ran out of memory.

    Measured in Faz 0: one OOM fragments the daemon's arena, so retrying in the
    same process keeps failing (ADR-0001 section 6). Never retried.
    """


class LLMClient(Protocol):
    def complete(self, *, system: str, user: str) -> str:
        """Return the raw assistant message for one stateless request."""
        ...


def openai_client(*, endpoint: str, timeout_seconds: int) -> Any:
    """The OpenAI-compatible client for the loopback endpoint, with two SDK defaults turned off.

    - `trust_env=False`: the SDK's HTTP client otherwise honours HTTP(S)_PROXY and,
      on Windows, the system proxy from the registry, which could route a prompt full
      of log data to a proxy host (rule: run-time network stays on loopback).
    - `max_retries=0`: the SDK otherwise resends a request up to twice on a 5xx or a
      timeout. A GPU OOM arrives as a 5xx and must never be retried (ADR-0001
      section 6); validation retries are our own, in interpret.py.
    """
    import openai  # imported lazily so the core stays import-light

    http_client = openai.DefaultHttpx2Client(trust_env=False, timeout=timeout_seconds)
    return openai.OpenAI(
        base_url=endpoint,
        api_key="not-needed",
        timeout=timeout_seconds,
        max_retries=0,
        http_client=http_client,
    )


def _classify(error: Exception) -> LLMError:
    text = str(error).lower()
    if any(marker in text for marker in OOM_MARKERS):
        return LLMOutOfMemoryError(str(error))
    return LLMError(str(error))


class FoundryLocalClient:
    """OpenAI-compatible client pointed at the loopback Foundry Local endpoint."""

    def __init__(
        self,
        *,
        endpoint: str,
        model_id: str,
        temperature: float,
        seed: int,
        max_output_tokens: int,
        timeout_seconds: int,
    ) -> None:
        # Deliberately untyped: the SDK is a lazy import, so the deterministic
        # core can be type-checked and tested without it being installed.
        self._client: Any = openai_client(endpoint=endpoint, timeout_seconds=timeout_seconds)
        self._model_id = model_id
        self._temperature = temperature
        self._seed: int | None = seed
        self._max_output_tokens = max_output_tokens
        self.last_usage: dict[str, int] = {}

    def complete(self, *, system: str, user: str) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        try:
            return self._call(messages, with_seed=self._seed is not None)
        except LLMError:
            raise
        except Exception as exc:  # noqa: BLE001 - mapped to our own error types
            # Foundry Local may reject parameters the OpenAI schema allows; drop
            # the seed once and remember, rather than failing the whole run.
            if self._seed is not None and "seed" in str(exc).lower():
                self._seed = None
                try:
                    return self._call(messages, with_seed=False)
                except Exception as retry_exc:  # noqa: BLE001
                    raise _classify(retry_exc) from retry_exc
            raise _classify(exc) from exc

    def _call(self, messages: list[dict[str, str]], *, with_seed: bool) -> str:
        if with_seed and self._seed is not None:
            response = self._client.chat.completions.create(
                model=self._model_id,
                messages=messages,
                temperature=self._temperature,
                max_tokens=self._max_output_tokens,
                seed=self._seed,
            )
        else:
            response = self._client.chat.completions.create(
                model=self._model_id,
                messages=messages,
                temperature=self._temperature,
                max_tokens=self._max_output_tokens,
            )
        usage = getattr(response, "usage", None)
        self.last_usage = (
            {"prompt_tokens": int(usage.prompt_tokens), "completion_tokens": int(usage.completion_tokens)}
            if usage is not None
            else {}
        )
        finish = response.choices[0].finish_reason
        if finish is not None:
            self.last_usage["finish_length"] = int(finish == "length")
        content = response.choices[0].message.content
        return str(content) if content else ""


class FakeLLM:
    """Scripted client for tests: hands back queued responses, or raises queued errors."""

    def __init__(self, responses: list[str | Exception]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def complete(self, *, system: str, user: str) -> str:
        self.calls.append((system, user))
        if not self._responses:
            raise LLMError("FakeLLM ran out of scripted responses")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item
