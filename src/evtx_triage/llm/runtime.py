"""Is the local runtime ready? The checks behind `evtx-triage doctor`, and automatic model loading.

Each check is read-only apart from two one-token probe requests, which are the
only way to learn whether a model is loaded: `/v1/models` lists every CACHED
model, loaded or not (measured on Foundry Local 0.10.3).

HTTP goes through urllib with proxy discovery switched off, so a probe cannot
leave the machine even when the environment or the registry names a proxy.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from ..tokens import PromptBudget

Status = Literal["ok", "warn", "fail"]

# Chat probe. Sent WITH a system message on purpose: without one, the Qwen chat
# template injects its own default system prompt and the overhead is no longer 13.
PROBE_SYSTEM = "You are a readiness probe."
PROBE_USER = "Reply with OK."


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str


class _NoProxyOpener:
    """urllib without proxy discovery: loopback requests stay on loopback."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(
        self, method: str, url: str, payload: dict[str, Any] | None, timeout: float
    ) -> tuple[int, Any]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(request, timeout=timeout) as response:
                status, body = response.status, response.read()
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read()
        try:
            return status, json.loads(body.decode("utf-8")) if body else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return status, body.decode("utf-8", errors="replace")


def _error_text(body: Any) -> str:
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            return str(error.get("message", error))
        if error is not None:
            return str(error)
    return str(body)[:300]


def check_endpoint(endpoint: str, model_ids: list[str], *, timeout: float) -> Check:
    """The server answers and has the configured models in its cache."""
    try:
        status, body = _NoProxyOpener().request("GET", f"{endpoint.rstrip('/')}/models", None, timeout)
    except (urllib.error.URLError, OSError) as exc:
        return Check(
            "endpoint",
            "fail",
            f"{endpoint} unreachable ({exc}); start it with: foundry server start --port "
            f"{urlparse(endpoint).port} --idle-timeout 0",
        )
    if status != 200 or not isinstance(body, dict):
        return Check("endpoint", "fail", f"{endpoint}/models returned HTTP {status}: {_error_text(body)}")
    listed = {str(item.get("id")) for item in body.get("data", []) if isinstance(item, dict)}
    missing = [model for model in model_ids if model not in listed]
    if missing:
        return Check(
            "endpoint",
            "fail",
            f"not in the Foundry Local cache: {', '.join(missing)}; "
            "download with: foundry model download <id>",
        )
    return Check("endpoint", "ok", f"{endpoint} answers; cached: {', '.join(model_ids)}")


def check_chat_model(endpoint: str, model_id: str, budget: PromptBudget, *, timeout: float) -> list[Check]:
    """A one-token completion: is the model loaded, and do our token counts match the server's?"""
    payload = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": PROBE_SYSTEM},
            {"role": "user", "content": PROBE_USER},
        ],
        "max_tokens": 1,
        "temperature": 0.0,
    }
    try:
        status, body = _NoProxyOpener().request(
            "POST", f"{endpoint.rstrip('/')}/chat/completions", payload, timeout
        )
    except (urllib.error.URLError, OSError) as exc:
        return [Check("chat model", "fail", f"probe request failed: {exc}")]
    if status != 200 or not isinstance(body, dict):
        return [
            Check(
                "chat model",
                "fail",
                f"{model_id}: HTTP {status}: {_error_text(body)}; load with: foundry model load {model_id}",
            )
        ]

    checks = [Check("chat model", "ok", f"{model_id} loaded and generating")]
    usage = body.get("usage") if isinstance(body.get("usage"), dict) else None
    if usage is None or "prompt_tokens" not in usage:
        checks.append(Check("token count", "warn", "server reported no usage; cannot compare token counts"))
        return checks

    server = int(usage["prompt_tokens"])
    ours = budget.prompt_tokens(PROBE_SYSTEM, PROBE_USER)
    if budget.counter.name != "tokenizer":
        checks.append(
            Check(
                "token count",
                "warn",
                f'pack.token_counter = "estimate": {ours} estimated vs {server} real tokens on the probe; '
                "the estimate wastes evidence budget",
            )
        )
    elif ours == server:
        checks.append(
            Check("token count", "ok", f"tokenizer + template overhead = {server} tokens, as the server")
        )
    else:
        checks.append(
            Check(
                "token count",
                "fail",
                f"we count {ours} tokens, the server {server}: llm.tokenizer_file or "
                "llm.chat_template_overhead_tokens does not match the running model",
            )
        )
    return checks


def check_embedding_model(
    endpoint: str, model_id: str, *, dim: int, normalized: bool, timeout: float
) -> Check:
    payload = {"model": model_id, "input": ["readiness probe"]}
    try:
        status, body = _NoProxyOpener().request(
            "POST", f"{endpoint.rstrip('/')}/embeddings", payload, timeout
        )
    except (urllib.error.URLError, OSError) as exc:
        return Check("embedding model", "fail", f"probe request failed: {exc}")
    if status != 200 or not isinstance(body, dict) or not body.get("data"):
        return Check(
            "embedding model",
            "fail",
            f"{model_id}: HTTP {status}: {_error_text(body)}; load with: foundry model load {model_id}",
        )
    vector = [float(value) for value in body["data"][0].get("embedding", [])]
    if len(vector) != dim:
        return Check(
            "embedding model", "fail", f"{model_id} returned {len(vector)} dimensions, config says {dim}"
        )
    norm = math.sqrt(sum(value * value for value in vector))
    if normalized and abs(norm - 1.0) > 1e-3:
        return Check(
            "embedding model", "fail", f"{model_id} vectors have norm {norm:.4f}, config says normalized"
        )
    return Check("embedding model", "ok", f"{model_id} loaded, {dim} dimensions")


# `  TCP    127.0.0.1:5273    0.0.0.0:0    LISTENING    6692` (state word is localised,
# so listeners are recognised by their wildcard foreign address instead).
NETSTAT_LINE = re.compile(r"^\s*TCP\s+(\S+):(\d+)\s+(0\.0\.0\.0:0|\[::\]:0)\s", re.IGNORECASE)
LOOPBACK_ADDRESSES = {"127.0.0.1", "[::1]"}


def parse_listeners(netstat_output: str, port: int) -> list[str]:
    """Local addresses with a TCP listener on `port`, from `netstat -ano -p TCP` style output."""
    found: list[str] = []
    for line in netstat_output.splitlines():
        match = NETSTAT_LINE.match(line)
        if match and int(match.group(2)) == port:
            found.append(match.group(1))
    return sorted(set(found))


def check_loopback_listener(endpoint: str) -> Check:
    """The server must not listen on an address other machines can reach (ADR-0001 criterion 5)."""
    port = urlparse(endpoint).port
    if port is None:
        return Check("listen address", "warn", f"no explicit port in {endpoint}; cannot inspect listeners")
    if sys.platform != "win32":
        return Check("listen address", "warn", "listener inspection is implemented for Windows netstat only")
    outputs: list[str] = []
    for family in ("TCP", "TCPv6"):
        try:
            completed = subprocess.run(
                ["netstat", "-ano", "-p", family], capture_output=True, text=True, timeout=30, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Check("listen address", "warn", f"netstat failed: {exc}")
        outputs.append(completed.stdout)
    listeners = parse_listeners("\n".join(outputs), port)
    if not listeners:
        return Check("listen address", "fail", f"nothing listens on port {port}")
    exposed = [address for address in listeners if address not in LOOPBACK_ADDRESSES]
    if exposed:
        return Check(
            "listen address",
            "fail",
            f"port {port} is also reachable on {', '.join(exposed)}; the server must listen on loopback only",
        )
    return Check("listen address", "ok", f"port {port} listens on {', '.join(listeners)} only")


def check_gpu_memory() -> Check:
    """Informational: a model that is loaded and has served a request holds most of the 8 GB."""
    if shutil.which("nvidia-smi") is None:
        return Check("gpu memory", "warn", "nvidia-smi not found; GPU memory unknown")
    try:
        completed = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.used,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Check("gpu memory", "warn", f"nvidia-smi failed: {exc}")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if completed.returncode != 0 or not lines:
        return Check("gpu memory", "warn", f"nvidia-smi exited {completed.returncode}")
    parts = [part.strip() for part in lines[0].split(",")]
    if len(parts) != 3:
        return Check("gpu memory", "warn", f"unexpected nvidia-smi output: {lines[0]}")
    name, used, total = parts
    return Check(
        "gpu memory",
        "ok",
        f"{name}: {used} / {total} MiB in use "
        "(the arena grows to ~7.9 GB after a request; ADR-0001 section 5)",
    )


def gpu_memory_used_mib() -> int | None:
    """Used GPU memory of the first GPU, or None when nvidia-smi is unavailable."""
    if shutil.which("nvidia-smi") is None:
        return None
    try:
        completed = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        first = completed.stdout.strip().splitlines()[0]
        return int(first.strip())
    except (OSError, subprocess.TimeoutExpired, IndexError, ValueError):
        return None


# --- automatic model loading (ADR-0001 section 9b decision, 2026-09-15) -------------
#
# Only `foundry model load` is automated, and only for a model that is already in the
# cache while the server is already running: measured, a load opens no connection
# off the machine (ADR-0001 section 9, C1a). Starting, stopping or restarting the
# server stays with the user, because `server start` contacts Azure.

NOT_LOADED = re.compile(r"is not loaded", re.IGNORECASE)


class RuntimeNotReady(Exception):
    """The runtime cannot serve a request, with the command that would fix it."""


@dataclass(frozen=True)
class LoadPolicy:
    foundry_cli: str
    timeout_seconds: int
    max_gpu_used_before_chat_load_mib: int


Runner = Callable[[list[str], int], "subprocess.CompletedProcess[str]"]


def _run_cli(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    # The Foundry CLI writes UTF-8 with colour codes; the Windows default code page
    # cannot decode it and the reader thread would die with the output lost.
    return subprocess.run(
        args, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout, check=False
    )


def _probe(
    kind: Literal["chat", "embedding"], endpoint: str, model_id: str, timeout: float
) -> tuple[int, Any]:
    base = endpoint.rstrip("/")
    if kind == "chat":
        payload: dict[str, Any] = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": PROBE_SYSTEM},
                {"role": "user", "content": PROBE_USER},
            ],
            "max_tokens": 1,
            "temperature": 0.0,
        }
        return _NoProxyOpener().request("POST", f"{base}/chat/completions", payload, timeout)
    return _NoProxyOpener().request(
        "POST", f"{base}/embeddings", {"model": model_id, "input": ["readiness probe"]}, timeout
    )


def _start_hint(endpoint: str) -> str:
    return f"foundry server start --port {urlparse(endpoint).port} --idle-timeout 0"


def ensure_model_loaded(
    endpoint: str,
    model_id: str,
    *,
    kind: Literal["chat", "embedding"],
    policy: LoadPolicy,
    timeout: float,
    runner: Runner = _run_cli,
    gpu_used: Callable[[], int | None] = gpu_memory_used_mib,
    log: Callable[[str], None] = lambda message: None,
) -> Literal["already loaded", "loaded"]:
    """Load a cached model into a running server if it is not loaded yet; raise RuntimeNotReady otherwise."""
    try:
        status, body = _probe(kind, endpoint, model_id, timeout)
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeNotReady(
            f"{endpoint} unreachable ({exc}); start the server: {_start_hint(endpoint)}"
        ) from exc
    if status == 200:
        return "already loaded"
    if not NOT_LOADED.search(_error_text(body)):
        raise RuntimeNotReady(f"{model_id}: HTTP {status}: {_error_text(body)}")

    # The server says "not loaded" for unknown models too; only load what is cached,
    # so a typo or a missing model never turns into a download.
    listed = check_endpoint(endpoint, [model_id], timeout=timeout)
    if listed.status != "ok":
        raise RuntimeNotReady(listed.detail)

    if kind == "chat":
        used = gpu_used()
        if used is not None and used > policy.max_gpu_used_before_chat_load_mib:
            raise RuntimeNotReady(
                f"the GPU already holds {used} MiB while {model_id} is not loaded. Memory of an unloaded "
                "model is not returned, and loading on top of it ends in an out-of-memory error "
                "(ADR-0001 section 7). Restart the server: foundry server stop, wait until nvidia-smi "
                f"shows about 0 MiB, then {_start_hint(endpoint)}"
            )

    cli = shutil.which(policy.foundry_cli)
    if cli is None:
        raise RuntimeNotReady(
            f"{model_id} is not loaded and the Foundry CLI {policy.foundry_cli!r} was not found; "
            f"load it yourself: foundry model load {model_id}"
        )
    log(f"loading {model_id} (foundry model load)")
    try:
        completed = runner([cli, "model", "load", model_id], policy.timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeNotReady(
            f"foundry model load {model_id} did not finish in {policy.timeout_seconds}s"
        ) from exc
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "").strip()[-400:]
        raise RuntimeNotReady(f"foundry model load {model_id} exited {completed.returncode}: {tail}")

    status, body = _probe(kind, endpoint, model_id, timeout)
    if status != 200:
        raise RuntimeNotReady(
            f"{model_id} still not usable after loading: HTTP {status}: {_error_text(body)}"
        )
    return "loaded"


WARM_UP_SYSTEM = "You are a readiness probe. Reply with OK."
WARM_UP_FILLER = " x"


def warm_up_text(budget: PromptBudget) -> str:
    """A user message that brings the request to exactly the input budget (by our count)."""
    target = budget.max_input_tokens
    base = "Reply with OK."
    step = budget.counter.count(WARM_UP_FILLER) or 1
    missing = max(target - budget.prompt_tokens(WARM_UP_SYSTEM, base), 0)
    text = base + WARM_UP_FILLER * (missing // step)
    while budget.prompt_tokens(WARM_UP_SYSTEM, text) > target and len(text) > len(base):
        text = text[: -len(WARM_UP_FILLER)]
    while budget.prompt_tokens(WARM_UP_SYSTEM, text + WARM_UP_FILLER) <= target:
        text += WARM_UP_FILLER
    return text


def warm_up(endpoint: str, model_id: str, budget: PromptBudget, *, timeout: float) -> int:
    """Send one request at the full input budget before any group, and return its prompt tokens.

    Measured (ADR-0001 section 6, 2026-09-16): on a freshly started server whose first
    requests were small, every later request of 3,764 tokens or more failed with a GPU
    out-of-memory error, while the same prompts passed after one full-budget request was
    served first. The arena appears to need its largest block (the logits buffer,
    0.58 MB per prompt token) before smaller requests fragment it. A warm-up that fails
    means the server must be restarted, which is reported before any group is sent.
    """
    payload = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": WARM_UP_SYSTEM},
            {"role": "user", "content": warm_up_text(budget)},
        ],
        "max_tokens": 1,
        "temperature": 0.0,
    }
    try:
        status, body = _NoProxyOpener().request(
            "POST", f"{endpoint.rstrip('/')}/chat/completions", payload, timeout
        )
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeNotReady(f"warm-up request failed: {exc}") from exc
    if status != 200 or not isinstance(body, dict):
        text = _error_text(body)
        if any(
            marker in text.lower() for marker in ("out of memory", "failed to allocate memory", "bfcarena")
        ):
            raise RuntimeNotReady(
                f"GPU out of memory on the {budget.max_input_tokens}-token warm-up request. The server's "
                "memory arena is fragmented or full; restart it: foundry server stop, wait until "
                f"nvidia-smi shows about 0 MiB, then {_start_hint(endpoint)}"
            )
        raise RuntimeNotReady(f"warm-up request: HTTP {status}: {text}")
    usage = body.get("usage")
    return int(usage.get("prompt_tokens", 0)) if isinstance(usage, dict) else 0


def check_tokenizer_file(path: Path, model_id: str, token_counter: str) -> Check:
    """The tokenizer must be the chat model's own, or the exact counts are exact for the wrong model."""
    if token_counter != "tokenizer":
        return Check(
            "tokenizer", "warn", 'pack.token_counter = "estimate"; token counts are upper-bound guesses'
        )
    if not path.is_file():
        return Check("tokenizer", "fail", f"llm.tokenizer_file not found: {path}")
    # The cache folder is the model id plus a version suffix: qwen2.5-7b-instruct-cuda-gpu-4
    folder = re.compile(rf"^{re.escape(model_id.lower())}(-\d+)?$")
    if not any(folder.match(part.lower()) for part in path.parts):
        return Check(
            "tokenizer",
            "fail",
            f"{path} is not inside a folder of model {model_id}; "
            "point llm.tokenizer_file at that model's cache",
        )
    return Check("tokenizer", "ok", str(path))
