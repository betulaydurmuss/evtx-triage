"""Readiness checks behind `doctor`, and the HTTP client settings they rely on.

Every request here goes to a scripted server on 127.0.0.1. A bogus proxy is set
in the environment throughout: if any client honoured it, the request would go
to proxy.invalid and fail, so a passing test proves the proxy was ignored.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evtx_triage.llm import runtime
from evtx_triage.llm.client import FoundryLocalClient, LLMOutOfMemoryError
from evtx_triage.tokens import EstimateCounter, PromptBudget, TokenizerCounter

TINY = Path(__file__).resolve().parents[1] / "fixtures" / "tokenizer" / "tiny_tokenizer.json"
CHAT = "qwen2.5-7b-instruct-cuda-gpu"
EMBED = "qwen3-embedding-0.6b-generic-cpu"


@pytest.fixture(autouse=True)
def _bogus_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://proxy.invalid:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)


def _models(*ids: str) -> tuple[int, dict[str, object]]:
    return 200, {"object": "list", "data": [{"id": model, "object": "model"} for model in ids]}


def test_endpoint_lists_cached_models(fake_foundry) -> None:
    fake_foundry.routes[("GET", "/v1/models")] = _models(CHAT, EMBED)
    check = runtime.check_endpoint(fake_foundry.endpoint, [CHAT, EMBED], timeout=5)
    assert check.status == "ok"


def test_endpoint_reports_a_model_missing_from_the_cache(fake_foundry) -> None:
    fake_foundry.routes[("GET", "/v1/models")] = _models(EMBED)
    check = runtime.check_endpoint(fake_foundry.endpoint, [CHAT, EMBED], timeout=5)
    assert check.status == "fail" and CHAT in check.detail


def test_unreachable_endpoint_says_how_to_start_it(fake_foundry) -> None:
    endpoint = fake_foundry.endpoint.replace(str(fake_foundry.port), "1")
    check = runtime.check_endpoint(endpoint, [CHAT], timeout=5)
    assert check.status == "fail" and "foundry server start" in check.detail


def _chat_ok(prompt_tokens: int) -> tuple[int, dict[str, object]]:
    return 200, {
        "choices": [{"message": {"role": "assistant", "content": "OK"}, "finish_reason": "length"}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 1},
    }


def test_chat_probe_confirms_our_token_count(fake_foundry) -> None:
    budget = PromptBudget(counter=TokenizerCounter(TINY), max_input_tokens=4096, template_overhead_tokens=13)
    expected = budget.prompt_tokens(runtime.PROBE_SYSTEM, runtime.PROBE_USER)
    fake_foundry.routes[("POST", "/v1/chat/completions")] = _chat_ok(expected)

    checks = runtime.check_chat_model(fake_foundry.endpoint, CHAT, budget, timeout=5)

    assert [check.status for check in checks] == ["ok", "ok"]
    sent = fake_foundry.requests[-1][2]
    assert sent["max_tokens"] == 1 and sent["messages"][0]["role"] == "system"


def test_chat_probe_catches_a_token_count_mismatch(fake_foundry) -> None:
    budget = PromptBudget(counter=TokenizerCounter(TINY), max_input_tokens=4096, template_overhead_tokens=13)
    wrong = budget.prompt_tokens(runtime.PROBE_SYSTEM, runtime.PROBE_USER) + 16
    fake_foundry.routes[("POST", "/v1/chat/completions")] = _chat_ok(wrong)

    checks = runtime.check_chat_model(fake_foundry.endpoint, CHAT, budget, timeout=5)

    assert checks[1].status == "fail" and "chat_template_overhead_tokens" in checks[1].detail


def test_chat_probe_with_the_estimate_only_warns(fake_foundry) -> None:
    budget = PromptBudget(counter=EstimateCounter(1.9), max_input_tokens=4096, template_overhead_tokens=13)
    fake_foundry.routes[("POST", "/v1/chat/completions")] = _chat_ok(30)
    checks = runtime.check_chat_model(fake_foundry.endpoint, CHAT, budget, timeout=5)
    assert [check.status for check in checks] == ["ok", "warn"]


def test_model_not_loaded_is_a_failure_with_the_load_command(fake_foundry) -> None:
    fake_foundry.routes[("POST", "/v1/chat/completions")] = (
        400,
        {"error": {"message": f"Model '{CHAT}' is not loaded.", "type": "invalid_request_error"}},
    )
    budget = PromptBudget(counter=EstimateCounter(1.9), max_input_tokens=4096, template_overhead_tokens=13)
    checks = runtime.check_chat_model(fake_foundry.endpoint, CHAT, budget, timeout=5)
    assert checks[0].status == "fail"
    assert "is not loaded" in checks[0].detail and f"foundry model load {CHAT}" in checks[0].detail


def test_embedding_probe_checks_dimension_and_norm(fake_foundry) -> None:
    route = ("POST", "/v1/embeddings")
    fake_foundry.routes[route] = (200, {"data": [{"index": 0, "embedding": [0.6, 0.8]}]})
    assert (
        runtime.check_embedding_model(fake_foundry.endpoint, EMBED, dim=2, normalized=True, timeout=5).status
        == "ok"
    )
    assert (
        runtime.check_embedding_model(
            fake_foundry.endpoint, EMBED, dim=1024, normalized=True, timeout=5
        ).status
        == "fail"
    )
    fake_foundry.routes[route] = (200, {"data": [{"index": 0, "embedding": [3.0, 4.0]}]})
    assert (
        runtime.check_embedding_model(fake_foundry.endpoint, EMBED, dim=2, normalized=True, timeout=5).status
        == "fail"
    )


NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1200
  TCP    127.0.0.1:5273         0.0.0.0:0              DINLENIYOR      6692
  TCP    127.0.0.1:57039        127.0.0.1:5273         TIME_WAIT       0
  TCP    [::1]:5273             [::]:0                 LISTENING       6692
  TCP    [::]:445               [::]:0                 LISTENING       4
"""


def test_listeners_are_parsed_regardless_of_the_localised_state_word() -> None:
    assert runtime.parse_listeners(NETSTAT, 5273) == ["127.0.0.1", "[::1]"]
    assert runtime.parse_listeners(NETSTAT, 445) == ["[::]"]
    assert runtime.parse_listeners(NETSTAT, 57039) == []  # a client socket, not a listener


def test_tokenizer_file_must_belong_to_the_chat_model(tmp_path: Path) -> None:
    right = tmp_path / "Microsoft" / f"{CHAT}-4" / "v4" / "tokenizer.json"
    wrong = tmp_path / "Microsoft" / "phi-4-mini-instruct-cuda-gpu-1" / "tokenizer.json"
    for path in (right, wrong):
        path.parent.mkdir(parents=True)
        path.write_text("{}", encoding="utf-8")

    assert runtime.check_tokenizer_file(right, CHAT, "tokenizer").status == "ok"
    assert runtime.check_tokenizer_file(wrong, CHAT, "tokenizer").status == "fail"
    assert runtime.check_tokenizer_file(tmp_path / "absent.json", CHAT, "tokenizer").status == "fail"
    assert runtime.check_tokenizer_file(wrong, CHAT, "estimate").status == "warn"


def test_sdk_client_never_retries_an_oom_and_ignores_the_proxy(fake_foundry) -> None:
    """The OpenAI SDK resends 5xx responses twice by default; an OOM must reach the server once."""
    fake_foundry.routes[("POST", "/v1/chat/completions")] = (
        500,
        {"error": {"message": "CUDA failure 2: out of memory", "type": "server_error"}},
    )
    client = FoundryLocalClient(
        endpoint=fake_foundry.endpoint,
        model_id=CHAT,
        temperature=0.0,
        seed=1234,
        max_output_tokens=8,
        timeout_seconds=10,
    )
    with pytest.raises(LLMOutOfMemoryError):
        client.complete(system="s", user="u")
    assert len(fake_foundry.requests) == 1


# --- automatic model loading ----------------------------------------------------------

POLICY = runtime.LoadPolicy(foundry_cli="python", timeout_seconds=30, max_gpu_used_before_chat_load_mib=512)
NOT_LOADED = (400, {"error": {"message": f"Model '{CHAT}' is not loaded.", "type": "invalid_request_error"}})


def _loader(fake_foundry, calls: list[list[str]], *, returncode: int = 0):
    """A stand-in for `foundry model load` that flips the fake server to 'loaded'."""
    import subprocess

    def run(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if returncode == 0:
            fake_foundry.routes[("POST", "/v1/chat/completions")] = _chat_ok(20)
        return subprocess.CompletedProcess(args, returncode, stdout="", stderr="load failed")

    return run


def test_loaded_model_is_left_alone(fake_foundry) -> None:
    fake_foundry.routes[("POST", "/v1/chat/completions")] = _chat_ok(20)
    calls: list[list[str]] = []
    result = runtime.ensure_model_loaded(
        fake_foundry.endpoint,
        CHAT,
        kind="chat",
        policy=POLICY,
        timeout=5,
        runner=_loader(fake_foundry, calls),
        gpu_used=lambda: 7900,
    )
    assert result == "already loaded" and calls == []


def test_cached_model_is_loaded_with_the_cli(fake_foundry) -> None:
    fake_foundry.routes[("POST", "/v1/chat/completions")] = NOT_LOADED
    fake_foundry.routes[("GET", "/v1/models")] = _models(CHAT, EMBED)
    calls: list[list[str]] = []
    result = runtime.ensure_model_loaded(
        fake_foundry.endpoint,
        CHAT,
        kind="chat",
        policy=POLICY,
        timeout=5,
        runner=_loader(fake_foundry, calls),
        gpu_used=lambda: 0,
    )
    assert result == "loaded"
    assert len(calls) == 1 and calls[0][1:] == ["model", "load", CHAT]


def test_uncached_model_is_never_downloaded(fake_foundry) -> None:
    fake_foundry.routes[("POST", "/v1/chat/completions")] = NOT_LOADED
    fake_foundry.routes[("GET", "/v1/models")] = _models(EMBED)
    calls: list[list[str]] = []
    with pytest.raises(runtime.RuntimeNotReady, match="not in the Foundry Local cache"):
        runtime.ensure_model_loaded(
            fake_foundry.endpoint,
            CHAT,
            kind="chat",
            policy=POLICY,
            timeout=5,
            runner=_loader(fake_foundry, calls),
            gpu_used=lambda: 0,
        )
    assert calls == []


def test_chat_model_is_not_loaded_on_top_of_leftover_gpu_memory(fake_foundry) -> None:
    """ADR-0001 section 7: an unloaded model's memory stays; loading on top of it runs out of memory."""
    fake_foundry.routes[("POST", "/v1/chat/completions")] = NOT_LOADED
    fake_foundry.routes[("GET", "/v1/models")] = _models(CHAT, EMBED)
    calls: list[list[str]] = []
    with pytest.raises(runtime.RuntimeNotReady, match="foundry server stop"):
        runtime.ensure_model_loaded(
            fake_foundry.endpoint,
            CHAT,
            kind="chat",
            policy=POLICY,
            timeout=5,
            runner=_loader(fake_foundry, calls),
            gpu_used=lambda: 1773,
        )
    assert calls == []


def test_a_stopped_server_is_not_started(fake_foundry) -> None:
    endpoint = fake_foundry.endpoint.replace(str(fake_foundry.port), "1")
    calls: list[list[str]] = []
    with pytest.raises(runtime.RuntimeNotReady, match="foundry server start"):
        runtime.ensure_model_loaded(
            endpoint,
            CHAT,
            kind="chat",
            policy=POLICY,
            timeout=5,
            runner=_loader(fake_foundry, calls),
            gpu_used=lambda: 0,
        )
    assert calls == []


def test_failed_load_reports_the_cli_output(fake_foundry) -> None:
    fake_foundry.routes[("POST", "/v1/chat/completions")] = NOT_LOADED
    fake_foundry.routes[("GET", "/v1/models")] = _models(CHAT)
    with pytest.raises(runtime.RuntimeNotReady, match="load failed"):
        runtime.ensure_model_loaded(
            fake_foundry.endpoint,
            CHAT,
            kind="chat",
            policy=POLICY,
            timeout=5,
            runner=_loader(fake_foundry, [], returncode=1),
            gpu_used=lambda: 0,
        )


# --- warm-up at the full input budget -------------------------------------------------


def test_warm_up_text_reaches_the_budget_exactly() -> None:
    budget = PromptBudget(counter=TokenizerCounter(TINY), max_input_tokens=300, template_overhead_tokens=13)
    text = runtime.warm_up_text(budget)
    assert budget.prompt_tokens(runtime.WARM_UP_SYSTEM, text) <= 300
    assert budget.prompt_tokens(runtime.WARM_UP_SYSTEM, text + runtime.WARM_UP_FILLER) > 300


def test_warm_up_sends_one_full_budget_request(fake_foundry) -> None:
    budget = PromptBudget(counter=EstimateCounter(1.9), max_input_tokens=200, template_overhead_tokens=13)
    fake_foundry.routes[("POST", "/v1/chat/completions")] = _chat_ok(180)
    assert runtime.warm_up(fake_foundry.endpoint, CHAT, budget, timeout=5) == 180
    sent = fake_foundry.requests[-1][2]
    assert sent["max_tokens"] == 1
    assert budget.prompt_tokens(sent["messages"][0]["content"], sent["messages"][1]["content"]) <= 200


def test_warm_up_out_of_memory_asks_for_a_restart(fake_foundry) -> None:
    budget = PromptBudget(counter=EstimateCounter(1.9), max_input_tokens=200, template_overhead_tokens=13)
    fake_foundry.routes[("POST", "/v1/chat/completions")] = (
        500,
        {
            "error": {
                "message": "BFCArena::AllocateRawInternal Failed to allocate memory for requested buffer"
            }
        },
    )
    with pytest.raises(runtime.RuntimeNotReady, match="restart it"):
        runtime.warm_up(fake_foundry.endpoint, CHAT, budget, timeout=5)
    assert len(fake_foundry.requests) == 1
