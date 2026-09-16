"""Shared fixtures.

Network policy: unit tests may not reach anything but the loopback interface.
pytest-socket turns any other connection into a test failure.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from pytest_socket import socket_allow_hosts

from evtx_triage.config import Config, load_config

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class FakeFoundry:
    """A scripted OpenAI-compatible server on 127.0.0.1 that records every request."""

    routes: dict[tuple[str, str], tuple[int, Any]] = field(default_factory=dict)
    requests: list[tuple[str, str, Any]] = field(default_factory=list)
    port: int = 0

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"


@pytest.fixture
def fake_foundry() -> Iterator[FakeFoundry]:
    fake = FakeFoundry()

    class Handler(BaseHTTPRequestHandler):
        def _serve(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            fake.requests.append((method, self.path, json.loads(raw) if raw else None))
            status, body = fake.routes.get((method, self.path), (404, {"error": "no route"}))
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            self._serve("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._serve("POST")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    fake.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def _loopback_only() -> None:
    socket_allow_hosts(["127.0.0.1", "::1"], allow_unix_socket=True)


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def config_path() -> Path:
    return REPO_ROOT / "config" / "default.toml"


@pytest.fixture
def config(config_path: Path) -> Config:
    """The shipped config, counting tokens by estimate.

    The exact counter needs the model's tokenizer file from the Foundry Local cache,
    which a test machine may not have. Tests that exercise it load it explicitly
    (tests/unit/test_tokens.py) or use the small synthetic tokenizer fixture.
    """
    shipped = load_config(config_path)
    return shipped.model_copy(update={"pack": shipped.pack.model_copy(update={"token_counter": "estimate"})})


@pytest.fixture
def mini_csv() -> Path:
    return REPO_ROOT / "tests" / "fixtures" / "synthetic" / "mini.csv"
