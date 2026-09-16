"""The Streamlit app renders a report without running any triage logic.

Skipped unless the optional `ui` extra is installed: pip install -e ".[ui]"
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evtx_triage.config import Config

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest  # noqa: E402
from tests.unit.test_ui_report_view import _report  # noqa: E402

APP = Path(__file__).resolve().parents[2] / "src" / "evtx_triage" / "ui" / "app.py"


@pytest.fixture
def report_file(config: Config, mini_csv: Path, tmp_path: Path) -> Path:
    report = _report(config, mini_csv)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def _texts(app: AppTest) -> str:
    parts = [element.value for element in app.markdown] + [element.value for element in app.error]
    parts += [element.value for element in app.warning] + [element.value for element in app.success]
    parts += [element.value for element in app.subheader] + [element.value for element in app.caption]
    return " ".join(str(part) for part in parts)


def test_app_shows_the_report_it_is_given(report_file: Path) -> None:
    app = AppTest.from_file(str(APP), default_timeout=60)
    app.session_state["report_path"] = str(report_file)
    app.run()

    assert not app.exception
    report = json.loads(report_file.read_text(encoding="utf-8"))
    outcome = report["model"]["interpretations"][0]
    rendered = _texts(app)

    # the warning the CLI attached is on the page, not something the viewer decided
    assert any(outcome["warnings"][0] in str(element.value) for element in app.error)
    # group overview carries every group of the report
    table = app.dataframe[1].value if len(app.dataframe) > 1 else app.dataframe[0].value
    assert len(table) == len(report["deterministic"]["groups"])
    # the model's own words are shown
    assert outcome["what_happened"][0]["text"] in rendered
    assert outcome["next_steps"][0]["text"] in rendered
    assert str(report_file) in rendered


def test_app_without_a_report_asks_for_one() -> None:
    app = AppTest.from_file(str(APP), default_timeout=60)
    app.run()
    assert not app.exception
    assert "Run triage" in _texts(app) or app.info
