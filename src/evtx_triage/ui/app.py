"""Streamlit viewer for reports the CLI wrote.

    streamlit run src/evtx_triage/ui/app.py

The viewer runs no triage logic of its own. It starts the CLI as a subprocess and
then reads `report.json`, so what it shows is exactly what `evtx-triage triage`
produced. Everything it renders comes from `report_view.py`, which is plain data.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import streamlit as st

from evtx_triage.ui import report_view as view

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG = REPO_ROOT / "config" / "default.toml"
DEFAULT_CSV_DIR = REPO_ROOT / "data" / "hayabusa_csv"
DEFAULT_OUT_DIR = REPO_ROOT / "out" / "ui"


def run_triage(
    csv_path: Path, out_dir: Path, config_path: Path, *, no_llm: bool, audit: bool
) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "evtx_triage.cli",
        "triage",
        str(csv_path),
        "--out",
        str(out_dir),
        "--config",
        str(config_path),
        "--format",
        "json",
    ]
    if no_llm:
        command.append("--no-llm")
    if audit:
        command.append("--audit")
    started = time.monotonic()
    completed = subprocess.run(
        command, capture_output=True, encoding="utf-8", errors="replace", cwd=REPO_ROOT, check=False
    )
    return {
        "command": " ".join(command),
        "code": completed.returncode,
        "seconds": time.monotonic() - started,
        "log": (completed.stdout or "") + (completed.stderr or ""),
    }


def sidebar() -> Path | None:
    """Pick or produce a report; returns the path of the report to show."""
    st.sidebar.header("Report")
    chosen: Path | None = None

    csv_dir = Path(st.sidebar.text_input("CSV folder", str(DEFAULT_CSV_DIR)))
    candidates = view.find_csv_files(csv_dir)
    if candidates:
        labels = [str(path.relative_to(csv_dir)) for path in candidates]
        picked = st.sidebar.selectbox("CSV", labels, index=0)
        csv_path = csv_dir / picked
    else:
        st.sidebar.info("No CSV found in that folder; give a full path.")
        csv_path = Path(st.sidebar.text_input("CSV path", ""))

    config_path = Path(st.sidebar.text_input("Config", str(DEFAULT_CONFIG)))
    no_llm = st.sidebar.checkbox("--no-llm (deterministic part only)", value=False)
    audit = st.sidebar.checkbox("--audit (raw prompts and answers in the report)", value=False)

    if st.sidebar.button("Run triage", type="primary", disabled=not csv_path.is_file()):
        out_dir = DEFAULT_OUT_DIR / csv_path.stem
        with st.spinner(f"evtx-triage triage {csv_path.name} … the model takes 10–60 s per group"):
            result = run_triage(csv_path, out_dir, config_path, no_llm=no_llm, audit=audit)
        st.session_state["last_run"] = result
        report_path = out_dir / "report.json"
        if result["code"] == 0 and report_path.is_file():
            st.session_state["report_path"] = str(report_path)
        else:
            st.sidebar.error(f"triage exited {result['code']}")

    st.sidebar.divider()
    st.sidebar.caption("Or open a report the CLI wrote earlier")
    out_root = Path(st.sidebar.text_input("Reports folder", str(REPO_ROOT / "out")))
    existing = view.find_reports(out_root)[:50]
    if existing:
        labels = [str(path.relative_to(out_root)) for path in existing]
        picked_report = st.sidebar.selectbox("report.json", labels, index=0)
        if st.sidebar.button("Open"):
            st.session_state["report_path"] = str(out_root / picked_report)

    stored = st.session_state.get("report_path")
    if stored and Path(stored).is_file():
        chosen = Path(stored)
    return chosen


def show_run_log() -> None:
    result = st.session_state.get("last_run")
    if not result:
        return
    status = "finished" if result["code"] == 0 else f"exited {result['code']}"
    with st.expander(f"CLI run {status} in {result['seconds']:.0f} s", expanded=result["code"] != 0):
        st.code(result["command"], language="text")
        st.code(result["log"] or "(no output)", language="text")


def show_warnings(report: dict[str, Any]) -> None:
    warnings = view.all_warnings(report)
    if not warnings:
        return
    st.subheader("Warnings")
    for group_id, warning in warnings:
        text = f"**{group_id}** — {warning}"
        if warning.startswith("assessment"):
            st.error(text, icon="⚠")
        else:
            st.warning(text, icon="⚠")


def show_group(report: dict[str, Any], group_id: str) -> None:
    group = view.find_group(report, group_id)
    if group is None:
        st.info("Group not found in this report.")
        return
    outcome = view.outcomes(report).get(group_id, {})
    evidence = group.get("evidence") or {}

    columns = st.columns(5)
    columns[0].metric("highest level", group["max_level"])
    columns[1].metric("events", group["event_count"])
    columns[2].metric("assessment", outcome.get("assessment", outcome.get("status", "-")))
    columns[3].metric("prompt tokens", evidence.get("prompt_tokens") or 0)
    columns[4].metric("defused tokens", evidence.get("neutralized_control_tokens") or 0)

    for warning in outcome.get("warnings", []):
        st.error(warning, icon="⚠")

    if outcome.get("status") in {"rejected", "skipped"} and outcome.get("reasons"):
        st.warning("Model interpretation " + outcome["status"] + ": " + "; ".join(outcome["reasons"]))

    cited = view.cited_row_ids(group, outcome)
    shown = set(evidence.get("included_row_ids", []))

    if outcome.get("what_happened"):
        st.subheader("What appears to have happened")
        for claim in outcome["what_happened"]:
            st.markdown(f"- {claim['text']}  \n  _evidence: {', '.join(claim['evidence'])}_")
    if outcome.get("next_steps"):
        st.subheader("Suggested next steps")
        for step in outcome["next_steps"]:
            guidance = f" · guidance: {', '.join(step['guidance'])}" if step.get("guidance") else ""
            st.markdown(f"- {step['text']}  \n  _evidence: {', '.join(step['evidence'])}{guidance}_")

    guidance_rows = view.guidance_rows(group)
    if guidance_rows:
        st.subheader("Investigation guidance retrieved for this group")
        st.dataframe(guidance_rows, width="stretch", hide_index=True)

    if evidence:
        st.subheader("Evidence as the prompt showed it")
        st.dataframe(view.evidence_rows(group), width="stretch", hide_index=True)
        if evidence.get("dropped_row_ids"):
            st.caption(f"{evidence['note']} — dropped: {', '.join(evidence['dropped_row_ids'])}")

    st.subheader("Events")
    rows = view.event_rows(group, cited, shown)
    filters = st.columns([2, 2, 1, 3])
    levels = filters[0].multiselect("level", view.level_options(rows), default=[])
    channels = filters[1].multiselect("channel", view.channel_options(rows), default=[])
    event_ids = filters[2].multiselect("event id", view.event_id_options(rows), default=[])
    search = filters[3].text_input("search (rule, fields, user, row id)", "")
    toggles = st.columns(2)
    only_cited = toggles[0].checkbox("only rows the model cited", value=False)
    only_prompt = toggles[1].checkbox("only rows the prompt showed", value=False)

    filtered = view.filter_events(
        rows,
        levels=levels,
        channels=channels,
        event_ids=event_ids,
        search=search,
        only_cited=only_cited,
        only_in_prompt=only_prompt,
    )
    st.caption(f"{len(filtered)} / {len(rows)} events")
    st.dataframe(filtered, width="stretch", hide_index=True)


def main() -> None:
    st.set_page_config(page_title="evtx-triage report viewer", layout="wide")
    st.title("evtx-triage — report viewer")
    st.caption(
        "Shows a report.json written by the CLI. The viewer runs no triage logic: groups, "
        "evidence, guidance, model answers and warnings are read from the report as they are."
    )

    report_path = sidebar()
    show_run_log()
    if report_path is None:
        st.info("Pick a CSV and press **Run triage**, or open a report the CLI wrote earlier.")
        return

    report = view.load_report(report_path)
    st.success(f"report: {report_path}")

    with st.expander("Provenance (what produced this report)"):
        st.dataframe(
            [{"field": name, "value": value} for name, value in view.provenance_rows(report)],
            width="stretch",
            hide_index=True,
        )

    errors = report["deterministic"]["ingest_errors"]
    if errors:
        st.warning(f"{len(errors)} row(s) could not be parsed; they are listed in the report.")

    show_warnings(report)

    st.subheader("Groups")
    rows = view.group_rows(report)
    st.dataframe(rows, width="stretch", hide_index=True)

    if not rows:
        return
    labels = [f"{row['group']} · {row['level']} · {row['host']} · {row['assessment']}" for row in rows]
    picked = st.selectbox("Group", labels, index=0)
    show_group(report, rows[labels.index(picked)]["group"])


main()
