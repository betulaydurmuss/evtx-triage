"""Model evaluation on the labelled samples (Faz 7).

    python eval/run_eval.py --run --tag qwen25-v3   # triage every labelled CSV, then score
    python eval/run_eval.py --tag qwen25-v3         # score the reports in out/eval/runs/<tag>
    python eval/run_eval.py --run --tag phi4mini-v3 --config config/phi4mini.toml

With --run, each labelled CSV goes through the real CLI (`triage --audit`) one after
another on the running server, while nvidia-smi is sampled for peak GPU memory.
Scoring reads only the reports, so it can be repeated without the model.

Per labelled sample, over the groups that hold the label's key events:
- status and attempts; first attempt accepted; schema-valid on the first attempt;
- fabrication before validation: first attempts rejected for a row, guidance note,
  EID, technique or IP that the evidence does not contain (rules 3 to 6);
- key event recall, per matcher: a label's key event counts as found when the model
  cited at least one row it matches (a folded line counts for every row it stands
  for); per row as a secondary number, which large folded sets pull down;
- must_mention_any hit, must_not_mention violations, assessment in the accepted set;
- interpretation seconds per group; peak GPU memory during the sample's run.

Labels were drafted by the party that wrote the tool (docs/eval-dataset.md section 3).
The numbers are an optimistic upper bound until the labels are verified.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from metrics import matches  # noqa: E402

from evtx_triage.llm.runtime import gpu_memory_used_mib  # noqa: E402

FABRICATION = ("which was not shown", "which was not retrieved", "mentions EID", "mentions IP", "mentions T")
SCHEMA = ("not valid JSON", "does not match the required schema", "group_id is")


class ReportEvent:
    """The attributes metrics.matches reads, taken from an event in report.json."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.row_id: str = payload["row_id"]
        self.channel: str = payload["channel"]
        self.event_id: int = int(payload["event_id"])
        self.principal_user: str | None = payload["principal_user"]
        self.rule_title: str = payload["rule_title"]
        self.fields: dict[str, Any] = payload["fields"]

    def field_text(self, key: str) -> str:
        value = self.fields.get(key)
        if value is None:
            return ""
        return " | ".join(value) if isinstance(value, list) else str(value)


@dataclass
class GroupScore:
    group_id: str
    status: str
    attempts: int
    first_accepted: bool
    first_schema_valid: bool
    first_fabricated: bool
    assessment: str | None
    assessment_ok: bool
    warnings: int
    seconds: float


@dataclass
class SampleScore:
    label: str
    csv: str
    found: bool
    groups: list[GroupScore] = field(default_factory=list)
    key_events: int = 0
    key_events_cited: int = 0
    matchers: int = 0
    matchers_cited: int = 0
    mention_hit: bool = False
    forbidden: list[str] = field(default_factory=list)
    peak_gpu_mib: int | None = None
    note: str = ""


def _key_matchers(label: dict[str, Any]) -> list[dict[str, Any]]:
    if label.get("key_events_same_group", True):
        return list(label.get("key_events", []))
    return [matcher for story in label.get("expected_groups", []) for matcher in story["key_events"]]


def score_sample(label: dict[str, Any], label_name: str, report: dict[str, Any] | None) -> SampleScore:
    sample = SampleScore(label=label_name, csv=label["csv"], found=report is not None)
    if report is None:
        sample.note = "no report"
        return sample

    groups = report["deterministic"]["groups"]
    outcomes = {item["group_id"]: item for item in report["model"]["interpretations"]}
    audit: dict[tuple[str, int], dict[str, Any]] = {
        (item["group_id"], item["attempt"]): item for item in report.get("audit", [])
    }
    events = [(group, ReportEvent(event)) for group in groups for event in group["events"]]

    key_rows: set[str] = set()
    rows_per_matcher: list[set[str]] = []
    target_groups: set[str] = set()
    for matcher in _key_matchers(label):
        hits: set[str] = set()
        for group, event in events:
            if matches(event, matcher):  # type: ignore[arg-type]
                hits.add(event.row_id)
                target_groups.add(group["group_id"])
        rows_per_matcher.append(hits)
        key_rows |= hits
    sample.key_events = len(key_rows)
    sample.matchers = len(rows_per_matcher)

    cited: set[str] = set()
    texts: list[str] = []
    for group in groups:
        if group["group_id"] not in target_groups:
            continue
        outcome = outcomes.get(group["group_id"])
        if outcome is None:
            continue  # below the model threshold
        first = audit.get((group["group_id"], 1))
        first_errors = first["errors"] if first else outcome.get("reasons", [])
        accepted = outcome["status"] == "accepted"
        sample.groups.append(
            GroupScore(
                group_id=group["group_id"],
                status=outcome["status"],
                attempts=outcome["attempts"],
                first_accepted=accepted and outcome["attempts"] == 1,
                first_schema_valid=bool(first) and not any(m in e for e in first_errors for m in SCHEMA),
                first_fabricated=any(marker in error for error in first_errors for marker in FABRICATION),
                assessment=outcome.get("assessment"),
                assessment_ok=outcome.get("assessment") in label.get("acceptable_assessments", []),
                warnings=len(outcome.get("warnings", [])),
                seconds=float(outcome.get("duration_seconds", 0.0)),
            )
        )
        if not accepted:
            continue
        shown = {
            entry["row_ids"][0]: entry["row_ids"]
            for entry in (group.get("evidence") or {}).get("entries", [])
        }
        for item in outcome.get("what_happened", []) + outcome.get("next_steps", []):
            texts.append(item["text"].lower())
            for row_id in item["evidence"]:
                cited.update(shown.get(row_id, [row_id]))

    sample.key_events_cited = len(key_rows & cited)
    sample.matchers_cited = sum(1 for hits in rows_per_matcher if hits & cited)
    joined = " ".join(texts)
    sample.mention_hit = any(word.lower() in joined for word in label.get("must_mention_any", []))
    sample.forbidden = [word for word in label.get("must_not_mention", []) if word.lower() in joined]
    return sample


class GpuSampler:
    def __init__(self) -> None:
        self.peak: int | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            used = gpu_memory_used_mib()
            if used is not None:
                self.peak = used if self.peak is None else max(self.peak, used)
            self._stop.wait(0.5)

    def __enter__(self) -> GpuSampler:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join()


def run_triage(csv_path: Path, out_dir: Path, config: Path) -> tuple[int, int | None]:
    with GpuSampler() as sampler:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "evtx_triage.cli",
                "triage",
                str(csv_path),
                "--out",
                str(out_dir),
                "--format",
                "json",
                "--audit",
                "--config",
                str(config),
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    (out_dir / "triage.log").parent.mkdir(parents=True, exist_ok=True)
    (out_dir / "triage.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    return completed.returncode, sampler.peak


def _rate(numerator: int, denominator: int) -> str:
    return f"{numerator}/{denominator} ({numerator / denominator:.0%})" if denominator else "n/a"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--tag", required=True, help="name of this run, e.g. qwen25-v3")
    parser.add_argument("--run", action="store_true", help="run triage on every labelled CSV first")
    parser.add_argument("--labels", type=Path, default=Path("eval/labels/expected"))
    parser.add_argument("--csv-dir", type=Path, default=Path("data/hayabusa_csv/eval"))
    parser.add_argument("--config", type=Path, default=Path("config/default.toml"))
    parser.add_argument("--runs-dir", type=Path, default=Path("out/eval/runs"))
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--max-minutes",
        type=float,
        default=0.0,
        help="with --run, stop starting new samples after this long (0: no limit); rerun to continue",
    )
    args = parser.parse_args()
    budget_started = time.monotonic()

    run_dir = args.runs_dir / args.tag
    peaks_path = run_dir / "gpu_peaks.json"
    peaks: dict[str, int | None] = (
        json.loads(peaks_path.read_text(encoding="utf-8")) if peaks_path.is_file() else {}
    )
    labels = sorted(args.labels.glob("*.yaml"))
    if args.run:
        run_dir.mkdir(parents=True, exist_ok=True)
        for position, label_path in enumerate(labels, start=1):
            label = yaml.safe_load(label_path.read_text(encoding="utf-8"))
            csv_path = args.csv_dir / label["csv"]
            if not csv_path.is_file():
                print(f"[{position}/{len(labels)}] missing CSV {csv_path}", flush=True)
                continue
            if (run_dir / csv_path.stem / "report.json").is_file():
                # Resumable: this machine kills long jobs when memory runs low.
                print(f"[{position}/{len(labels)}] {csv_path.stem} already has a report, skipped", flush=True)
                continue
            if args.max_minutes and time.monotonic() - budget_started > args.max_minutes * 60:
                print("time budget reached; rerun to continue", flush=True)
                return 3
            started = time.monotonic()
            code, peak = run_triage(csv_path, run_dir / csv_path.stem, args.config)
            peaks[csv_path.stem] = peak
            peaks_path.write_text(json.dumps(peaks, indent=2) + "\n", encoding="utf-8")
            print(
                f"[{position}/{len(labels)}] {csv_path.stem} exit={code} "
                f"{time.monotonic() - started:.0f}s peak_gpu={peak} MiB",
                flush=True,
            )

    samples: list[SampleScore] = []
    for label_path in labels:
        label = yaml.safe_load(label_path.read_text(encoding="utf-8"))
        report_path = run_dir / Path(label["csv"]).stem / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else None
        sample = score_sample(label, label_path.stem, report)
        sample.peak_gpu_mib = peaks.get(Path(label["csv"]).stem)
        samples.append(sample)

    heading = (
        f"{'grp':>3} {'status':<10} {'att':>3} {'assess':<17} {'ok':<3} {'keys':>5} {'ment':<4} {'s':>5}"
    )
    print(f"\n{'label':<36} {heading}")
    for sample in samples:
        for score in sample.groups or [None]:
            if score:
                middle = (
                    f"{score.group_id[-3:]:>3} {score.status:<10} {score.attempts:>3} "
                    f"{score.assessment!s:<17} {'y' if score.assessment_ok else 'N':<3} "
                )
            else:
                middle = f"{'-':>3} {sample.note or 'no model group':<10} {'':>3} {'':<17} {'':<3} "
            keys = f"{sample.matchers_cited:>2}/{sample.matchers:<2}"
            mention = "y" if sample.mention_hit else "N"
            seconds_text = f"{score.seconds:>5.0f}" if score else ""
            print(f"{sample.label[:36]:<36} {middle}{keys} {mention:<4} {seconds_text}")

    groups = [score for sample in samples for score in sample.groups]
    found = [sample for sample in samples if sample.found]
    keys = sum(sample.key_events for sample in found)
    keys_cited = sum(sample.key_events_cited for sample in found)
    seconds = [score.seconds for score in groups if score.seconds]
    peak_values = [sample.peak_gpu_mib for sample in samples if sample.peak_gpu_mib is not None]
    summary = {
        "tag": args.tag,
        "samples": len(samples),
        "reports": len(found),
        "model_groups": len(groups),
        "first_attempt_accepted": sum(score.first_accepted for score in groups),
        "first_attempt_schema_valid": sum(score.first_schema_valid for score in groups),
        "first_attempt_fabricated": sum(score.first_fabricated for score in groups),
        "fallback": sum(score.status != "accepted" for score in groups),
        "key_events": keys,
        "key_events_cited": keys_cited,
        "key_matchers": sum(sample.matchers for sample in found),
        "key_matchers_cited": sum(sample.matchers_cited for sample in found),
        "mention_hits": sum(sample.mention_hit for sample in found),
        "forbidden_mentions": sum(bool(sample.forbidden) for sample in found),
        "assessment_ok": sum(score.assessment_ok for score in groups),
        "assessment_warnings": sum(bool(score.warnings) for score in groups),
        "seconds_median": round(statistics.median(seconds), 1) if seconds else None,
        "seconds_max": round(max(seconds), 1) if seconds else None,
        "peak_gpu_mib": max(peak_values) if peak_values else None,
    }
    n = len(groups)
    print(f"\n=== {args.tag}: {len(found)}/{len(samples)} reports, {n} model groups holding key events")
    print(f"first attempt accepted      : {_rate(summary['first_attempt_accepted'], n)}")
    print(f"first attempt schema-valid  : {_rate(summary['first_attempt_schema_valid'], n)}")
    print(f"fabrication before checking : {_rate(summary['first_attempt_fabricated'], n)}")
    print(f"fallback (rejected/skipped) : {_rate(summary['fallback'], n)}   threshold proposal <= 10%")
    matcher_recall = _rate(summary["key_matchers_cited"], summary["key_matchers"])
    print(f"key event recall (matchers) : {matcher_recall}   threshold proposal >= 0.7")
    print(f"key event recall (rows)     : {_rate(keys_cited, keys)}")
    print(f"must_mention hit            : {_rate(summary['mention_hits'], len(found))}")
    print(f"must_not_mention violated   : {summary['forbidden_mentions']}")
    print(f"assessment acceptable       : {_rate(summary['assessment_ok'], n)}")
    print(f"assessment warnings         : {summary['assessment_warnings']}")
    print(f"seconds per group           : median {summary['seconds_median']}, max {summary['seconds_max']}")
    print(f"peak GPU memory             : {summary['peak_gpu_mib']} MiB")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {"summary": summary, "samples": [asdict(sample) for sample in samples]}
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
