"""Run Hayabusa once per EVTX sample and pin every input and output by hash (eval/samples.lock).

    python scripts/generate_sample_csvs.py --hayabusa C:\\tools\\hayabusa-4.1.0\\hayabusa-4.1.0-win-x64.exe

Writes data/hayabusa_csv/per_evtx/<Tactic folder>/<sample>.csv (git-ignored: the
samples are GPL and never committed) and eval/samples.lock, which holds only
names, detection counts and SHA-256 hashes.

`-A` (enable all rules) is part of the command on purpose. Without it Hayabusa
builds a channel filter from a sample of each file and enables only the rules for
the channels it saw; on a single file that took 49 s and silently dropped 7 of 19
detections of Credential Access/tutto_malseclogon.evtx, one of them medium
(ADR-0002 section 2, amendment 2026-09-15). With `-A` the same file takes 2.5 s.

A sample Microsoft Defender blocks is recorded as blocked and skipped; Defender is
never turned off and never worked around.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HAYABUSA_FLAGS = ["-p", "all-field-info-verbose", "-U", "-O", "-w", "-q", "-C", "-b", "-A"]
SAFE = re.compile(r"[^a-z0-9_]+")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def csv_name(evtx: Path) -> str:
    return SAFE.sub("_", evtx.stem.lower()).strip("_") + ".csv"


def detections(path: Path) -> int:
    with path.open(encoding="utf-8", newline="") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--hayabusa", type=Path, required=True)
    parser.add_argument("--samples", type=Path, default=Path("data/samples/EVTX-ATTACK-SAMPLES"))
    parser.add_argument("--out", type=Path, default=Path("data/hayabusa_csv/per_evtx"))
    parser.add_argument("--lock", type=Path, default=Path("eval/samples.lock"))
    args = parser.parse_args()

    commit = subprocess.run(
        ["git", "-C", str(args.samples), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    ).stdout.strip()
    evtx_files = sorted(args.samples.rglob("*.evtx"), key=lambda p: p.relative_to(args.samples).as_posix())

    entries = []
    started = time.monotonic()
    for position, evtx in enumerate(evtx_files, start=1):
        relative = evtx.relative_to(args.samples).as_posix()
        folder = evtx.parent.relative_to(args.samples).as_posix() or "."
        target = args.out / folder / csv_name(evtx)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.unlink(missing_ok=True)
        entry: dict[str, object] = {
            "evtx": relative,
            "evtx_sha256": sha256(evtx),
            "csv": target.relative_to(args.out).as_posix(),
        }
        try:
            completed = subprocess.run(
                [str(args.hayabusa), "dfir-timeline", "-f", str(evtx), *HAYABUSA_FLAGS, "-o", str(target)],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as exc:
            # Measured: Defender refuses to start Hayabusa when the command line names
            # Invoke-Mimikatz (ThreatID 2147725502). Recorded, not worked around.
            entry["status"] = f"blocked: process start refused ({exc.strerror or exc})"
            entries.append(entry)
            print(f"[{position:>3}/{len(evtx_files)}] {entry['status']:<16} {relative}", flush=True)
            continue
        if completed.returncode != 0:
            entry["status"] = f"hayabusa exit {completed.returncode}"
        elif not target.exists():
            entry["status"] = "no detections"  # Hayabusa writes no file when nothing matched
        else:
            try:
                entry["detections"] = detections(target)
                entry["csv_sha256"] = sha256(target)
                entry["status"] = "ok" if entry["detections"] else "no detections"
            except OSError as exc:  # Defender blocks reading a file it flagged
                entry["status"] = f"blocked: {exc.strerror or exc}"
        entries.append(entry)
        print(f"[{position:>3}/{len(evtx_files)}] {entry['status']:<16} {relative}", flush=True)

    lock = {
        "samples_repository": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
        "samples_commit": commit,
        "hayabusa": {
            "binary": args.hayabusa.name,
            "binary_sha256": sha256(args.hayabusa),
            "command": ["dfir-timeline", "-f", "<evtx>", *HAYABUSA_FLAGS, "-o", "<csv>"],
        },
        "samples": entries,
    }
    args.lock.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n")
    counts: dict[str, int] = {}
    for entry in entries:
        key = str(entry["status"]).split(":")[0]
        counts[key] = counts.get(key, 0) + 1
    print(f"\n{len(entries)} samples in {time.monotonic() - started:.0f}s: {counts}")
    print(f"lock written: {args.lock}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
