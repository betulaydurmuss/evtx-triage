"""Rank (channel, event id) pairs by how often they appear in Hayabusa timelines.

The ranking decides which dictionary entries are worth writing first: the head of
this list carries most of the rows an analyst will ever read.

    python scripts/eid_frequency.py data/hayabusa_csv/by_tactic/*.csv
    python scripts/eid_frequency.py data/hayabusa_csv --uncovered-only
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from evtx_triage.config import load_config  # noqa: E402
from evtx_triage.ingest.hayabusa_csv import InputContractError, read_events  # noqa: E402
from evtx_triage.knowledge.dictionary import load_dictionary  # noqa: E402


def collect(paths: list[Path]) -> tuple[Counter[tuple[str, int]], list[str]]:
    counts: Counter[tuple[str, int]] = Counter()
    skipped: list[str] = []
    for path in paths:
        try:
            result = read_events(path, assume_utc=False)
        except InputContractError as exc:
            skipped.append(f"{path.name}: {str(exc).splitlines()[0]}")
            continue
        for event in result.events:
            counts[(event.channel, event.event_id)] += 1
    return counts, skipped


def expand(inputs: list[str]) -> list[Path]:
    paths: list[Path] = []
    for item in inputs:
        path = Path(item)
        if path.is_dir():
            paths.extend(sorted(path.rglob("*.csv")))
        else:
            paths.append(path)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="CSV files or directories of CSV files")
    parser.add_argument("--config", default="config/default.toml")
    parser.add_argument(
        "--uncovered-only", action="store_true", help="only pairs the dictionary does not cover"
    )
    args = parser.parse_args()

    paths = expand(args.inputs)
    if not paths:
        print("no CSV files found", file=sys.stderr)
        return 2

    counts, skipped = collect(paths)
    dictionary = load_dictionary(
        load_config(Path(args.config)).resolve(load_config(Path(args.config)).knowledge.eventids_dir)
    )

    total = sum(counts.values())
    covered_rows = 0
    print(f"{'rows':>7} {'share':>7} {'kb':>4}  channel / event id")
    for (channel, event_id), count in counts.most_common():
        known = dictionary.lookup(channel, event_id) is not None
        if known:
            covered_rows += count
        if args.uncovered_only and known:
            continue
        print(f"{count:>7} {100 * count / total:>6.2f}% {'yes' if known else 'NO':>4}  {channel} {event_id}")

    print()
    print(f"pairs: {len(counts)}  rows: {total}")
    print(f"dictionary covers {covered_rows}/{total} rows ({100 * covered_rows / max(total, 1):.1f}%)")
    for line in skipped:
        print(f"skipped {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
