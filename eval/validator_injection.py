"""Validator fault injection on REAL model answers (Faz 6 exit criterion).

    python eval/validator_injection.py out/faz6            # every */report.json below it
    python eval/validator_injection.py out/faz5 out/faz6 --json out/eval/validator_injection.json

The unit catalogue in tests/unit/test_validate.py breaks a hand-written answer.
This script breaks the answers the model actually gave: every accepted
interpretation in the reports is re-validated against the context its prompt
showed (validate.context_from_report), then mutated one fault at a time.

Three numbers come out:
- originals: stored answers that still pass today's rules. Answers from an
  older validator (Faz 5 checked rules 1-3 only) can fail rules 4-6 here, which
  is a finding about the old answers, not an error of this script;
- faults: mutations that must be rejected; the exit criterion is 100%;
- controls: harmless wrappers (reasoning block, code fence) that must still pass.
Mutations are applied to originals that pass, so a rejection is caused by the fault.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from evtx_triage.config import load_config  # noqa: E402
from evtx_triage.knowledge.guidance import load_guidance  # noqa: E402
from evtx_triage.validate import ValidationContext, context_from_report, validate_interpretation  # noqa: E402

Body = dict[str, Any]
# A mutation returns the raw text to validate, or None when it does not apply to this answer.
Mutation = Callable[[Body, ValidationContext, dict[str, Any]], str | None]

# Commonly seen ids a model might invent; the first one absent from the group is used.
CANDIDATE_EIDS = [4624, 4688, 7045, 1, 4104, 3, 11, 13, 4625, 4720]
CANDIDATE_TECHNIQUES = ["T1059.001", "T1003.001", "T1021.002", "T1547.001", "T1110"]
FABRICATED_IP = "203.0.113.7"  # TEST-NET-3, documentation range


def _body(outcome: dict[str, Any]) -> Body:
    return {
        "group_id": outcome["group_id"],
        "assessment": outcome["assessment"],
        "what_happened": copy.deepcopy(outcome["what_happened"]),
        "next_steps": copy.deepcopy(outcome["next_steps"]),
    }


def _dump(body: Body) -> str:
    return json.dumps(body, ensure_ascii=False)


def _edit(apply: Callable[[Body], bool]) -> Mutation:
    def mutate(body: Body, context: ValidationContext, group: dict[str, Any]) -> str | None:
        changed = copy.deepcopy(body)
        return _dump(changed) if apply(changed) else None

    return mutate


def _unshown_row(body: Body, context: ValidationContext, group: dict[str, Any]) -> str | None:
    evidence = group.get("evidence") or {}
    hidden = sorted(
        (set(evidence.get("included_row_ids", [])) | set(evidence.get("dropped_row_ids", [])))
        - context.row_ids
    )
    if not hidden:
        return None
    changed = copy.deepcopy(body)
    changed["what_happened"][0]["evidence"] = [hidden[0]]
    return _dump(changed)


def _unretrieved_guidance(corpus_ids: list[str]) -> Mutation:
    def mutate(body: Body, context: ValidationContext, group: dict[str, Any]) -> str | None:
        spare = [note_id for note_id in corpus_ids if note_id not in context.guidance_ids]
        if not body["next_steps"] or not spare:
            return None
        changed = copy.deepcopy(body)
        changed["next_steps"][0]["guidance"] = [*changed["next_steps"][0]["guidance"], spare[0]]
        return _dump(changed)

    return mutate


def _append_text(section: str, suffix: Callable[[ValidationContext], str | None]) -> Mutation:
    def mutate(body: Body, context: ValidationContext, group: dict[str, Any]) -> str | None:
        text = suffix(context)
        if not body[section] or text is None:
            return None
        changed = copy.deepcopy(body)
        changed[section][0]["text"] = f"{changed[section][0]['text']} {text}"
        return _dump(changed)

    return mutate


def _foreign_eid(context: ValidationContext) -> str | None:
    eid = next((value for value in CANDIDATE_EIDS if value not in context.event_ids), None)
    return None if eid is None else f"This matches EID {eid}."


def _foreign_technique(context: ValidationContext) -> str | None:
    allowed = context.techniques
    for technique in CANDIDATE_TECHNIQUES:
        if technique not in allowed and not any(item.startswith(technique + ".") for item in allowed):
            return f"See {technique}."
    return None


def _sub_of_parent(context: ValidationContext) -> str | None:
    """A sub-technique invented under a parent the group or its notes carry (parent to child is refused)."""
    for technique in sorted(context.techniques):
        if "." not in technique:
            candidate = f"{technique}.999"
            if candidate not in context.techniques:
                return f"Specifically {candidate}."
    return None


def _wrap(prefix: str, suffix: str) -> Mutation:
    def mutate(body: Body, context: ValidationContext, group: dict[str, Any]) -> str | None:
        return prefix + _dump(body) + suffix

    return mutate


def fault_catalogue(corpus_ids: list[str]) -> dict[str, Mutation]:
    def set_group(body: Body) -> bool:
        body["group_id"] = "G9999"
        return True

    def set_assessment(body: Body) -> bool:
        body["assessment"] = "definitely_evil"
        return True

    def add_field(body: Body) -> bool:
        body["confidence"] = 0.9
        return True

    def drop_steps(body: Body) -> bool:
        body.pop("next_steps")
        return True

    def ghost_row(body: Body) -> bool:
        body["what_happened"][0]["evidence"] = ["R999999"]
        return True

    def claim_without_evidence(body: Body) -> bool:
        body["what_happened"][0]["evidence"] = []
        return True

    def step_without_evidence(body: Body) -> bool:
        if not body["next_steps"]:
            return False
        body["next_steps"][0]["evidence"] = []
        return True

    return {
        "cites a row that does not exist": _edit(ghost_row),
        "cites a group row the prompt did not show": _unshown_row,
        "claim without evidence": _edit(claim_without_evidence),
        "next step without evidence": _edit(step_without_evidence),
        "cites guidance that was not retrieved": _unretrieved_guidance(corpus_ids),
        "fabricated EID in a claim": _append_text("what_happened", _foreign_eid),
        "fabricated EID in a next step": _append_text("next_steps", _foreign_eid),
        "fabricated technique id": _append_text("what_happened", _foreign_technique),
        "invented sub-technique of a known parent": _append_text("what_happened", _sub_of_parent),
        "fabricated IPv4 address": _append_text(
            "what_happened", lambda _: f"Traffic went to {FABRICATED_IP}."
        ),
        "wrong group id": _edit(set_group),
        "unknown assessment": _edit(set_assessment),
        "unexpected field": _edit(add_field),
        "missing field": _edit(drop_steps),
        "truncated JSON": lambda body, context, group: _dump(body)[: len(_dump(body)) // 2],
        "prose instead of JSON": lambda body, context, group: (
            "The activity looks malicious; isolate the host."
        ),
    }


CONTROLS: dict[str, Mutation] = {
    "reasoning block before the JSON": _wrap("<think>weighing the evidence</think>\n", ""),
    "JSON inside a code fence": _wrap("```json\n", "\n```"),
}


@dataclass
class Tally:
    applied: int = 0
    caught: int = 0
    misses: list[str] = field(default_factory=list)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("roots", nargs="+", type=Path, help="directories holding */report.json")
    parser.add_argument("--config", type=Path, default=Path("config/default.toml"))
    parser.add_argument("--json", type=Path, help="also write the results here")
    args = parser.parse_args()

    config = load_config(args.config)
    corpus = load_guidance(config.resolve(config.knowledge.guidance_dir))
    note_techniques = {note.id: list(note.applies_to.techniques) for note in corpus.notes}
    faults = fault_catalogue(corpus.ids)

    fault_tally = {name: Tally() for name in faults}
    control_tally = {name: Tally() for name in CONTROLS}
    originals: list[dict[str, Any]] = []

    reports = sorted(path for root in args.roots for path in root.glob("*/report.json"))
    for path in reports:
        report = json.loads(path.read_text(encoding="utf-8"))
        groups = {group["group_id"]: group for group in report["deterministic"]["groups"]}
        for outcome in report["model"]["interpretations"]:
            if outcome["status"] != "accepted":
                continue
            label = f"{path.parent.name}/{outcome['group_id']}"
            group = groups[outcome["group_id"]]
            context = context_from_report(group, note_techniques)
            body = _body(outcome)
            accepted, errors = validate_interpretation(_dump(body), context)
            originals.append({"answer": label, "still_accepted": accepted is not None, "errors": errors})
            if accepted is None:
                continue

            for name, mutate in faults.items():
                raw = mutate(body, context, group)
                if raw is None:
                    continue
                fault_tally[name].applied += 1
                if validate_interpretation(raw, context)[0] is None:
                    fault_tally[name].caught += 1
                else:
                    fault_tally[name].misses.append(label)
            for name, mutate in CONTROLS.items():
                raw = mutate(body, context, group)
                assert raw is not None
                control_tally[name].applied += 1
                if validate_interpretation(raw, context)[0] is not None:
                    control_tally[name].caught += 1  # here: still accepted
                else:
                    control_tally[name].misses.append(label)

    kept = sum(1 for item in originals if item["still_accepted"])
    print(f"reports: {len(reports)}  accepted answers: {len(originals)}  still accepted today: {kept}")
    for item in originals:
        if not item["still_accepted"]:
            print(f"  rejected by today's rules: {item['answer']}")
            for error in item["errors"]:
                print(f"    - {error}")

    print(f"\n{'fault':<45} {'applied':>7} {'caught':>7}")
    applied = caught = 0
    for name, tally in fault_tally.items():
        applied += tally.applied
        caught += tally.caught
        flag = "" if tally.caught == tally.applied else "   MISSED: " + ", ".join(tally.misses)
        print(f"{name:<45} {tally.applied:>7} {tally.caught:>7}{flag}")
    rate = caught / applied if applied else 0.0
    print(f"{'TOTAL':<45} {applied:>7} {caught:>7}   detection {rate:.1%}")

    print(f"\n{'control (must stay accepted)':<45} {'applied':>7} {'accepted':>8}")
    controls_ok = True
    for name, tally in control_tally.items():
        controls_ok = controls_ok and tally.caught == tally.applied
        print(f"{name:<45} {tally.applied:>7} {tally.caught:>8}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "reports": [str(path) for path in reports],
            "originals": originals,
            "faults": {name: vars(tally) for name, tally in fault_tally.items()},
            "controls": {name: vars(tally) for name, tally in control_tally.items()},
            "detection_rate": rate,
        }
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    return 0 if applied and caught == applied and controls_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
