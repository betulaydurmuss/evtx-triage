"""Generate knowledge/attack/techniques.json from a pinned MITRE ATT&CK release.

Hayabusa writes more than techniques into MitreTags: group ids (G####) and
software ids (S####) appear there too, so all three object kinds are extracted.

Run this only when the pinned ATT&CK version changes, and commit the result: the
tool itself must never reach the network for knowledge (run time stays on loopback).

    python scripts/build_attack_json.py --version 19.2

The generated file carries only identifiers, names, tactic short names and the
ATT&CK page URL. ATT&CK is (c) The MITRE Corporation; the attribution
note travels with the data.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)
ATTRIBUTION = (
    "MITRE ATT&CK(r) is a registered trademark of The MITRE Corporation. "
    "Technique identifiers, names and tactic assignments are reproduced from the "
    "ATT&CK Enterprise matrix, (c) The MITRE Corporation. https://attack.mitre.org/"
)


def attack_id(entry: dict[str, Any]) -> tuple[str, str] | None:
    for reference in entry.get("external_references", []):
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return reference["external_id"], reference.get("url", "")
    return None


def build(version: str, out_path: Path) -> int:
    url = BUNDLE_URL.format(version=version)
    print(f"downloading {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "evtx-triage-build"})
    with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310 - pinned https URL
        bundle = json.load(response)

    kinds = {
        "attack-pattern": "technique",
        "intrusion-set": "group",
        "malware": "software",
        "tool": "software",
    }

    techniques: list[dict[str, Any]] = []
    for entry in bundle.get("objects", []):
        kind = kinds.get(entry.get("type", ""))
        if kind is None:
            continue
        # Deprecated and revoked entries are kept, flagged rather than dropped:
        # Sigma rules still carry older identifiers (T1070.001 is gone from the
        # v19.2 matrix), and "deprecated in ATT&CK 19.2" is more useful to an
        # analyst than "unknown identifier".
        retired = bool(entry.get("revoked")) or bool(entry.get("x_mitre_deprecated"))
        identity = attack_id(entry)
        if identity is None:
            continue
        identifier, page = identity
        techniques.append(
            {
                "attack_id": identifier,
                "kind": kind,
                "name": entry.get("name", ""),
                "retired": retired,
                "tactics": [
                    phase["phase_name"]
                    for phase in entry.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ],
                "is_subtechnique": bool(entry.get("x_mitre_is_subtechnique", False)),
                "url": page,
            }
        )

    techniques.sort(key=lambda item: (item["kind"], item["attack_id"]))
    payload = {
        "attack_version": version,
        "source": url,
        "attribution": ATTRIBUTION,
        "technique_count": len(techniques),
        "techniques": techniques,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    counts: dict[str, int] = {}
    for item in techniques:
        counts[item["kind"]] = counts.get(item["kind"], 0) + 1
    counts["retired"] = sum(1 for item in techniques if item["retired"])
    print(f"wrote {out_path} with {len(techniques)} entries: {counts}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="19.2", help="pinned ATT&CK Enterprise version")
    parser.add_argument("--out", default="knowledge/attack/techniques.json")
    args = parser.parse_args()
    return build(args.version, Path(args.out))


if __name__ == "__main__":
    raise SystemExit(main())
