"""List the licence of every installed dependency and flag anything not MIT-compatible.

    python scripts/check_licenses.py            # runtime + dev + ui, as installed
    python scripts/check_licenses.py --strict   # exit 1 when a licence needs a decision

The project is MIT. Permissive licences (MIT, BSD, Apache-2.0, ISC, PSF, MPL-2.0)
are compatible; copyleft ones (GPL, AGPL, LGPL without an exception) are not and
must not end up in the distribution. Metadata is read from the installed packages,
so this reflects the environment that was actually tested, not a wish list.
"""

from __future__ import annotations

import argparse
import re
from importlib.metadata import distributions

PERMISSIVE = re.compile(
    r"\b(mit|bsd|apache|isc|psf|python software foundation|mpl-2|mozilla public license 2|unlicense|"
    r"zlib|cnri|historical permission notice)\b",
    re.IGNORECASE,
)
COPYLEFT = re.compile(r"\b(gpl|agpl|lgpl|eupl|cecill|osl|sspl)\b", re.IGNORECASE)


def licence_of(metadata: object) -> str:
    """Licence text from the metadata, whichever field the package filled in."""
    get = getattr(metadata, "get_all", None)
    fields = []
    if get is not None:
        fields = [value for value in (get("License-Expression") or []) if value]
        fields += [value for value in (get("License") or []) if value]
        for classifier in get("Classifier") or []:
            if classifier.startswith("License ::"):
                fields.append(classifier.split("::")[-1].strip())
    text = "; ".join(dict.fromkeys(str(field).strip() for field in fields if str(field).strip()))
    return text or "UNKNOWN"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    rows = []
    for distribution in distributions():
        name = distribution.metadata["Name"]
        if not name or name.lower() == "evtx-triage":
            continue
        rows.append((name, distribution.version, licence_of(distribution.metadata)))

    needs_decision = []
    print(f"{'package':<28} {'version':<14} licence")
    for name, version, licence in sorted(rows, key=lambda row: row[0].lower()):
        flag = ""
        if COPYLEFT.search(licence) and not PERMISSIVE.search(licence):
            flag = "  <-- copyleft, check"
            needs_decision.append((name, licence))
        elif not PERMISSIVE.search(licence):
            flag = "  <-- unclear, check"
            needs_decision.append((name, licence))
        print(f"{name:<28} {version:<14} {licence[:60]}{flag}")

    print(f"\n{len(rows)} packages, {len(needs_decision)} need a decision")
    for name, licence in needs_decision:
        print(f"  {name}: {licence}")
    return 1 if (args.strict and needs_decision) else 0


if __name__ == "__main__":
    raise SystemExit(main())
