"""Verify raw-byte hashes for the release-critical DatasetBond surface.

The manifest deliberately excludes itself and narrative-only documentation. It covers the readable
contract, the exact compact artifact deployed to Bradbury, the checked-in schema, the integration
payload builder, the published fixture, and the release metadata that binds those facts together.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "MANIFEST.sha256"
HASHED_PATHS = (
    "contracts/datasetbond.py",
    "contracts/datasetbond_compact.py",
    "schema/datasetbond.schema.json",
    "examples/datasetbond-package.json",
    "examples/integration.py",
    "examples/public-fixture/LICENSE.txt",
    "examples/public-fixture/dataset.json",
    "examples/public-fixture/provenance.json",
    "release/datasetbond-bradbury.json",
    "tools/minify_contract.py",
    "tools/release_audit.py",
)

HEADER = (
    "# DatasetBond release reproducibility manifest\n"
    "# sha256 over raw bytes. Regenerate with: python tools/source_hash.py --write\n"
    "# Verified in CI by: python tools/source_hash.py --check\n"
)


def collect() -> dict[str, str]:
    return {
        relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in HASHED_PATHS
    }


def read_manifest() -> dict[str, str]:
    if not MANIFEST.exists():
        return {}
    entries: dict[str, str] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, separator, relative = line.partition("  ")
        if separator:
            entries[relative] = digest
    return entries


def write_manifest() -> int:
    actual = collect()
    body = "".join(f"{digest}  {relative}\n" for relative, digest in sorted(actual.items()))
    MANIFEST.write_text(HEADER + body, encoding="utf-8", newline="\n")
    print(f"wrote {MANIFEST.name} -- {len(actual)} file(s)")
    return 0


def check_manifest() -> int:
    actual = collect()
    recorded = read_manifest()
    if not recorded:
        print("FAIL -- MANIFEST.sha256 missing or empty", file=sys.stderr)
        return 1

    problems: list[str] = []
    for relative in sorted(set(actual) | set(recorded)):
        if relative not in actual:
            problems.append(f"manifest contains unexpected path: {relative}")
        elif relative not in recorded:
            problems.append(f"path is not recorded: {relative}")
        elif actual[relative] != recorded[relative]:
            problems.append(
                f"hash drift: {relative} (recorded {recorded[relative]}, actual {actual[relative]})"
            )
    if problems:
        print("FAIL -- reproducibility manifest drift", file=sys.stderr)
        print("\n".join(f"- {problem}" for problem in problems), file=sys.stderr)
        return 1
    print(f"source hash check passed -- {len(actual)} file(s)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--write", action="store_true")
    args = parser.parse_args()
    return write_manifest() if args.write else check_manifest()


if __name__ == "__main__":
    raise SystemExit(main())
