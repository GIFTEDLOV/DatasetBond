"""Mutation gate for the generated DatasetBond compact artifact.

The readable contract remains covered by ``mutation_test.py``.  This companion
gate reuses the same critical checks and accepts only the quote/line formatting
that Python's deterministic AST unparser produces for the compact artifact.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "contracts" / "datasetbond_compact.py"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.mutation_test import MUTATIONS


COMPACT_ALTERNATIVES = {
    "https-only": ("if not reference.startswith('https://'):",),
    "model-output-shape": (
        "if not isinstance(raw, dict) or len(raw) != 1 or 'verdict' not in raw:",
    ),
    "model-verdict-enum": (
        "    verdict = raw['verdict']\n"
        "    if not isinstance(verdict, str) or verdict not in VERDICTS:",
    ),
}


def _anchors(mutation) -> tuple[str, ...]:
    return COMPACT_ALTERNATIVES.get(mutation.name, (mutation.anchor,))


def _find_anchor(source: str, mutation) -> str | None:
    return next((anchor for anchor in _anchors(mutation) if anchor in source), None)


def security_violations(source: str) -> list[str]:
    return sorted(mutation.name for mutation in MUTATIONS if _find_anchor(source, mutation) is None)


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    baseline = security_violations(source)
    if baseline:
        print("compact baseline security guard failure: " + ", ".join(baseline))
        return 1

    survivors: list[str] = []
    for mutation in MUTATIONS:
        anchor = _find_anchor(source, mutation)
        assert anchor is not None
        mutated = source.replace(anchor, "# removed critical guard", 1)
        if not security_violations(mutated):
            survivors.append(mutation.name)
    if survivors:
        print("compact mutation survivors: " + ", ".join(survivors))
        return 1

    print(f"compact mutation gate passed: {len(MUTATIONS)} critical guard mutations killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
