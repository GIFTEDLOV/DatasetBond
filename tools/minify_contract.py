"""Deterministically build DatasetBond's compact deployment source.

The readable contract remains the source of truth. This generator removes comments (except the
GenVM dependency header), docstrings, blank-line noise, and one provably equivalent duplicate
dataset-id validation block. It does not remove security checks, public methods, schema-bearing
annotations, cryptographic code, or consensus behavior.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "contracts" / "datasetbond.py"
DEFAULT_OUTPUT = ROOT / "contracts" / "datasetbond_compact.py"
DEPENDS_PREFIX = '# { "Depends":'


def _remove_docstrings(tree: ast.Module) -> ast.Module:
    """Remove module/class/function docstrings while preserving executable AST nodes."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not body or not isinstance(body, list):
            continue
        first = body[0]
        if not isinstance(first, ast.Expr):
            continue
        value = first.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            body.pop(0)
    return tree


def _deduplicate_safe_validation(source: str) -> str:
    """Use the already centralised identifier validator for dataset IDs.

    Both old and new paths enforce the same text bound and the same anchored identifier regex.
    Keeping the shared helper as the only implementation changes no accepted input or failure
    condition; this exact replacement is guarded so a source-layout drift cannot silently produce a
    different artifact.
    """
    old = (
        'def _validate_dataset_id(value: str) -> str:\n'
        '    dataset_id = _require_text("dataset_id", value, MAX_ID_LEN)\n'
        '    if _DATASET_ID_RE.match(dataset_id) is None:\n'
        '        _fail(\n'
        '            ERROR_EXPECTED,\n'
        '            "dataset_id must match ^[a-z][a-z0-9._:-]{0,95}$",\n'
        '        )\n'
        '    return dataset_id\n'
    )
    new = 'def _validate_dataset_id(value: str) -> str:\n    return _validate_identifier("dataset_id", value)\n'
    if source.count(old) != 1:
        raise ValueError("expected exactly one dataset-id validation block")
    return source.replace(old, new, 1)


def _strip_non_authoritative_source(source: str) -> str:
    header = source.splitlines()[0]
    tree = _remove_docstrings(ast.parse(source))
    return header + "\n" + ast.unparse(tree).rstrip() + "\n"


def compact_source(source: str) -> str:
    if not source.startswith(DEPENDS_PREFIX):
        raise ValueError("source is missing the required GenVM dependency header")
    transformed = _deduplicate_safe_validation(source)
    compact = _strip_non_authoritative_source(transformed)
    ast.parse(compact)
    return compact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    source_path = args.source if args.source.is_absolute() else ROOT / args.source
    output_path = args.output if args.output.is_absolute() else ROOT / args.output
    source = source_path.read_text(encoding="utf-8")
    compact = compact_source(source)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(compact, encoding="utf-8", newline="\n")
    original_bytes = len(source.encode("utf-8"))
    compact_bytes = len(compact.encode("utf-8"))
    saved = original_bytes - compact_bytes
    print(
        {
            "source": str(source_path.relative_to(ROOT)),
            "output": str(output_path.relative_to(ROOT)),
            "original_utf8_bytes": original_bytes,
            "compact_utf8_bytes": compact_bytes,
            "bytes_saved": saved,
            "percent_saved": round(saved * 100 / original_bytes, 2),
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
