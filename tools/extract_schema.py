"""Extract the declared public surface and compare it with the checked-in schema.

The GenVM ABI extractor remains authoritative for deployment-time ABI details. This small AST
extractor is an offline, deterministic parity check for the source/schema contract surface.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contracts" / "datasetbond.py"
DECLARED = ROOT / "schema" / "datasetbond.schema.json"


def _public_methods(tree: ast.Module) -> dict[str, list[str]]:
    methods: dict[str, list[str]] = {"write": [], "view": []}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Attribute) or not isinstance(decorator.value, ast.Attribute):
                continue
            if not isinstance(decorator.value.value, ast.Name) or decorator.value.value.id != "gl":
                continue
            if decorator.value.attr != "public":
                continue
            if decorator.attr in methods:
                methods[decorator.attr].append(node.name)
    for key in methods:
        methods[key].sort()
    return methods


def main() -> int:
    tree = ast.parse(CONTRACT.read_text(encoding="utf-8"))
    methods = _public_methods(tree)
    expected_writes = ["certify_dataset", "register_dataset", "revoke_certificate"]
    expected_views = [
        "get_certificate",
        "get_certificate_count",
        "get_certificate_ids",
        "get_certificates",
    ]
    if methods["write"] != expected_writes or methods["view"] != expected_views:
        print(json.dumps({"actual": methods, "expected": {"write": expected_writes, "view": expected_views}}))
        return 1
    declared = json.loads(DECLARED.read_text(encoding="utf-8"))
    declared_writes = sorted(item["method"] for item in (declared["registration"], declared["certification"], declared["revocation"]))
    declared_views = sorted(item["method"] for item in declared["views"])
    if declared_writes != expected_writes or declared_views != expected_views:
        print("checked-in schema does not match expected public surface")
        return 1
    print(json.dumps({"contract": "DatasetBond", "schema_version": declared["schema_version"], "write": methods["write"], "view": methods["view"]}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
