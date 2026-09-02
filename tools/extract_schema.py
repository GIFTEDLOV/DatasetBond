"""Extract the declared public surface and compare it with both contract artifacts and schema.

The GenVM ABI extractor remains authoritative for deployment-time ABI details. This small AST
extractor is an offline, deterministic parity check for the source/schema contract surface.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contracts" / "datasetbond.py"
COMPACT = ROOT / "contracts" / "datasetbond_compact.py"
DECLARED = ROOT / "schema" / "datasetbond.schema.json"


def _public_methods(tree: ast.Module) -> dict[str, list[tuple[str, tuple[str, ...]]]]:
    methods: dict[str, list[tuple[str, tuple[str, ...]]]] = {"write": [], "view": []}
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
                methods[decorator.attr].append(
                    (node.name, tuple(argument.arg for argument in node.args.args if argument.arg != "self"))
                )
    for key in methods:
        methods[key].sort()
    return methods


def main() -> int:
    tree = ast.parse(CONTRACT.read_text(encoding="utf-8"))
    methods = _public_methods(tree)
    expected_writes = [
        ("certify_dataset", ("dataset_id",)),
        ("register_dataset", ("dataset_id", "dataset_reference", "dataset_sha256", "license_reference", "license_sha256", "provenance_reference", "provenance_sha256", "evidence_manifest", "evidence_manifest_sha256", "nonce", "publisher_identity", "key_id", "usage_profile")),
        ("register_issuer_key", ("issuer_id", "key_id", "public_key", "signature_algorithm")),
        ("revoke_certificate", ("dataset_id", "reason")),
        ("revoke_issuer_key", ("key_id", "reason")),
        ("rotate_issuer_key", ("issuer_id", "old_key_id", "new_key_id", "new_public_key")),
    ]
    expected_views = [
        ("get_certificate", ("dataset_id",)),
        ("get_certificate_count", ()),
        ("get_certificate_ids", ()),
        ("get_certificates", ()),
        ("get_issuer_key", ("key_id",)),
        ("get_issuer_key_count", ()),
        ("get_issuer_keys", ()),
        ("get_trust_root", ()),
    ]
    if methods["write"] != expected_writes or methods["view"] != expected_views:
        print(json.dumps({"actual": methods, "expected": {"write": expected_writes, "view": expected_views}}))
        return 1
    compact_methods = _public_methods(ast.parse(COMPACT.read_text(encoding="utf-8")))
    if compact_methods != methods:
        print(json.dumps({"readable": methods, "compact": compact_methods}))
        return 1
    declared = json.loads(DECLARED.read_text(encoding="utf-8"))
    declared_writes = sorted(
        (item["method"], tuple(argument["name"] for argument in item.get("arguments", [])))
        for item in (
            declared["registration"],
            declared["issuer_registration"],
            declared["issuer_revocation"],
            declared["issuer_rotation"],
            declared["certification"],
            declared["revocation"],
        )
    )
    declared_views = sorted((item["method"], tuple(item.get("arguments", []))) for item in declared["views"])
    if declared_writes != expected_writes or declared_views != expected_views:
        print("checked-in schema does not match expected public surface")
        return 1
    print(
        json.dumps(
            {
                "contract": "DatasetBond",
                "schema_version": declared["schema_version"],
                "write": methods["write"],
                "view": methods["view"],
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
