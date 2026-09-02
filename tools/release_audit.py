"""Offline release audit for DatasetBond source, artifact, schema, fixture, and proof parity."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "contracts/datasetbond.py"
COMPACT = ROOT / "contracts/datasetbond_compact.py"
SCHEMA = ROOT / "schema/datasetbond.schema.json"
PACKAGE = ROOT / "examples/datasetbond-package.json"
FIXTURE = ROOT / "examples/public-fixture"
PROOF = ROOT / "docs/BRADBURY-PROOF.md"
RELEASE = ROOT / "release/datasetbond-bradbury.json"

WRITE_SECTIONS = (
    "registration",
    "issuer_registration",
    "issuer_revocation",
    "issuer_rotation",
    "certification",
    "revocation",
)
HEX64 = re.compile(r"^0x[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_surface(path: Path) -> dict[str, tuple[str, tuple[str, ...]]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    surface: dict[str, tuple[str, tuple[str, ...]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        kind = None
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Attribute)
                and isinstance(decorator.value, ast.Attribute)
                and isinstance(decorator.value.value, ast.Name)
                and decorator.value.value.id == "gl"
                and decorator.value.attr == "public"
                and decorator.attr in {"read", "view", "write"}
            ):
                kind = "view" if decorator.attr in {"read", "view"} else "write"
        if kind is not None:
            args = tuple(arg.arg for arg in node.args.args if arg.arg != "self")
            surface[node.name] = (kind, args)
    return dict(sorted(surface.items()))


def schema_surface(schema: dict[str, Any]) -> dict[str, tuple[str, tuple[str, ...]]]:
    surface: dict[str, tuple[str, tuple[str, ...]]] = {}
    for section in WRITE_SECTIONS:
        item = schema[section]
        surface[item["method"]] = (
            "write",
            tuple(argument["name"] for argument in item.get("arguments", [])),
        )
    for item in schema["views"]:
        surface[item["method"]] = ("view", tuple(item.get("arguments", [])))
    return dict(sorted(surface.items()))


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def audit() -> list[str]:
    failures: list[str] = []
    source_bytes = SOURCE.read_bytes()
    compact_bytes = COMPACT.read_bytes()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    package = json.loads(PACKAGE.read_text(encoding="utf-8"))
    release = json.loads(RELEASE.read_text(encoding="utf-8"))

    require(schema.get("contract") == "DatasetBond", "schema contract is not DatasetBond", failures)
    require(schema.get("schema_version") == 2.1, "schema version is not 2.1", failures)
    source_surface = public_surface(SOURCE)
    compact_surface = public_surface(COMPACT)
    declared_surface = schema_surface(schema)
    require(source_surface == compact_surface, "readable and compact public surfaces differ", failures)
    require(source_surface == declared_surface, "contract public surface differs from checked-in schema", failures)
    require(len(source_surface) == 14, f"expected 14 public methods, found {len(source_surface)}", failures)

    require(source_bytes.startswith(b'# { "Depends":'), "readable contract is missing the GenVM pin", failures)
    require(compact_bytes.startswith(b'# { "Depends":'), "compact contract is missing the GenVM pin", failures)
    require(source_bytes.splitlines()[0] == compact_bytes.splitlines()[0], "GenVM pin differs between artifacts", failures)

    # Importing the generator is safe: it has no contract/runtime side effects.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tools.minify_contract import compact_source

    regenerated = compact_source(source_bytes.decode("utf-8")).encode("utf-8")
    require(regenerated == compact_bytes, "compact artifact is stale or not reproducibly generated", failures)

    contract_meta = release.get("contract", {})
    network = release.get("network", {})
    require(release.get("release") == "DatasetBond v2.1 Bradbury proof", "release identity mismatch", failures)
    require(release.get("track") == "Intelligent Contract", "release track mismatch", failures)
    require(network.get("name") == "GenLayer Bradbury", "release network mismatch", failures)
    require(network.get("chain_id") == 4221, "release chain ID mismatch", failures)
    require(network.get("rpc") == "https://rpc-bradbury.genlayer.com", "release RPC mismatch", failures)
    require(ADDRESS.fullmatch(contract_meta.get("address", "")) is not None, "invalid deployed contract address", failures)
    require(contract_meta.get("audited_source") == "contracts/datasetbond.py", "audited source path mismatch", failures)
    require(sha256(source_bytes) == contract_meta.get("audited_source_sha256"), "audited source hash mismatch", failures)
    require(sha256(compact_bytes) == contract_meta.get("deployed_artifact_sha256"), "deployed artifact hash mismatch", failures)
    require(len(compact_bytes) == contract_meta.get("deployed_artifact_bytes"), "deployed artifact byte length mismatch", failures)
    require(contract_meta.get("deployed_artifact") == "contracts/datasetbond_compact.py", "release artifact path mismatch", failures)
    require(contract_meta.get("schema") == "schema/datasetbond.schema.json", "release schema path mismatch", failures)
    require(contract_meta.get("schema_version") == schema.get("schema_version"), "release/schema version mismatch", failures)

    manifest_text = package.get("evidence_manifest")
    require(isinstance(manifest_text, str) and manifest_text.startswith("{"), "inline manifest is not raw object JSON", failures)
    if isinstance(manifest_text, str):
        try:
            manifest = json.loads(manifest_text)
            canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            require(isinstance(manifest, dict), "inline manifest is not an object", failures)
            require(canonical == manifest_text, "inline manifest is not canonical JSON", failures)
            require(sha256(manifest_text.encode("utf-8")) == package.get("evidence_manifest_sha256"), "inline manifest digest mismatch", failures)
            if isinstance(manifest, dict):
                for field in (
                    "dataset_id", "dataset_reference", "dataset_sha256", "license_reference", "license_sha256",
                    "provenance_reference", "provenance_sha256", "nonce", "publisher_identity", "key_id", "usage_profile",
                ):
                    require(manifest.get(field) == package.get(field), f"manifest/package mismatch: {field}", failures)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            failures.append(f"inline manifest cannot be parsed: {exc}")

    for field, filename in (
        ("dataset_sha256", "dataset.json"),
        ("license_sha256", "LICENSE.txt"),
        ("provenance_sha256", "provenance.json"),
    ):
        raw = (FIXTURE / filename).read_bytes()
        require(SHA256.fullmatch(package.get(field, "")) is not None, f"package {field} is not lowercase SHA-256", failures)
        require(sha256(raw) == package.get(field), f"fixture digest mismatch: {filename}", failures)

    provenance = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))
    for field in ("dataset_reference", "dataset_sha256", "license_reference", "license_sha256"):
        require(provenance.get(field) == package.get(field), f"provenance/package mismatch: {field}", failures)
    require(provenance.get("publisher") == package.get("publisher_identity"), "provenance publisher mismatch", failures)
    require(isinstance(provenance.get("transformations"), list) and bool(provenance["transformations"]), "provenance transformations are empty", failures)

    release_certificate = release.get("certificate", {})
    require(release_certificate.get("id") == package.get("dataset_id"), "release certificate/package ID mismatch", failures)
    for field in ("evidence_manifest_sha256", "dataset_sha256", "license_sha256", "provenance_sha256"):
        require(release_certificate.get(field) == package.get(field), f"release certificate/package mismatch: {field}", failures)
    require(release_certificate.get("status") == "CERTIFIED", "release certificate status mismatch", failures)
    require(release_certificate.get("verdict") == "CERTIFIED", "release certificate verdict mismatch", failures)

    transactions = release.get("transactions", {})
    for name, record in transactions.items():
        require(HEX64.fullmatch(record.get("hash", "")) is not None, f"invalid transaction hash: {name}", failures)
        require(record.get("status") == "FINALIZED", f"transaction is not FINALIZED: {name}", failures)
        require(record.get("consensus") == "AGREE", f"transaction consensus is not AGREE: {name}", failures)
        require(record.get("execution") == "FINISHED_WITH_RETURN", f"transaction execution is not successful: {name}", failures)
    certification = transactions.get("certification", {})
    require(HEX64.fullmatch(certification.get("execution_hash", "")) is not None, "invalid certification execution hash", failures)
    proof_text = PROOF.read_text(encoding="utf-8")
    for value in (
        contract_meta.get("address"), contract_meta.get("deployed_artifact_sha256"),
        transactions["deployment"]["hash"], transactions["issuer_registration"]["hash"],
        transactions["dataset_registration"]["hash"], transactions["certification"]["hash"],
        release["certificate"]["id"], release["certificate"]["evidence_manifest_sha256"],
    ):
        require(str(value) in proof_text, f"Bradbury proof is missing release value: {value}", failures)
    return failures


def main() -> int:
    failures = audit()
    if failures:
        print("release audit failed", file=sys.stderr)
        print("\n".join(f"- {failure}" for failure in failures), file=sys.stderr)
        return 1
    print("release audit passed: source/artifact/schema/fixture/proof parity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
