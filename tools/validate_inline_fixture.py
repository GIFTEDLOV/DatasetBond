"""Validate the published DatasetBond demonstration package.

This is a read-only fixture gate. It independently fetches the three commit-addressed public
evidence objects, checks their exact response bytes and SHA-256 digests, validates the linked
provenance shape, and verifies the inline low-s secp256k1 manifest with the published public key.
It never creates, prints, persists, or publishes private key material and never contacts a chain.
"""

from __future__ import annotations

import hashlib
import json
import re
import base64
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from eth_keys import keys


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_PATH = ROOT / "examples" / "datasetbond-package.json"
FIXTURE_DIR = ROOT / "examples" / "public-fixture"
MAX_MANIFEST_BYTES = 16_384
MAX_PROVENANCE_BYTES = 32_768
MAX_REFERENCE_CHARS = 512
MAX_TEXT_CHARS = 256
MAX_TRANSFORMATIONS = 32
MAX_SIGNATURE_LIFETIME = 31_622_400
SIGNATURE_ALGORITHM = "SECP256K1_ECDSA_SHA256"
MANIFEST_VERSION = 2
SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
RAW_COMMIT_REFERENCE = re.compile(
    r"^https://raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/.+$"
)
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
LOWER_HEX_128 = re.compile(r"^[0-9a-f]{128}$")
PLACEHOLDER_MARKERS = ("acme", "placeholder", "replace-with", "example.com", "<canonical")
MANIFEST_FIELDS = {
    "nonce",
    "manifest_version",
    "dataset_id",
    "dataset_reference",
    "dataset_sha256",
    "license_reference",
    "license_sha256",
    "provenance_reference",
    "provenance_sha256",
    "usage_profile",
    "publisher_identity",
    "key_id",
    "issued_at",
    "expires_at",
    "signature_algorithm",
    "signature",
}
PROVENANCE_FIELDS = {
    "dataset_reference",
    "dataset_sha256",
    "license_reference",
    "license_sha256",
    "publisher",
    "source",
    "version",
    "created_at",
    "transformations",
}
NODE_FETCH_SCRIPT = (
    'const response = await fetch(process.argv[1], '
    '{headers: {"User-Agent": "DatasetBond-fixture-validator"}}); '
    'const body = new Uint8Array(await response.arrayBuffer()); '
    'process.stdout.write(JSON.stringify({status: response.status, body: Buffer.from(body).toString("base64")}));'
)


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_json_object(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except Exception as exc:
        raise AssertionError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AssertionError(f"{label} must be a JSON object")
    return value


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def assert_no_placeholders(value: object, label: str) -> None:
    if isinstance(value, str):
        lowered = value.lower()
        for marker in PLACEHOLDER_MARKERS:
            if marker in lowered:
                raise AssertionError(f"{label} contains placeholder marker {marker!r}")
    elif isinstance(value, dict):
        for key, nested in value.items():
            assert_no_placeholders(nested, f"{label}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            assert_no_placeholders(nested, f"{label}[{index}]")


def fetch_exact(reference: str) -> tuple[int, bytes]:
    request = Request(reference, headers={"User-Agent": "DatasetBond-fixture-validator"})
    try:
        with urlopen(request, timeout=45) as response:
            status = getattr(response, "status", None)
            body = response.read()
    except HTTPError as exc:
        raise AssertionError(f"HTTP failure for {reference}: {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        node = shutil.which("node")
        if node is None:
            raise AssertionError(f"unavailable source for {reference}: {exc}") from exc
        try:
            result = subprocess.run(
                [node, "--input-type=module", "-e", NODE_FETCH_SCRIPT, reference],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or f"node exited with {result.returncode}")
            payload = json.loads(result.stdout)
            status = int(payload["status"])
            body = base64.b64decode(payload["body"], validate=True)
        except Exception as fallback_exc:
            raise AssertionError(
                f"unavailable source for {reference}: urllib={exc}; node-fetch={fallback_exc}"
            ) from fallback_exc
    if status != 200:
        raise AssertionError(f"HTTP status for {reference} was {status}, expected 200")
    return int(status), body


def validate_reference(reference: object, label: str) -> str:
    if not isinstance(reference, str) or not 1 <= len(reference) <= MAX_REFERENCE_CHARS:
        raise AssertionError(f"{label} has invalid length")
    if not RAW_COMMIT_REFERENCE.fullmatch(reference) or "?" in reference or "#" in reference:
        raise AssertionError(f"{label} is not an immutable commit-addressed raw GitHub URL")
    if any(character.isspace() for character in reference):
        raise AssertionError(f"{label} contains whitespace")
    return reference


def validate_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or LOWER_HEX_64.fullmatch(value) is None:
        raise AssertionError(f"{label} is not lowercase SHA-256 hex")
    return value


def validate_provenance(package: dict, provenance_bytes: bytes) -> None:
    if len(provenance_bytes) == 0 or len(provenance_bytes) > MAX_PROVENANCE_BYTES:
        raise AssertionError("provenance size is outside DatasetBond bounds")
    provenance = parse_json_object(provenance_bytes, "provenance")
    if set(provenance) != PROVENANCE_FIELDS:
        raise AssertionError("provenance fields do not match DatasetBond's required schema")
    if provenance["dataset_reference"] != package["dataset_reference"]:
        raise AssertionError("provenance dataset_reference is not linked to the package")
    if provenance["dataset_sha256"] != package["dataset_sha256"]:
        raise AssertionError("provenance dataset_sha256 is not linked to the package")
    if provenance["license_reference"] != package["license_reference"]:
        raise AssertionError("provenance license_reference is not linked to the package")
    if provenance["license_sha256"] != package["license_sha256"]:
        raise AssertionError("provenance license_sha256 is not linked to the package")
    if provenance["publisher"] != package["publisher_identity"]:
        raise AssertionError("provenance publisher is not the signed publisher identity")
    for field in ("publisher", "source", "version"):
        value = provenance[field]
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_TEXT_CHARS:
            raise AssertionError(f"provenance {field} is empty or oversized")
    created_at = provenance["created_at"]
    if not isinstance(created_at, str):
        raise AssertionError("provenance created_at is not a string")
    parsed = datetime.fromisoformat(created_at[:-1] + "+00:00" if created_at.endswith("Z") else created_at)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AssertionError("provenance created_at lacks a timezone")
    transformations = provenance["transformations"]
    if not isinstance(transformations, list) or not 1 <= len(transformations) <= MAX_TRANSFORMATIONS:
        raise AssertionError("provenance transformations must be a non-empty bounded list")
    for transformation in transformations:
        if not isinstance(transformation, str) or not 1 <= len(transformation) <= MAX_TEXT_CHARS:
            raise AssertionError("provenance transformation is empty or oversized")


def validate_manifest(package: dict) -> None:
    manifest_text = package["evidence_manifest"]
    if not isinstance(manifest_text, str):
        raise AssertionError("evidence_manifest must be a JSON string")
    manifest_bytes = manifest_text.encode("utf-8")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise AssertionError("inline manifest exceeds DatasetBond's size bound")
    manifest = parse_json_object(manifest_bytes, "inline manifest")
    if set(manifest) != MANIFEST_FIELDS:
        raise AssertionError("inline manifest has unknown or missing fields")
    if canonical_json(manifest) != manifest_bytes:
        raise AssertionError("inline manifest is not canonical sorted-key UTF-8 JSON")
    if sha256(manifest_bytes) != package["evidence_manifest_sha256"]:
        raise AssertionError("inline manifest digest mismatch")
    expected_fields = {
        "dataset_id": package["dataset_id"],
        "dataset_reference": package["dataset_reference"],
        "dataset_sha256": package["dataset_sha256"],
        "license_reference": package["license_reference"],
        "license_sha256": package["license_sha256"],
        "provenance_reference": package["provenance_reference"],
        "provenance_sha256": package["provenance_sha256"],
        "nonce": package["nonce"],
        "publisher_identity": package["publisher_identity"],
        "key_id": package["key_id"],
        "usage_profile": package["usage_profile"],
    }
    for field, expected in expected_fields.items():
        if manifest[field] != expected:
            raise AssertionError(f"inline manifest {field} does not match package")
    if manifest["manifest_version"] != MANIFEST_VERSION or manifest["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise AssertionError("inline manifest version or signature algorithm is unsupported")
    for field in ("nonce", "dataset_id", "publisher_identity", "key_id", "usage_profile"):
        value = manifest[field]
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_TEXT_CHARS:
            raise AssertionError(f"inline manifest {field} is empty or oversized")
    issued_at = manifest["issued_at"]
    expires_at = manifest["expires_at"]
    if (
        type(issued_at) is not int
        or type(expires_at) is not int
        or issued_at < 0
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_SIGNATURE_LIFETIME
    ):
        raise AssertionError("inline manifest validity window is invalid")
    now = int(datetime.now(timezone.utc).timestamp())
    if now < issued_at or now > expires_at:
        raise AssertionError("inline manifest is outside its validity window")
    public_key = package["issuer_public_key"]
    signature = manifest["signature"]
    if not isinstance(public_key, str) or LOWER_HEX_128.fullmatch(public_key) is None:
        raise AssertionError("issuer public key is not lowercase uncompressed secp256k1 x||y hex")
    if not isinstance(signature, str) or LOWER_HEX_128.fullmatch(signature) is None:
        raise AssertionError("manifest signature is not lowercase r||s hex")
    s = int(signature[64:], 16)
    if s <= 0 or s > SECP256K1_N // 2:
        raise AssertionError("manifest signature is not low-s")
    unsigned = dict(manifest)
    del unsigned["signature"]
    message_hash = hashlib.sha256(canonical_json(unsigned)).digest()
    try:
        # DatasetBond stores compact r||s (64 bytes), while eth_keys' recovery API requires v||r||s.
        # The verification API accepts the same r||s values with an ignored recovery marker.
        signature_object = keys.Signature(
            vrs=(0, int(signature[:64], 16), int(signature[64:], 16))
        )
        registered = keys.PublicKey(bytes.fromhex(public_key))
        verified = registered.verify_msg_hash(message_hash, signature_object)
    except Exception as exc:
        raise AssertionError(f"manifest signature/public key is malformed: {exc}") from exc
    if not verified:
        raise AssertionError("manifest signature does not verify against issuer public key")


def main() -> int:
    try:
        package = json.loads(PACKAGE_PATH.read_text(encoding="utf-8"))
        if not isinstance(package, dict):
            raise AssertionError("package must be a JSON object")
        assert_no_placeholders(package, "package")
        required_package_fields = {
            "dataset_id",
            "dataset_reference",
            "dataset_sha256",
            "license_reference",
            "license_sha256",
            "provenance_reference",
            "provenance_sha256",
            "evidence_manifest",
            "evidence_manifest_sha256",
            "nonce",
            "publisher_identity",
            "key_id",
            "usage_profile",
            "issuer_public_key",
            "signature_algorithm",
        }
        if set(package) != required_package_fields:
            raise AssertionError("package fields do not match the published fixture schema")
        references = {
            "dataset": validate_reference(package["dataset_reference"], "dataset_reference"),
            "license": validate_reference(package["license_reference"], "license_reference"),
            "provenance": validate_reference(package["provenance_reference"], "provenance_reference"),
        }
        digests = {
            "dataset": validate_digest(package["dataset_sha256"], "dataset_sha256"),
            "license": validate_digest(package["license_sha256"], "license_sha256"),
            "provenance": validate_digest(package["provenance_sha256"], "provenance_sha256"),
            "manifest": validate_digest(package["evidence_manifest_sha256"], "evidence_manifest_sha256"),
        }
        responses: dict[str, dict[str, object]] = {}
        bodies: dict[str, bytes] = {}
        for label, reference in references.items():
            status, body = fetch_exact(reference)
            expected = digests[label]
            actual = sha256(body)
            if actual != expected:
                raise AssertionError(f"{label} digest mismatch: expected {expected}, got {actual}")
            bodies[label] = body
            responses[label] = {"url": reference, "status": status, "bytes": len(body), "sha256": actual}
        dataset = parse_json_object(bodies["dataset"], "dataset")
        if dataset.get("dataset_id") != package["dataset_id"] or dataset.get("version") != "1.0.0":
            raise AssertionError("dataset identity/version does not match the demonstration package")
        if dataset.get("publisher") != "DatasetBond project" or len(dataset.get("records", [])) < 3:
            raise AssertionError("dataset is not the labeled self-owned demonstration dataset")
        if b"MIT License" not in bodies["license"]:
            raise AssertionError("license fixture is not the identified MIT license text")
        validate_provenance(package, bodies["provenance"])
        validate_manifest(package)
        print(
            json.dumps(
                {
                    "status": "PASS",
                    "package": str(PACKAGE_PATH.relative_to(ROOT)),
                    "underlying_evidence": responses,
                    "manifest_sha256": package["evidence_manifest_sha256"],
                    "publisher_identity": package["publisher_identity"],
                    "key_id": package["key_id"],
                    "signature_verified": True,
                    "trust_root_registration_required": True,
                    "private_key_output": False,
                    "network_or_chain_write": False,
                },
                indent=2,
            )
        )
        return 0
    except (AssertionError, OSError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
