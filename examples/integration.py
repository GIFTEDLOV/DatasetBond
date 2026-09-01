"""Client-neutral DatasetBond v2.1 integration example.

The checked-in package is a self-owned DatasetBond demonstration. This module loads its exact
fixture bytes and builds call-shaped payloads; it does not sign, deploy, broadcast, or compute a
certification verdict. A production client should submit the inline manifest and digest exactly as
provided after the trust-root issuer key has been registered.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def registration_call(
    dataset_id: str,
    dataset_reference: str,
    dataset_bytes: bytes,
    license_reference: str,
    license_bytes: bytes,
    provenance_reference: str,
    provenance_bytes: bytes,
    evidence_manifest: str,
    nonce: str,
    publisher_identity: str,
    key_id: str,
    usage_profile: str,
) -> dict[str, Any]:
    """Build the exact v2.1 register_dataset call and bind hashes to exact bytes."""
    return {
        "method": "register_dataset",
        "args": [
            dataset_id,
            dataset_reference,
            sha256_hex(dataset_bytes),
            license_reference,
            sha256_hex(license_bytes),
            provenance_reference,
            sha256_hex(provenance_bytes),
            evidence_manifest,
            sha256_hex(evidence_manifest.encode("utf-8")),
            nonce,
            publisher_identity,
            key_id,
            usage_profile,
        ],
    }


def register_issuer_key_call(
    issuer_id: str, key_id: str, public_key_hex: str
) -> dict[str, Any]:
    return {
        "method": "register_issuer_key",
        "args": [issuer_id, key_id, public_key_hex, "SECP256K1_ECDSA_SHA256"],
    }


def rotate_issuer_key_call(
    issuer_id: str, old_key_id: str, new_key_id: str, new_public_key_hex: str
) -> dict[str, Any]:
    return {
        "method": "rotate_issuer_key",
        "args": [issuer_id, old_key_id, new_key_id, new_public_key_hex],
    }


def certification_call(dataset_id: str) -> dict[str, Any]:
    return {"method": "certify_dataset", "args": [dataset_id]}


def revocation_call(dataset_id: str, reason: str) -> dict[str, Any]:
    return {"method": "revoke_certificate", "args": [dataset_id, reason]}


def accept_certificate(certificate: dict[str, Any], expected_profile: str) -> bool:
    """Consumer-side gate; it does not calculate or override the contract verdict."""
    return (
        certificate.get("status") == "CERTIFIED"
        and certificate.get("verdict") == "CERTIFIED"
        and certificate.get("integrity_status") == "VERIFIED"
        and certificate.get("authentication_status") == "AUTHENTICATED"
        and certificate.get("license_status") == "COMPATIBLE"
        and certificate.get("provenance_status") == "COMPLETE"
        and certificate.get("usage_profile") == expected_profile
        and isinstance(certificate.get("certification_record"), str)
        and bool(certificate["certification_record"])
    )


def demonstration_calls() -> list[dict[str, Any]]:
    """Return calls for the published self-owned demonstration package."""
    package = json.loads(
        (Path(__file__).with_name("datasetbond-package.json")).read_text(encoding="utf-8")
    )
    fixture_dir = Path(__file__).with_name("public-fixture")
    dataset_bytes = (fixture_dir / "dataset.json").read_bytes()
    license_bytes = (fixture_dir / "LICENSE.txt").read_bytes()
    provenance_bytes = (fixture_dir / "provenance.json").read_bytes()
    return [
        register_issuer_key_call(
            package["publisher_identity"],
            package["key_id"],
            package["issuer_public_key"],
        ),
        registration_call(
            package["dataset_id"],
            package["dataset_reference"],
            dataset_bytes,
            package["license_reference"],
            license_bytes,
            package["provenance_reference"],
            provenance_bytes,
            package["evidence_manifest"],
            package["nonce"],
            package["publisher_identity"],
            package["key_id"],
            package["usage_profile"],
        ),
        certification_call(package["dataset_id"]),
        revocation_call(package["dataset_id"], "demonstration lifecycle complete"),
    ]


if __name__ == "__main__":
    print(json.dumps(demonstration_calls(), indent=2))
