"""Client-neutral DatasetBond v2.1 integration example.

This module constructs call-shaped payloads only. It does not sign, deploy, broadcast, or contact a
network. The signed manifest is supplied inline; sign its canonical bytes with an approved issuer
key before submitting the JSON string and digest.
"""

from __future__ import annotations

import hashlib
import json
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


if __name__ == "__main__":
    package = {
        "dataset_reference": "https://raw.githubusercontent.com/acme/datasets/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/data.csv",
        "license_reference": "https://raw.githubusercontent.com/spdx/license-list-data/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/licenses/MIT.txt",
        "provenance_reference": "https://raw.githubusercontent.com/acme/provenance/cccccccccccccccccccccccccccccccccccccccc/manifests/demo.json",
        "evidence_manifest": "<canonical signed evidence manifest JSON supplied inline>",
    }
    dataset_bytes = b"id,value\n1,example\n"
    license_bytes = b"MIT license bytes"
    provenance_bytes = b"<canonical provenance manifest bytes>"
    evidence_manifest = "<canonical signed evidence manifest JSON supplied inline>"
    calls = [
        register_issuer_key_call(
            "example-publisher",
            "example-key-2026-a",
            "<128 lowercase hex characters containing secp256k1 x||y>",
        ),
        registration_call(
            "demo-dataset-1",
            package["dataset_reference"],
            dataset_bytes,
            package["license_reference"],
            license_bytes,
            package["provenance_reference"],
            provenance_bytes,
            evidence_manifest,
            "manifest-2026-01",
            "example-publisher",
            "example-key-2026-a",
            "MODEL_TRAINING",
        ),
        certification_call("demo-dataset-1"),
    ]
    print(json.dumps(calls, indent=2))
