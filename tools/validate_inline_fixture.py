"""Validate one complete positive DatasetBond v2.1 package without publication or network I/O.

This is a package-assembly gate, not a deployment or certification test. It creates a test-only
issuer key in memory, constructs local dataset/license/provenance bytes, signs the canonical inline
manifest, and checks the exact registration payload shape and digests. It deliberately does not
print or persist key material and does not publish or fetch any evidence.
"""

from __future__ import annotations

import hashlib
import json
import re

from eth_keys import keys


REFERENCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"
DATASET_REFERENCE = f"https://raw.githubusercontent.com/example/datasets/{REFERENCE_COMMIT}/demo.csv"
LICENSE_REFERENCE = f"https://raw.githubusercontent.com/example/licenses/{REFERENCE_COMMIT}/LICENSE"
PROVENANCE_REFERENCE = f"https://raw.githubusercontent.com/example/provenance/{REFERENCE_COMMIT}/manifest.json"
PROFILE = "COMMERCIAL_TRAINING"
ISSUER_ID = "example-publisher"
KEY_ID = "example-key-2026-a"
NONCE = "inline-fixture-2026-01"
SIGNATURE_ALGORITHM = "SECP256K1_ECDSA_SHA256"
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


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    dataset_id = "inline-fixture-dataset"
    dataset_bytes = b"id,value\n1,example\n"
    license_bytes = (
        b"SPDX-License-Identifier: MIT\n"
        b"Commercial use and machine-learning training are permitted.\n"
    )
    provenance_bytes = canonical_json(
        {
            "created_at": "2026-01-01T00:00:00Z",
            "dataset_reference": DATASET_REFERENCE,
            "dataset_sha256": sha256(dataset_bytes),
            "license_reference": LICENSE_REFERENCE,
            "license_sha256": sha256(license_bytes),
            "publisher": ISSUER_ID,
            "source": "local fixture assembly",
            "transformations": ["UTF-8 CSV export"],
            "version": "2026.01",
        }
    )

    manifest_without_signature = {
        "nonce": NONCE,
        "manifest_version": 2,
        "dataset_id": dataset_id,
        "dataset_reference": DATASET_REFERENCE,
        "dataset_sha256": sha256(dataset_bytes),
        "license_reference": LICENSE_REFERENCE,
        "license_sha256": sha256(license_bytes),
        "provenance_reference": PROVENANCE_REFERENCE,
        "provenance_sha256": sha256(provenance_bytes),
        "usage_profile": PROFILE,
        "publisher_identity": ISSUER_ID,
        "key_id": KEY_ID,
        "issued_at": 1790000000,
        "expires_at": 1790003600,
        "signature_algorithm": SIGNATURE_ALGORITHM,
    }
    # Test-only key material exists only in memory and is never emitted or written.
    signer = keys.PrivateKey(hashlib.sha256(b"DatasetBond v2.1 inline fixture test key").digest())
    signature = signer.sign_msg_hash(hashlib.sha256(canonical_json(manifest_without_signature)).digest())
    manifest = dict(manifest_without_signature)
    manifest["signature"] = f"{signature.r:064x}{signature.s:064x}"
    manifest_bytes = canonical_json(manifest)

    assert len(manifest_bytes) <= 16_384
    assert set(manifest) == MANIFEST_FIELDS
    assert canonical_json(json.loads(manifest_bytes)) == manifest_bytes
    assert re.fullmatch(r"[0-9a-f]{64}", sha256(manifest_bytes))
    assert re.fullmatch(r"[0-9a-f]{128}", manifest["signature"])
    recovered = keys.Signature(signature.to_bytes()).recover_public_key_from_msg_hash(
        hashlib.sha256(canonical_json(manifest_without_signature)).digest()
    )
    assert recovered == signer.public_key

    registration_args = [
        dataset_id,
        DATASET_REFERENCE,
        sha256(dataset_bytes),
        LICENSE_REFERENCE,
        sha256(license_bytes),
        PROVENANCE_REFERENCE,
        sha256(provenance_bytes),
        manifest_bytes.decode("utf-8"),
        sha256(manifest_bytes),
        NONCE,
        ISSUER_ID,
        KEY_ID,
        PROFILE,
    ]
    assert len(registration_args) == 13
    assert registration_args[7] == manifest_bytes.decode("utf-8")
    assert registration_args[8] == sha256(registration_args[7].encode("utf-8"))
    assert all("?" not in reference and "#" not in reference for reference in registration_args[1:7:2])
    assert all(re.fullmatch(r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/.+", reference) for reference in registration_args[1:7:2])

    print(
        json.dumps(
            {
                "status": "PASS",
                "dataset_id": dataset_id,
                "manifest_sha256": sha256(manifest_bytes),
                "underlying_evidence": "locally assembled; not fetched",
                "external_publication_required": False,
                "private_key_output": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
