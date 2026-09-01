"""Client-neutral DatasetBond integration example.

This module constructs call-shaped payloads only. It does not sign, deploy, broadcast, or contact a
network. Pass the method names and argument arrays to the supported GenLayer client for the chosen
environment.
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
    usage_profile: str,
) -> dict[str, Any]:
    """Build the exact register_dataset method call and bind hashes to exact bytes."""
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
            usage_profile,
        ],
    }


def certification_call(dataset_id: str) -> dict[str, Any]:
    return {"method": "certify_dataset", "args": [dataset_id]}


def revocation_call(dataset_id: str, reason: str) -> dict[str, Any]:
    return {"method": "revoke_certificate", "args": [dataset_id, reason]}


def accept_certificate(certificate: dict[str, Any], expected_profile: str) -> bool:
    """Consumer-side gate: accept only a live certificate for the exact requested profile."""
    return (
        certificate.get("status") == "CERTIFIED"
        and certificate.get("verdict") == "CERTIFIED"
        and certificate.get("usage_profile") == expected_profile
        and isinstance(certificate.get("certification_record"), str)
        and bool(certificate["certification_record"])
    )


if __name__ == "__main__":
    package = {
        "dataset_reference": "https://raw.githubusercontent.com/acme/datasets/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/data.csv",
        "license_reference": "https://raw.githubusercontent.com/spdx/license-list-data/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/licenses/MIT.json",
        "provenance_reference": "https://raw.githubusercontent.com/acme/provenance/cccccccccccccccccccccccccccccccccccccccc/manifests/demo.json",
    }
    dataset_bytes = b"id,value\n1,example\n"
    license_bytes = b"MIT license bytes"
    provenance_bytes = json.dumps(
        {
            "dataset_reference": package["dataset_reference"],
            "dataset_sha256": sha256_hex(dataset_bytes),
            "license_reference": package["license_reference"],
            "license_sha256": sha256_hex(license_bytes),
            "publisher": "Example Publisher",
            "source": "Example source",
            "version": "2026.01",
            "created_at": "2026-01-01T00:00:00Z",
            "transformations": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    calls = [
        registration_call(
            "demo-dataset-1",
            package["dataset_reference"],
            dataset_bytes,
            package["license_reference"],
            license_bytes,
            package["provenance_reference"],
            provenance_bytes,
            "MODEL_TRAINING",
        ),
        certification_call("demo-dataset-1"),
    ]
    print(json.dumps(calls, indent=2))
