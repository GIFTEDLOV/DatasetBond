"""Direct and consensus-shaped DatasetBond tests."""

from __future__ import annotations

import hashlib
import json
import re

import pytest


DATASET_REFERENCE = (
    "https://raw.githubusercontent.com/acme/datasets/"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/data.csv"
)
LICENSE_REFERENCE = (
    "https://raw.githubusercontent.com/spdx/license-list-data/"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/licenses/MIT.txt"
)
PROVENANCE_REFERENCE = (
    "https://raw.githubusercontent.com/acme/provenance/"
    "cccccccccccccccccccccccccccccccccccccccc/manifests/demo.json"
)

DATASET_BYTES = b"id,value\n1,example\n"
LICENSE_BYTES = (
    b"SPDX-License-Identifier: MIT\n"
    b"Permission is hereby granted to use, copy, modify, publish, distribute, and sell.\n"
    b"Commercial machine-learning training use is permitted.\n"
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def manifest_bytes(
    dataset_reference: str = DATASET_REFERENCE,
    dataset_sha256: str = sha256(DATASET_BYTES),
    license_reference: str = LICENSE_REFERENCE,
    license_sha256: str = sha256(LICENSE_BYTES),
    **overrides,
) -> bytes:
    payload = {
        "dataset_reference": dataset_reference,
        "dataset_sha256": dataset_sha256,
        "license_reference": license_reference,
        "license_sha256": license_sha256,
        "publisher": "Example Publisher",
        "source": "Example catalog export",
        "version": "2026.01",
        "created_at": "2026-01-01T00:00:00Z",
        "transformations": ["UTF-8 CSV export"],
    }
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def package(
    dataset_reference: str = DATASET_REFERENCE,
    dataset_sha256: str = sha256(DATASET_BYTES),
    license_reference: str = LICENSE_REFERENCE,
    license_sha256: str = sha256(LICENSE_BYTES),
    provenance_reference: str = PROVENANCE_REFERENCE,
    provenance_sha256: str | None = None,
    usage_profile: str = "COMMERCIAL_TRAINING",
    provenance_body: bytes | None = None,
) -> dict:
    body = provenance_body if provenance_body is not None else manifest_bytes(
        dataset_reference, dataset_sha256, license_reference, license_sha256
    )
    return {
        "dataset_id": "demo-dataset-1",
        "dataset_reference": dataset_reference,
        "dataset_sha256": dataset_sha256,
        "license_reference": license_reference,
        "license_sha256": license_sha256,
        "provenance_reference": provenance_reference,
        "provenance_sha256": provenance_sha256 or sha256(body),
        "usage_profile": usage_profile,
    }


def deploy(direct_deploy):
    return direct_deploy("contracts/datasetbond.py")


def register(direct_vm, contract, direct_alice, pkg=None):
    direct_vm.sender = direct_alice
    values = pkg or package()
    return contract.register_dataset(**values)


def mock_package(
    direct_vm,
    pkg: dict,
    dataset_body: bytes = DATASET_BYTES,
    license_body: bytes = LICENSE_BYTES,
    provenance_body: bytes | None = None,
    status: int = 200,
    model_response: dict | str | None = None,
) -> None:
    direct_vm.clear_mocks()
    body = provenance_body if provenance_body is not None else manifest_bytes(
        pkg["dataset_reference"],
        pkg["dataset_sha256"],
        pkg["license_reference"],
        pkg["license_sha256"],
    )
    for reference, response_body in (
        (pkg["dataset_reference"], dataset_body),
        (pkg["license_reference"], license_body),
        (pkg["provenance_reference"], body),
    ):
        direct_vm.mock_web(re.escape(reference) + "$", {"status": status, "body": response_body})
    if model_response is not None:
        direct_vm.mock_llm(r"DatasetBond certification arbiter", json.dumps(model_response) if isinstance(model_response, dict) else model_response)


def test_register_schema_duplicate_and_views(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_deploy)
    pkg = package()
    assert register(direct_vm, contract, direct_alice, pkg) == "demo-dataset-1"
    cert = contract.get_certificate("demo-dataset-1")
    assert cert["certificate_id"] == "demo-dataset-1"
    assert cert["status"] == "REGISTERED"
    assert cert["verdict"] == ""
    assert cert["submitter"].lower() == ("0x" + bytes(direct_alice).hex()).lower()
    assert cert["dataset_sha256"] == sha256(DATASET_BYTES)
    assert cert["license_sha256"] == sha256(LICENSE_BYTES)
    assert cert["provenance_sha256"] == pkg["provenance_sha256"]
    assert contract.get_certificate_ids() == ["demo-dataset-1"]
    assert contract.get_certificate_count() == 1
    assert list(contract.get_certificates()) == ["demo-dataset-1"]
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("DUPLICATE_DATASET_ID"):
        contract.register_dataset(**pkg)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("dataset_reference", "https://raw.githubusercontent.com/acme/datasets/main/data.csv", "immutable"),
        ("dataset_reference", "http://raw.githubusercontent.com/acme/datasets/main/data.csv", "https://"),
        ("license_reference", "ipfs://bafybeigdyrzt5example", "https://"),
        ("dataset_sha256", "A" * 64, "lowercase"),
        ("usage_profile", "GENERIC_DATASET_SCORE", "usage_profile"),
    ],
)
def test_registration_rejects_mutable_scheme_and_malformed_profile(
    direct_vm, direct_deploy, direct_alice, field, value, error
):
    contract = deploy(direct_deploy)
    pkg = package()
    pkg[field] = value
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert(error):
        contract.register_dataset(**pkg)
    assert contract.get_certificate_count() == 0


def test_valid_certified_package_stores_only_bounded_verdict(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    result = contract.certify_dataset(pkg["dataset_id"])
    assert result["status"] == "CERTIFIED"
    cert = contract.get_certificate(pkg["dataset_id"])
    assert cert["verdict"] == "CERTIFIED"
    assert cert["attempts"] == 1
    assert cert["evaluated_at"] > 0
    assert cert["certification_record"].startswith("{")
    assert "explanation" not in cert
    assert "confidence" not in cert["certification_record"]


def test_verified_license_incompatibility_is_not_certified(direct_vm, direct_deploy, direct_alice):
    incompatible_license = (
        b"SPDX-License-Identifier: CC-BY-NC-4.0\n"
        b"Commercial use and commercial machine-learning training are not permitted.\n"
    )
    pkg = package(license_sha256=sha256(incompatible_license))
    contract = deploy(direct_deploy)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, license_body=incompatible_license, model_response={"verdict": "NOT_CERTIFIED"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "NOT_CERTIFIED"
    assert cert["verdict"] == "NOT_CERTIFIED"


@pytest.mark.parametrize("failure_status", [404, 503])
def test_missing_evidence_and_http_failure_are_inconclusive(direct_vm, direct_deploy, direct_alice, failure_status):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, status=failure_status, model_response=None)
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "INCONCLUSIVE"
    assert cert["verdict"] == "INCONCLUSIVE"
    assert cert["attempts"] == 1
    assert cert["certification_record"]


def test_malformed_json_manifest_fails_closed(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    malformed_manifest = b"not-json"
    pkg = package(provenance_sha256=sha256(malformed_manifest), provenance_body=malformed_manifest)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, provenance_body=malformed_manifest)
    assert contract.certify_dataset(pkg["dataset_id"])["status"] == "INCONCLUSIVE"

def test_dataset_digest_mismatch_fails_closed(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, dataset_body=b"tampered", model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(pkg["dataset_id"])["status"] == "INCONCLUSIVE"

def test_contradictory_manifest_fails_closed(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    contradictory = manifest_bytes(dataset_sha256="f" * 64)
    pkg = package(provenance_sha256=sha256(contradictory), provenance_body=contradictory)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, provenance_body=contradictory, model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(pkg["dataset_id"])["status"] == "INCONCLUSIVE"


def test_oversized_dataset_is_inconclusive(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, dataset_body=b"x" * (1_048_576 + 1), model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(pkg["dataset_id"])["status"] == "INCONCLUSIVE"


def test_retry_after_inconclusive_then_certify(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, status=503)
    assert contract.certify_dataset(pkg["dataset_id"])["status"] == "INCONCLUSIVE"
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "CERTIFIED"
    assert cert["attempts"] == 2


def test_malformed_semantic_output_is_inconclusive_and_has_no_extra_state(
    direct_vm, direct_deploy, direct_alice
):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED", "explanation": "trust me"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "INCONCLUSIVE"
    assert cert["verdict"] == "INCONCLUSIVE"
    assert "trust me" not in cert["certification_record"]


def test_consensus_validator_repeats_complete_evaluation(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    contract.certify_dataset(pkg["dataset_id"])

    mock_package(direct_vm, pkg, model_response={"verdict": "NOT_CERTIFIED"})
    assert direct_vm.run_validator() is False


def test_duplicate_certification_and_replay_protection(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "NOT_CERTIFIED"})
    contract.certify_dataset(pkg["dataset_id"])
    with direct_vm.expect_revert("DUPLICATE_CERTIFICATION"):
        contract.certify_dataset(pkg["dataset_id"])


def test_unauthorized_and_controlled_revocation_preserve_history(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = deploy(direct_deploy)
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    contract.certify_dataset(pkg["dataset_id"])
    before = contract.get_certificate(pkg["dataset_id"])
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("ONLY_SUBMITTER"):
        contract.revoke_certificate(pkg["dataset_id"], "not authorized")
    assert contract.get_certificate(pkg["dataset_id"]) == before

    with direct_vm.prank(direct_alice):
        after = contract.revoke_certificate(pkg["dataset_id"], "publisher withdrew this certificate")
    assert after["status"] == "REVOKED"
    assert after["verdict"] == "CERTIFIED"
    assert after["certification_record"] == before["certification_record"]
    assert after["dataset_sha256"] == before["dataset_sha256"]
    assert after["revoked_at"] > 0
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("ONLY_CERTIFIED_CERTIFICATE"):
        contract.revoke_certificate(pkg["dataset_id"], "again")
    with direct_vm.expect_revert("DUPLICATE_CERTIFICATION"):
        contract.certify_dataset(pkg["dataset_id"])


def test_inconclusive_not_revokeable_and_missing_id_is_rejected(
    direct_vm, direct_deploy, direct_alice
):
    contract = deploy(direct_deploy)
    with direct_vm.expect_revert("CERTIFICATE_NOT_FOUND"):
        contract.get_certificate("missing")
    pkg = package()
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, status=404)
    contract.certify_dataset(pkg["dataset_id"])
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("ONLY_CERTIFIED_CERTIFICATE"):
        contract.revoke_certificate(pkg["dataset_id"], "not live")
