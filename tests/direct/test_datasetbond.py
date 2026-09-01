"""Direct and consensus-shaped DatasetBond v2.1 tests."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime

import pytest
from eth_keys import keys


DATASET_REFERENCE = (
    "https://raw.githubusercontent.com/acme/datasets/"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/data.csv"
)
DATASET_REFERENCE_TWO = (
    "https://raw.githubusercontent.com/acme/datasets/"
    "dddddddddddddddddddddddddddddddddddddddd/data.csv"
)
LICENSE_REFERENCE = (
    "https://raw.githubusercontent.com/spdx/license-list-data/"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/licenses/MIT.txt"
)
LICENSE_REFERENCE_TWO = (
    "https://raw.githubusercontent.com/spdx/license-list-data/"
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/licenses/MIT.txt"
)
PROVENANCE_REFERENCE = (
    "https://raw.githubusercontent.com/acme/provenance/"
    "cccccccccccccccccccccccccccccccccccccccc/manifests/demo.json"
)
PROVENANCE_REFERENCE_TWO = (
    "https://raw.githubusercontent.com/acme/provenance/"
    "ffffffffffffffffffffffffffffffffffffffff/manifests/demo.json"
)
DATASET_BYTES = b"id,value\n1,example\n"
LICENSE_BYTES = (
    b"SPDX-License-Identifier: MIT\n"
    b"Permission is hereby granted to use, copy, modify, publish, distribute, and sell.\n"
    b"Commercial machine-learning training use is permitted.\n"
)
ISSUER_ID = "example-publisher"
KEY_ONE_ID = "example-key-2026-a"
KEY_TWO_ID = "example-key-2026-b"
# Test-only keys are derived at runtime from labels; no raw private key is committed.
PRIVATE_ONE = keys.PrivateKey(hashlib.sha256(b"DatasetBond v2.1 test-only key one").digest())
PRIVATE_TWO = keys.PrivateKey(hashlib.sha256(b"DatasetBond v2.1 test-only key two").digest())


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def public_key_hex(private_key: keys.PrivateKey) -> str:
    return private_key.public_key.to_bytes().hex()


def transaction_timestamp(direct_vm) -> int:
    raw = direct_vm.get_message_raw()["datetime"]
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    return int(datetime.fromisoformat(text).timestamp())


def provenance_bytes(
    dataset_reference: str,
    dataset_sha256: str,
    license_reference: str,
    license_sha256: str,
    publisher: str = ISSUER_ID,
    **overrides,
) -> bytes:
    payload = {
        "dataset_reference": dataset_reference,
        "dataset_sha256": dataset_sha256,
        "license_reference": license_reference,
        "license_sha256": license_sha256,
        "publisher": publisher,
        "source": "Example catalog export",
        "version": "2026.01",
        "created_at": "2026-01-01T00:00:00Z",
        "transformations": ["UTF-8 CSV export"],
    }
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(payload: dict, private_key: keys.PrivateKey) -> bytes:
    unsigned = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    signature = private_key.sign_msg_hash(hashlib.sha256(unsigned).digest())
    signed = dict(payload)
    signed["signature"] = f"{signature.r:064x}{signature.s:064x}"
    return json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def package(
    direct_vm,
    dataset_id: str = "demo-dataset-1",
    dataset_reference: str = DATASET_REFERENCE,
    license_reference: str = LICENSE_REFERENCE,
    provenance_reference: str = PROVENANCE_REFERENCE,
    nonce: str = "manifest-2026-01",
    publisher_identity: str = ISSUER_ID,
    key_id: str = KEY_ONE_ID,
    usage_profile: str = "COMMERCIAL_TRAINING",
    private_key: keys.PrivateKey = PRIVATE_ONE,
    issued_at: int | None = None,
    expires_at: int | None = None,
    provenance_body: bytes | None = None,
) -> dict:
    now = transaction_timestamp(direct_vm)
    signed_issued_at = now - 60 if issued_at is None else issued_at
    signed_expires_at = now + 3600 if expires_at is None else expires_at
    dataset_digest = sha256(DATASET_BYTES)
    license_digest = sha256(LICENSE_BYTES)
    exact_provenance_body = provenance_body if provenance_body is not None else provenance_bytes(
        dataset_reference,
        dataset_digest,
        license_reference,
        license_digest,
        publisher_identity,
    )
    signed_payload = {
        "nonce": nonce,
        "manifest_version": 2,
        "dataset_id": dataset_id,
        "dataset_reference": dataset_reference,
        "dataset_sha256": dataset_digest,
        "license_reference": license_reference,
        "license_sha256": license_digest,
        "provenance_reference": provenance_reference,
        "provenance_sha256": sha256(exact_provenance_body),
        "usage_profile": usage_profile,
        "publisher_identity": publisher_identity,
        "key_id": key_id,
        "issued_at": signed_issued_at,
        "expires_at": signed_expires_at,
        "signature_algorithm": "SECP256K1_ECDSA_SHA256",
    }
    exact_evidence_manifest_body = sign_manifest(signed_payload, private_key)
    return {
        "dataset_id": dataset_id,
        "dataset_reference": dataset_reference,
        "dataset_sha256": dataset_digest,
        "license_reference": license_reference,
        "license_sha256": license_digest,
        "provenance_reference": provenance_reference,
        "provenance_sha256": sha256(exact_provenance_body),
        "evidence_manifest": exact_evidence_manifest_body.decode("utf-8"),
        "evidence_manifest_sha256": sha256(exact_evidence_manifest_body),
        "nonce": nonce,
        "publisher_identity": publisher_identity,
        "key_id": key_id,
        "usage_profile": usage_profile,
        "_provenance_body": exact_provenance_body,
        "_evidence_manifest_body": exact_evidence_manifest_body,
    }


def deploy(direct_deploy):
    return direct_deploy("contracts/datasetbond.py")


def register(direct_vm, contract, direct_alice, pkg: dict) -> str:
    direct_vm.sender = direct_alice
    values = {key: value for key, value in pkg.items() if not key.startswith("_")}
    return contract.register_dataset(**values)


def register_key(direct_vm, contract, direct_owner, key_id: str = KEY_ONE_ID, private_key=PRIVATE_ONE):
    direct_vm.sender = direct_owner
    return contract.register_issuer_key(
        ISSUER_ID,
        key_id,
        public_key_hex(private_key),
        "SECP256K1_ECDSA_SHA256",
    )


def deploy_with_key(direct_vm, direct_deploy, direct_owner):
    contract = deploy(direct_deploy)
    register_key(direct_vm, contract, direct_owner)
    return contract


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
    exact_provenance_body = pkg["_provenance_body"] if provenance_body is None else provenance_body
    for reference, response_body in (
        (pkg["dataset_reference"], dataset_body),
        (pkg["license_reference"], license_body),
        (pkg["provenance_reference"], exact_provenance_body),
    ):
        direct_vm.mock_web(re.escape(reference) + "$", {"status": status, "body": response_body})
    if model_response is not None:
        response = json.dumps(model_response) if isinstance(model_response, dict) else model_response
        direct_vm.mock_llm(r"DatasetBond certification arbiter", response)


def test_trust_root_issuer_registration_and_views(direct_vm, direct_deploy, direct_owner, direct_bob):
    contract = deploy(direct_deploy)
    assert contract.get_trust_root().lower() == ("0x" + bytes(direct_owner).hex()).lower()
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("ONLY_TRUST_ROOT"):
        contract.register_issuer_key(ISSUER_ID, KEY_ONE_ID, public_key_hex(PRIVATE_ONE), "SECP256K1_ECDSA_SHA256")
    key = register_key(direct_vm, contract, direct_owner)
    assert key["status"] == "ACTIVE"
    assert contract.get_issuer_key(KEY_ONE_ID)["public_key"] == public_key_hex(PRIVATE_ONE)
    assert contract.get_issuer_key_count() == 1
    assert list(contract.get_issuer_keys()) == [KEY_ONE_ID]
    with direct_vm.prank(direct_owner), direct_vm.expect_revert("DUPLICATE_ISSUER_KEY"):
        contract.register_issuer_key(ISSUER_ID, KEY_ONE_ID, public_key_hex(PRIVATE_ONE), "SECP256K1_ECDSA_SHA256")


def test_valid_signature_certifies_and_exposes_separate_levels(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "CERTIFIED"
    assert cert["verdict"] == "CERTIFIED"
    assert cert["integrity_status"] == "VERIFIED"
    assert cert["authentication_status"] == "AUTHENTICATED"
    assert cert["license_status"] == "COMPATIBLE"
    assert cert["provenance_status"] == "COMPLETE"
    assert cert["evidence_manifest_sha256"] == pkg["evidence_manifest_sha256"]
    assert cert["nonce"] == pkg["nonce"]
    assert cert["publisher_identity"] == ISSUER_ID
    assert cert["key_id"] == KEY_ONE_ID
    assert cert["usage_profile"] == pkg["usage_profile"]
    assert cert["manifest_signature"] == json.loads(pkg["evidence_manifest"])["signature"]
    assert all(key != "evidence_" + "manifest_reference" for key in cert)
    assert cert["scope_statement"].count("does not prove") == 1
    assert "explanation" not in cert["certification_record"]


def test_registration_views_and_duplicate_dataset_id(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    assert register(direct_vm, contract, direct_alice, pkg) == pkg["dataset_id"]
    cert = contract.get_certificate(pkg["dataset_id"])
    assert cert["status"] == "REGISTERED"
    assert cert["verdict"] == ""
    assert cert["integrity_status"] == "NOT_EVALUATED"
    assert contract.get_certificate_ids() == [pkg["dataset_id"]]
    assert contract.get_certificate_count() == 1
    assert list(contract.get_certificates()) == [pkg["dataset_id"]]
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("DUPLICATE_DATASET_ID"):
        register(direct_vm, contract, direct_alice, pkg)


def test_verified_license_incompatibility_is_not_certified(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    incompatible_license = b"SPDX-License-Identifier: CC-BY-NC-4.0\nCommercial training is prohibited.\n"
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    pkg["license_sha256"] = sha256(incompatible_license)
    pkg["_provenance_body"] = provenance_bytes(
        pkg["dataset_reference"], pkg["dataset_sha256"], pkg["license_reference"], pkg["license_sha256"]
    )
    pkg["provenance_sha256"] = sha256(pkg["_provenance_body"])
    pkg["_evidence_manifest_body"] = sign_manifest(
        {
            "nonce": pkg["nonce"],
            "manifest_version": 2,
            "dataset_id": pkg["dataset_id"],
            "dataset_reference": pkg["dataset_reference"],
            "dataset_sha256": pkg["dataset_sha256"],
            "license_reference": pkg["license_reference"],
            "license_sha256": pkg["license_sha256"],
            "provenance_reference": pkg["provenance_reference"],
            "provenance_sha256": pkg["provenance_sha256"],
            "usage_profile": pkg["usage_profile"],
            "publisher_identity": pkg["publisher_identity"],
            "key_id": pkg["key_id"],
            "issued_at": transaction_timestamp(direct_vm) - 60,
            "expires_at": transaction_timestamp(direct_vm) + 3600,
            "signature_algorithm": "SECP256K1_ECDSA_SHA256",
        },
        PRIVATE_ONE,
    )
    pkg["evidence_manifest"] = pkg["_evidence_manifest_body"].decode("utf-8")
    pkg["evidence_manifest_sha256"] = sha256(pkg["_evidence_manifest_body"])
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, license_body=incompatible_license, model_response={"verdict": "NOT_CERTIFIED"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "NOT_CERTIFIED"
    assert cert["license_status"] == "INCOMPATIBLE"
    assert cert["authentication_status"] == "AUTHENTICATED"


def test_altered_manifest_fails_signature_verification(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    altered = pkg["_evidence_manifest_body"]
    signature_start = altered.index(b'"signature":"') + len(b'"signature":"')
    replacement = b"0" if altered[signature_start : signature_start + 1] != b"0" else b"1"
    altered = altered[:signature_start] + replacement + altered[signature_start + 1 :]
    pkg["_evidence_manifest_body"] = altered
    pkg["evidence_manifest"] = altered.decode("utf-8")
    pkg["evidence_manifest_sha256"] = sha256(altered)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "INCONCLUSIVE"
    assert cert["authentication_status"] == "INVALID_SIGNATURE"
    assert cert["integrity_status"] == "VERIFIED"


def test_changed_usage_profile_is_rejected_by_signed_binding(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    pkg["usage_profile"] = "MODEL_TRAINING"
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("MANIFEST_MISMATCH"):
        register(direct_vm, contract, direct_alice, pkg)


def test_wrong_signer_is_not_authenticated(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm, private_key=PRIVATE_TWO)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(pkg["dataset_id"])["authentication_status"] == "INVALID_SIGNATURE"


def test_unregistered_signer_is_inconclusive(direct_vm, direct_deploy, direct_alice):
    contract = deploy(direct_deploy)
    pkg = package(direct_vm, key_id="unregistered-key")
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["authentication_status"] == "UNREGISTERED_ISSUER"
    assert cert["status"] == "INCONCLUSIVE"


def test_revoked_signer_is_inconclusive(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    with direct_vm.prank(direct_owner):
        contract.revoke_issuer_key(KEY_ONE_ID, "trust root emergency revocation")
    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(pkg["dataset_id"])["authentication_status"] == "REVOKED_ISSUER"


def test_expired_signature_is_inconclusive(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    now = transaction_timestamp(direct_vm)
    pkg = package(direct_vm, issued_at=now - 7200, expires_at=now - 3600)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(pkg["dataset_id"])["authentication_status"] == "EXPIRED"


def test_key_rotation_invalidates_old_key_and_accepts_successor(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    with direct_vm.prank(direct_owner):
        rotated = contract.rotate_issuer_key(
            ISSUER_ID, KEY_ONE_ID, KEY_TWO_ID, public_key_hex(PRIVATE_TWO)
        )
    assert rotated["status"] == "ACTIVE"
    old_pkg = package(direct_vm, nonce="old-key-manifest")
    register(direct_vm, contract, direct_alice, old_pkg)
    mock_package(direct_vm, old_pkg, model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(old_pkg["dataset_id"])["authentication_status"] == "ROTATED_KEY"

    new_pkg = package(
        direct_vm,
        dataset_id="new-key-dataset",
        nonce="new-key-manifest",
        key_id=KEY_TWO_ID,
        private_key=PRIVATE_TWO,
    )
    register(direct_vm, contract, direct_alice, new_pkg)
    mock_package(direct_vm, new_pkg, model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(new_pkg["dataset_id"])["status"] == "CERTIFIED"


def test_canonicalization_mismatch_is_rejected_at_registration(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    pretty = json.dumps(json.loads(pkg["_evidence_manifest_body"]), sort_keys=True, indent=2).encode("utf-8")
    pkg["_evidence_manifest_body"] = pretty
    pkg["evidence_manifest"] = pretty.decode("utf-8")
    pkg["evidence_manifest_sha256"] = sha256(pretty)
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("CANONICALIZATION_MISMATCH"):
        register(direct_vm, contract, direct_alice, pkg)


def test_malformed_signature_is_rejected_at_registration(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    malformed = re.sub(rb'"signature":"[0-9a-f]+"', b'"signature":"not-hex"', pkg["_evidence_manifest_body"])
    pkg["_evidence_manifest_body"] = malformed
    pkg["evidence_manifest"] = malformed.decode("utf-8")
    pkg["evidence_manifest_sha256"] = sha256(malformed)
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("MALFORMED_MANIFEST"):
        register(direct_vm, contract, direct_alice, pkg)


def test_manifest_digest_mismatch_is_rejected_at_registration(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    pkg["evidence_manifest_sha256"] = "0" * 64
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("MANIFEST_DIGEST_MISMATCH"):
        register(direct_vm, contract, direct_alice, pkg)


def test_malformed_inline_manifest_is_rejected_at_registration(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    pkg["evidence_manifest"] = "not-json"
    pkg["evidence_manifest_sha256"] = sha256(b"not-json")
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("MALFORMED_MANIFEST"):
        register(direct_vm, contract, direct_alice, pkg)


@pytest.mark.parametrize("mutation", ["unknown", "missing"])
def test_inline_manifest_rejects_unknown_or_missing_fields(
    direct_vm, direct_deploy, direct_owner, direct_alice, mutation
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    manifest = json.loads(pkg["evidence_manifest"])
    if mutation == "unknown":
        manifest["unexpected"] = "rejected"
    else:
        del manifest["nonce"]
    malformed = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    pkg["evidence_manifest"] = malformed.decode("utf-8")
    pkg["evidence_manifest_sha256"] = sha256(malformed)
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("MALFORMED_MANIFEST"):
        register(direct_vm, contract, direct_alice, pkg)


@pytest.mark.parametrize("field", ["dataset", "license", "provenance"])
def test_altered_source_bytes_are_digest_mismatches(direct_vm, direct_deploy, direct_owner, direct_alice, field):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    kwargs = {field + "_body": b"altered-source"}
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"}, **kwargs)
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["integrity_status"] == "DIGEST_MISMATCH"
    assert cert["authentication_status"] == "AUTHENTICATED"


@pytest.mark.parametrize("field", ["dataset_sha256", "license_sha256", "provenance_sha256"])
def test_altered_registered_digests_break_signed_manifest_binding(
    direct_vm, direct_deploy, direct_owner, direct_alice, field
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    pkg[field] = "0" * 64
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("MANIFEST_MISMATCH"):
        register(direct_vm, contract, direct_alice, pkg)


@pytest.mark.parametrize("failure_status", [404, 503])
def test_unavailable_source_is_distinct_from_digest_mismatch(
    direct_vm, direct_deploy, direct_owner, direct_alice, failure_status
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, status=failure_status)
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["integrity_status"] == "UNAVAILABLE"
    assert cert["authentication_status"] == "AUTHENTICATED"


def test_malformed_provenance_manifest_is_inconclusive(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    malformed = b"not-json"
    pkg = package(direct_vm, provenance_body=malformed)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "INCONCLUSIVE"
    assert cert["authentication_status"] == "AUTHENTICATED"
    assert cert["provenance_status"] == "INCOMPLETE"


def test_replayed_nonce_is_inconclusive(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    first = package(direct_vm, nonce="single-use-manifest")
    register(direct_vm, contract, direct_alice, first)
    mock_package(direct_vm, first, model_response={"verdict": "CERTIFIED"})
    assert contract.certify_dataset(first["dataset_id"])["status"] == "CERTIFIED"

    second = package(
        direct_vm,
        dataset_id="second-dataset",
        dataset_reference=DATASET_REFERENCE_TWO,
        license_reference=LICENSE_REFERENCE_TWO,
        provenance_reference=PROVENANCE_REFERENCE_TWO,
        nonce="single-use-manifest",
    )
    register(direct_vm, contract, direct_alice, second)
    mock_package(direct_vm, second, model_response={"verdict": "CERTIFIED"})
    cert = contract.certify_dataset(second["dataset_id"])
    assert cert["authentication_status"] == "REPLAYED"
    assert cert["status"] == "INCONCLUSIVE"


def test_semantic_output_tampering_is_inconclusive_and_unstored(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED", "explanation": "override"})
    cert = contract.certify_dataset(pkg["dataset_id"])
    assert cert["status"] == "INCONCLUSIVE"
    assert cert["license_status"] == "INCONCLUSIVE"
    assert "override" not in cert["certification_record"]


def test_consensus_rejects_semantic_output_tampering(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    contract.certify_dataset(pkg["dataset_id"])
    mock_package(direct_vm, pkg, model_response={"verdict": "NOT_CERTIFIED"})
    assert direct_vm.run_validator() is False


def test_mutable_url_is_rejected_at_registration(direct_vm, direct_deploy, direct_owner, direct_alice):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm, dataset_reference="https://example.com/dataset.csv")
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("immutable"):
        register(direct_vm, contract, direct_alice, pkg)


def test_unsupported_reference_scheme_is_rejected_at_registration(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm, dataset_reference="ipfs://bafybeigdyrzt4example/data.csv")
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("https://"):
        register(direct_vm, contract, direct_alice, pkg)


def test_duplicate_registration_and_duplicate_certification_are_rejected(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("DUPLICATE_DATASET_ID"):
        register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "NOT_CERTIFIED"})
    contract.certify_dataset(pkg["dataset_id"])
    with direct_vm.expect_revert("DUPLICATE_CERTIFICATION"):
        contract.certify_dataset(pkg["dataset_id"])


def test_retry_after_inconclusive_preserves_levels_and_certifies(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, status=503)
    first = contract.certify_dataset(pkg["dataset_id"])
    assert first["status"] == "INCONCLUSIVE"
    assert first["integrity_status"] == "UNAVAILABLE"
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    second = contract.certify_dataset(pkg["dataset_id"])
    assert second["status"] == "CERTIFIED"
    assert second["attempts"] == 2
    assert second["authentication_status"] == "AUTHENTICATED"


def test_unauthorized_issuer_administration_and_certificate_revocation(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    contract = deploy_with_key(direct_vm, direct_deploy, direct_owner)
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("ONLY_TRUST_ROOT"):
        contract.revoke_issuer_key(KEY_ONE_ID, "unauthorized")
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("ONLY_TRUST_ROOT"):
        contract.rotate_issuer_key(ISSUER_ID, KEY_ONE_ID, KEY_TWO_ID, public_key_hex(PRIVATE_TWO))

    pkg = package(direct_vm)
    register(direct_vm, contract, direct_alice, pkg)
    mock_package(direct_vm, pkg, model_response={"verdict": "CERTIFIED"})
    contract.certify_dataset(pkg["dataset_id"])
    before = contract.get_certificate(pkg["dataset_id"])
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("ONLY_SUBMITTER"):
        contract.revoke_certificate(pkg["dataset_id"], "unauthorized")
    assert contract.get_certificate(pkg["dataset_id"]) == before
    with direct_vm.prank(direct_alice):
        revoked = contract.revoke_certificate(pkg["dataset_id"], "publisher withdrew certificate")
    assert revoked["status"] == "REVOKED"
    assert revoked["verdict"] == "CERTIFIED"
    assert revoked["authentication_status"] == "AUTHENTICATED"
    assert revoked["evidence_manifest_sha256"] == before["evidence_manifest_sha256"]
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("ONLY_CERTIFIED_CERTIFICATE"):
        contract.revoke_certificate(pkg["dataset_id"], "again")
    with direct_vm.expect_revert("DUPLICATE_CERTIFICATION"):
        contract.certify_dataset(pkg["dataset_id"])
