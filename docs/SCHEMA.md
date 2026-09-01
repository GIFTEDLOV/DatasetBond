# Exact DatasetBond v2.1 schema

The machine-readable source of truth is [`schema/datasetbond.schema.json`](../schema/datasetbond.schema.json).
The v2.1 API adds a deployer-owned trust root and requires every certification package to supply a
bounded inline canonical signed evidence manifest. The trust root authenticates registered key
control, not legal ownership.

## Deployment trust root

The deployer becomes the immutable `trust_root` recorded in the constructor. Only that address may
register, revoke, or rotate issuer verification keys. There is no admin override for certificates.

## Registration

```text
register_dataset(
  dataset_id: string,
  dataset_reference: string,
  dataset_sha256: string,
  license_reference: string,
  license_sha256: string,
  provenance_reference: string,
  provenance_sha256: string,
  evidence_manifest: string,
  evidence_manifest_sha256: string,
  nonce: string,
  publisher_identity: string,
  key_id: string,
  usage_profile: string,
) -> string
```

`dataset_reference`, `license_reference`, and `provenance_reference` must be HTTPS content- or
commit-addressed references: commit-pinned GitHub, Arweave transaction, or HTTPS IPFS gateway/path.
They are not generic immutable HTTPS URLs. The signed manifest is not referenced by URL: its
canonical UTF-8 JSON is supplied directly as `evidence_manifest` and anchored by the supplied
`evidence_manifest_sha256`.

All references are at most 512 characters, credential-free, and have no query or fragment. Every
digest is exactly 64 lowercase hexadecimal characters. Identifiers are 1-96 characters matching
`^[a-z][a-z0-9._:-]{0,95}$`.

## Issuer administration

```text
register_issuer_key(issuer_id, key_id, public_key, "SECP256K1_ECDSA_SHA256") -> IssuerKey
revoke_issuer_key(key_id, reason) -> IssuerKey
rotate_issuer_key(issuer_id, old_key_id, new_key_id, new_public_key) -> IssuerKey
```

The public key is 64-byte uncompressed secp256k1 `x||y` as 128 lowercase hex characters. The
signature is 64-byte low-`s` ECDSA `r||s` as 128 lowercase hex characters. Verification is a
self-contained pure-Python secp256k1 verifier using runtime-supported integer arithmetic and
SHA-256; no host-only crypto package or invented GenVM verifier API is used.

## Canonical inline signed evidence manifest

The inline manifest is UTF-8 JSON with exactly these keys, sorted lexicographically, no
insignificant whitespace, and `ensure_ascii=false`. `manifest_version` remains part of the exact
field set for versioned canonicalization:

```json
{
  "dataset_id": "datasetbond-demo-observations",
  "dataset_reference": "https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/ac2cd29483d78adffc299f25c92702d6ffd05708/examples/public-fixture/dataset.json",
  "dataset_sha256": "7b24103a164674959d071b3e69baa2c194e4f24fdd373a5ea8a1e6f430d5eb12",
  "expires_at": 1819670400,
  "issued_at": 1788220800,
  "key_id": "datasetbond-demo-key-2026-a",
  "license_reference": "https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/ac2cd29483d78adffc299f25c92702d6ffd05708/examples/public-fixture/LICENSE.txt",
  "license_sha256": "8e28e056d91dbb82759a8e1b50ae0b81a07ddb3c2ee01e4592d38f9181a9881e",
  "nonce": "datasetbond-demo-nonce-2026-09-01-a",
  "manifest_version": 2,
  "provenance_reference": "https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/52f5b0c82a2e305b5e607818e69e5acc1ff063d5/examples/public-fixture/provenance.json",
  "provenance_sha256": "179a3e8edb8ea41b2cc974e000a520a95f2d8bb1332fdc62dfacbcf5492a8479",
  "publisher_identity": "datasetbond-demo",
  "signature": "7fc584a69b65228dfd25863f2ef7b944629b5b5794305581ef9f13ed7dd98a59300bc6da92d4a9ff2a4edf2bb97b39937ea7544fe781278c93e1cdea01896aec",
  "signature_algorithm": "SECP256K1_ECDSA_SHA256",
  "usage_profile": "RESEARCH_EVALUATION"
}
```

The signature input is the same canonical JSON with `signature` removed. The
`evidence_manifest_sha256` argument is the SHA-256 of the complete canonical signed-manifest UTF-8
bytes and is the certificate's canonical manifest digest. Registration rejects non-canonical JSON,
unknown/missing fields, a digest mismatch, and any mismatch between manifest fields and registration
arguments. Certification does not fetch a manifest URL; it reconstructs and re-authenticates the
anchored fields.

## Stored certificate

Each certificate contains the committed package, signed identity fields, lifecycle fields, four
separate evaluation levels, and a fixed scope statement:

```text
certificate_id, dataset_id,
dataset_reference, dataset_sha256,
license_reference, license_sha256,
provenance_reference, provenance_sha256,
evidence_manifest_sha256,
nonce, publisher_identity, key_id,
manifest_issued_at, manifest_expires_at, manifest_signature, usage_profile, submitter,
registered_at, evaluated_at, revoked_at,
status, verdict, attempts,
certification_record, revocation_reason,
integrity_status, authentication_status, license_status, provenance_status,
scope_statement
```

`integrity_status` distinguishes `VERIFIED`, `UNAVAILABLE`, `INVALID_RESPONSE`, and
`DIGEST_MISMATCH`. `authentication_status` distinguishes trusted, unregistered, revoked, rotated,
expired, replayed, malformed, canonicalization-mismatched, and invalid-signature outcomes.
`license_status` is `COMPATIBLE`, `INCOMPATIBLE`, or `INCONCLUSIVE`; `provenance_status` is
`COMPLETE`, `INCOMPLETE`, or `INCONCLUSIVE`.

## Public methods

| Method | Access | Behavior |
| --- | --- | --- |
| `register_dataset` | write | Add one signed-manifest package; duplicate IDs revert. |
| `register_issuer_key` | trust-root write | Register one verification key. |
| `revoke_issuer_key` | trust-root write | Revoke an active verification key. |
| `rotate_issuer_key` | trust-root write | Add a successor and rotate the old key atomically. |
| `certify_dataset` | write | Fetch, authenticate, and semantically evaluate once. |
| `revoke_certificate` | write | Submitter-only controlled revocation of `CERTIFIED`. |
| `get_certificate` | view | Return one complete certificate. |
| `get_certificates` | view | Return all certificates keyed by dataset ID. |
| `get_certificate_ids` | view | Return registration order. |
| `get_certificate_count` | view | Return certificate count. |
| `get_trust_root` | view | Return the deployer trust-root address. |
| `get_issuer_key` | view | Return one issuer-key record. |
| `get_issuer_keys` | view | Return all issuer-key records. |
| `get_issuer_key_count` | view | Return issuer-key count. |
