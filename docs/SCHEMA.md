# Exact DatasetBond v2 schema

The machine-readable source of truth is [`schema/datasetbond.schema.json`](../schema/datasetbond.schema.json).
The v2 API adds a deployer-owned trust root and requires every certification package to identify a
signed evidence manifest. The trust root authenticates registered key control, not legal ownership.

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
  evidence_manifest_reference: string,
  evidence_manifest_sha256: string,
  manifest_id: string,
  publisher_identity: string,
  key_id: string,
  usage_profile: string,
) -> string
```

`dataset_reference`, `license_reference`, and `provenance_reference` must be HTTPS content- or
commit-addressed references: commit-pinned GitHub, Arweave transaction, or HTTPS IPFS gateway/path.
They are not generic immutable HTTPS URLs. `evidence_manifest_reference` is an HTTPS locator whose
retrieved bytes must match its digest and the signed canonical manifest; the signature supplies the
authentication property even when the locator itself can move.

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

## Canonical signed evidence manifest

The signed manifest is UTF-8 JSON with exactly these keys, sorted lexicographically, no insignificant
whitespace, and `ensure_ascii=false`:

```json
{
  "dataset_id": "demo-dataset-1",
  "dataset_reference": "the registered content-addressed reference",
  "dataset_sha256": "the registered digest",
  "expires_at": 1790003600,
  "issued_at": 1790000000,
  "key_id": "example-key-2026-a",
  "license_reference": "the registered content-addressed reference",
  "license_sha256": "the registered digest",
  "manifest_id": "manifest-2026-01",
  "manifest_version": 2,
  "provenance_reference": "the registered content-addressed reference",
  "provenance_sha256": "the registered digest",
  "publisher_identity": "example-publisher",
  "signature": "lowercase hex r||s",
  "signature_algorithm": "SECP256K1_ECDSA_SHA256",
  "usage_profile": "MODEL_TRAINING"
}
```

`evidence_manifest_reference` is not a signed-manifest field; the package argument points to the
signed manifest itself. The signature input is the same canonical JSON with `signature` removed.
`evidence_manifest_sha256` is the SHA-256 of the complete canonical signed-manifest bytes and is
the certificate's canonical manifest digest. A non-canonical body or a digest mismatch is never
accepted.

## Stored certificate

Each certificate contains the committed package, signed identity fields, lifecycle fields, four
separate evaluation levels, and a fixed scope statement:

```text
certificate_id, dataset_id,
dataset_reference, dataset_sha256,
license_reference, license_sha256,
provenance_reference, provenance_sha256,
evidence_manifest_reference, evidence_manifest_sha256,
manifest_id, publisher_identity, key_id, usage_profile, submitter,
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
