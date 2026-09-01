# DatasetBond v2 integration guide

## 1. Establish the trust root

Deploy DatasetBond with the intended governance account. The deployer address becomes the immutable
`trust_root`. Register an issuer key before asking for certification:

```text
register_issuer_key(
  "example-publisher",
  "example-key-2026-a",
  "<128 lowercase hex characters containing secp256k1 x||y>",
  "SECP256K1_ECDSA_SHA256",
)
```

Keep the root account in the consumer's governance process. Key registration means only that this
root approved the key/issuer mapping. It is not a legal identity or ownership attestation.

## 2. Build and sign the canonical manifest

Create a JSON object with exactly the fields documented in [`docs/SCHEMA.md`](SCHEMA.md). Serialize
it as sorted-key UTF-8 JSON with no insignificant whitespace and `ensure_ascii=false`. Remove the
`signature` field, hash the remaining canonical bytes with SHA-256, and sign that hash using the
issuer's secp256k1 private key. Encode low-`s` `r||s` as 128 lowercase hex characters, add it as
`signature`, and canonicalize the complete signed object again.

The package's `evidence_manifest_sha256` is the SHA-256 of the complete signed manifest bytes. The
signed manifest covers the dataset ID/reference/digest, license reference/digest, provenance
reference/digest, use profile, issuer identity, key ID, version, validity timestamps, algorithm,
and signature. `manifest_id` is single-use after a terminal certification result.

## 3. Register exact evidence

Submit this exact argument order to `register_dataset`:

```json
[
  "demo-dataset-1",
  "https://raw.githubusercontent.com/acme/datasets/<40-hex-commit>/data.csv",
  "<sha256 of exact dataset bytes>",
  "https://raw.githubusercontent.com/spdx/license-list-data/<40-hex-commit>/licenses/MIT.txt",
  "<sha256 of exact license bytes>",
  "https://raw.githubusercontent.com/acme/provenance/<40-hex-commit>/manifest.json",
  "<sha256 of exact provenance bytes>",
  "https://publisher.example/evidence-manifest/demo-v2.json",
  "<sha256 of exact signed manifest bytes>",
  "manifest-2026-01",
  "example-publisher",
  "example-key-2026-a",
  "MODEL_TRAINING"
]
```

Replace the illustrative values with real evidence. Dataset, license, and provenance references
must be content-addressed or commit-pinned; ordinary HTTPS URLs are rejected for those fields. The
signed manifest locator may be ordinary HTTPS because its bytes are digest-checked and signed, but
the locator is not permanent.

## 4. Certify and consume

```text
certify_dataset(dataset_id) -> Certificate
get_certificate(dataset_id) -> Certificate
```

Accept only when all of these are true: `status == CERTIFIED`, `verdict == CERTIFIED`,
`integrity_status == VERIFIED`, `authentication_status == AUTHENTICATED`,
`license_status == COMPATIBLE`, and `provenance_status == COMPLETE`. Treat `INCONCLUSIVE` as
pending and retryable; it is never an approval or rejection. `NOT_CERTIFIED` is a verified semantic
negative. `REVOKED` is no longer live but retains the historical evidence and record.

## 5. Revoke or rotate

Only the original registration submitter can revoke a live `CERTIFIED` certificate. Only the trust
root can revoke or rotate issuer keys. Rotation creates a new active key and marks the old key
`ROTATED`; future attempts under the old key are `INCONCLUSIVE`.

[`examples/integration.py`](../examples/integration.py) constructs client-neutral call payloads and
uses no network, signer, deployment, or broadcast. A production client should use the supported
GenLayer client for the selected environment.
