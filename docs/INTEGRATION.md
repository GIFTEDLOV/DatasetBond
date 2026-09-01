# DatasetBond v2.1 integration guide

## Published demonstration package

The repository contains one self-owned demonstration package. It is intentionally small and is
published to the public [`DatasetBond` repository](https://github.com/GIFTEDLOV/DatasetBond) for
integration verification; it is not third-party production evidence and does not establish legal
ownership or publisher authority.

The dataset and license are pinned to commit
`ac2cd29483d78adffc299f25c92702d6ffd05708`, and the linked provenance JSON is pinned to commit
`52f5b0c82a2e305b5e607818e69e5acc1ff063d5`. The exact package, public issuer key, inline manifest,
and digests are in [`examples/datasetbond-package.json`](../examples/datasetbond-package.json).
Run the read-only validator before submitting any call:

```powershell
python tools/validate_inline_fixture.py
```

The validator independently fetches all three raw URLs, checks HTTP 200, hashes the exact response
bytes, validates the provenance linkage, and verifies the inline signature. It performs no chain
write and does not create or publish evidence.

## 1. Establish the trust root

Deploy DatasetBond with the intended governance account. The deployer address becomes the immutable
`trust_root`. Register the public key from the package before asking for certification:

```text
register_issuer_key(
  "datasetbond-demo",
  "datasetbond-demo-key-2026-a",
  "ec754b5dfd1c4678e36526ab729d8996eb1eecf344dc5e019c9352b5764e38096654c23b3876dc1f1e4572bc31c7713162f9f3324f6ffdd66dd00ae9e8cbbbe1",
  "SECP256K1_ECDSA_SHA256",
)
```

Trust-root registration authenticates that the deployer approved this issuer/key mapping. It does
not prove that the issuer is a legal identity, owns the dataset, or has authority to license it.

## 2. Submit the exact package

`examples/integration.py` loads the published fixture bytes and builds the exact call sequence:

```powershell
python examples/integration.py
```

The registration arguments are, in order:

```text
register_dataset(
  dataset_id,
  dataset_reference,
  dataset_sha256,
  license_reference,
  license_sha256,
  provenance_reference,
  provenance_sha256,
  evidence_manifest,
  evidence_manifest_sha256,
  nonce,
  publisher_identity,
  key_id,
  usage_profile,
)
```

The inline manifest is canonical UTF-8 JSON with sorted keys and no insignificant whitespace. Its
`signature` is low-`s` secp256k1 `r||s` over the SHA-256 of the canonical manifest with that field
removed. The complete signed bytes are anchored by `evidence_manifest_sha256`. DatasetBond does
not fetch a manifest URL.

## 3. Certify and consume

```text
certify_dataset(dataset_id) -> Certificate
get_certificate(dataset_id) -> Certificate
```

Accept only when `status == CERTIFIED`, `verdict == CERTIFIED`, `integrity_status == VERIFIED`,
`authentication_status == AUTHENTICATED`, `license_status == COMPATIBLE`,
`provenance_status == COMPLETE`, and the stored profile is the requested profile. The frontend or
client must not compute or override the verdict. `INCONCLUSIVE` is retryable and never an approval;
`NOT_CERTIFIED` is a verified semantic negative.

## 4. Revoke or rotate

Only the original registration submitter can revoke a live `CERTIFIED` certificate. Only the trust
root can revoke or rotate issuer keys. Rotation marks the old key `ROTATED`; future attempts under
it are `INCONCLUSIVE`. Revocation preserves the historical evidence, digests, signer identity, and
certification record.

The package demonstrates integrity, trust-root key authentication, bounded license/provenance
judgment, and lifecycle handling. It does not prove dataset factual correctness, legal ownership,
legal enforceability, absence of undisclosed source material, or permanent availability of external
URLs.
