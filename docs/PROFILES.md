# DatasetBond v2.1 certification profiles

Profiles are explicit licensing/provenance criteria, not general-purpose dataset-quality rubrics.
Every v2.1 package requires a bounded inline signed evidence manifest from an active trust-root key.

| Profile | Required license meaning | Minimum provenance meaning |
| --- | --- | --- |
| `RESEARCH_EVALUATION` | Research and evaluation use explicitly permitted. | Signed identity plus publisher, source, version, creation/collection time, transformations. |
| `MODEL_TRAINING` | Machine-learning or AI training explicitly permitted. | Signed identity plus publisher, source, version, creation/collection time, transformations. |
| `COMMERCIAL_TRAINING` | Commercial use and machine-learning/AI training explicitly permitted. | Signed identity plus publisher, source, version, creation/collection time, transformations. |
| `REDISTRIBUTION` | Redistribution explicitly permitted, including attribution/notice obligations. | Signed identity plus publisher, source, version, creation/collection time, transformations. |

## Inline signed evidence manifest

The canonical signed manifest contains exactly:

```json
{
  "nonce": "single-use-manifest",
  "manifest_version": 2,
  "dataset_id": "demo-dataset-1",
  "dataset_reference": "registered content-addressed reference",
  "dataset_sha256": "registered digest",
  "license_reference": "registered content-addressed reference",
  "license_sha256": "registered digest",
  "provenance_reference": "registered content-addressed reference",
  "provenance_sha256": "registered digest",
  "usage_profile": "MODEL_TRAINING",
  "publisher_identity": "example-publisher",
  "key_id": "example-key-2026-a",
  "issued_at": 1790000000,
  "expires_at": 1790003600,
  "signature_algorithm": "SECP256K1_ECDSA_SHA256",
  "signature": "lowercase hex r||s"
}
```

Its bytes are UTF-8 canonical JSON: lexicographically sorted keys, no insignificant whitespace,
and `ensure_ascii=false`. The signature covers the same canonical object with `signature` removed.
The manifest digest covers the complete signed bytes supplied inline at registration. `nonce` is
tracked as single-use after a terminal certification result, so an `INCONCLUSIVE` attempt can be
retried but a used manifest cannot be replayed for another certificate. No signed-manifest URL is
required.

## Provenance completeness

The referenced provenance manifest remains a separate exact evidence object. It must be UTF-8 JSON,
link the exact registered dataset/license references and digests, repeat the signed
`publisher_identity`, and contain non-empty `source`, `version`, timezone-qualified ISO-8601
`created_at`, and at most 32 transformation descriptions. Those fields establish completeness and
consistency only; they do not prove the real-world identity or legal authority of the named party.

## License authority

Consumers should select canonical license sources such as the relevant SPDX, Creative Commons, Open
Data Commons, Apache, or publisher-controlled immutable source. The issuer registry authenticates
control of a registered key over a manifest; it does not certify legal ownership, authorization,
legal enforceability, or the truth of publisher claims.
