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
  "nonce": "datasetbond-demo-nonce-2026-09-01-a",
  "manifest_version": 2,
  "dataset_id": "datasetbond-demo-observations",
  "dataset_reference": "https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/ac2cd29483d78adffc299f25c92702d6ffd05708/examples/public-fixture/dataset.json",
  "dataset_sha256": "7b24103a164674959d071b3e69baa2c194e4f24fdd373a5ea8a1e6f430d5eb12",
  "license_reference": "https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/ac2cd29483d78adffc299f25c92702d6ffd05708/examples/public-fixture/LICENSE.txt",
  "license_sha256": "8e28e056d91dbb82759a8e1b50ae0b81a07ddb3c2ee01e4592d38f9181a9881e",
  "provenance_reference": "https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/52f5b0c82a2e305b5e607818e69e5acc1ff063d5/examples/public-fixture/provenance.json",
  "provenance_sha256": "179a3e8edb8ea41b2cc974e000a520a95f2d8bb1332fdc62dfacbcf5492a8479",
  "usage_profile": "RESEARCH_EVALUATION",
  "publisher_identity": "datasetbond-demo",
  "key_id": "datasetbond-demo-key-2026-a",
  "issued_at": 1788220800,
  "expires_at": 1819670400,
  "signature_algorithm": "SECP256K1_ECDSA_SHA256",
  "signature": "7fc584a69b65228dfd25863f2ef7b944629b5b5794305581ef9f13ed7dd98a59300bc6da92d4a9ff2a4edf2bb97b39937ea7544fe781278c93e1cdea01896aec"
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
