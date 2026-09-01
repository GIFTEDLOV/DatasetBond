# Certification profiles

Profiles are deliberately small and explicit. They are not general-purpose dataset-quality
rubrics. The model must find explicit license permission; silence, ambiguity, or a conclusion that
depends on authenticating an unverified publisher is `INCONCLUSIVE`.

| Profile | Required license meaning | Minimum provenance meaning |
| --- | --- | --- |
| `RESEARCH_EVALUATION` | Research and evaluation use explicitly permitted. | Publisher, source, version, creation/collection time, transformations. |
| `MODEL_TRAINING` | Machine-learning or AI training explicitly permitted. | Publisher, source, version, creation/collection time, transformations. |
| `COMMERCIAL_TRAINING` | Both commercial use and machine-learning/AI training explicitly permitted. | Publisher, source, version, creation/collection time, transformations. |
| `REDISTRIBUTION` | Redistribution explicitly permitted, including required attribution/notice obligations. | Publisher, source, version, creation/collection time, transformations. |

The provenance manifest must be UTF-8 JSON with at least:

```json
{
  "dataset_reference": "the registered immutable reference",
  "dataset_sha256": "the registered digest",
  "license_reference": "the registered immutable reference",
  "license_sha256": "the registered digest",
  "publisher": "declared publisher or rights holder",
  "source": "collection/source description",
  "version": "dataset version",
  "created_at": "timezone-qualified ISO-8601 collection or manifest creation time",
  "transformations": ["normalization or transformation description"]
}
```

The deterministic contract checks the four exact package links, required non-empty provenance
fields, transformation bounds, duplicate JSON keys, JSON shape, and timezone-qualified ISO-8601
`created_at`. It does not claim that a text
field naming a publisher proves that publisher's identity.

A license should be referenced from a canonical authority such as the relevant SPDX, Creative
Commons, Open Data Commons, Apache, or publisher-controlled immutable source. An immutable URL
proves which bytes were retrieved; it does not prove that the host or submitter is authorized to
issue those bytes.
