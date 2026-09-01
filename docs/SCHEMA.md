# Exact DatasetBond schema

The machine-readable source of truth is [`schema/datasetbond.schema.json`](../schema/datasetbond.schema.json).
The contract uses `dataset_id` as both the unique registration key and `certificate_id`. There is
no setter and no second registration for the same identifier.

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
  usage_profile: string,
) -> string
```

`dataset_id` is 1–96 characters matching `^[a-z][a-z0-9._:-]{0,95}$`. Every reference is at most
512 characters, uses `https://`, has no credentials, query, or fragment, and must be one of:

- a GitHub raw/blob URL pinned to a 40-hex commit;
- an Arweave transaction URL;
- an HTTPS IPFS gateway or IPFS subdomain with a content identifier.

Every digest is exactly 64 lowercase hexadecimal characters. Profiles are:
`RESEARCH_EVALUATION`, `MODEL_TRAINING`, `COMMERCIAL_TRAINING`, and `REDISTRIBUTION`.

## Stored Certificate

Each `Certificate` contains:

```text
certificate_id, dataset_id,
dataset_reference, dataset_sha256,
license_reference, license_sha256,
provenance_reference, provenance_sha256,
usage_profile, submitter,
registered_at, evaluated_at, revoked_at,
status, verdict, attempts,
certification_record, revocation_reason
```

The evidence fields and profile never change. Timestamps are whole Unix seconds derived from the
timezone-qualified transaction message datetime, not a validator wall clock. The certification
record is canonical, key-sorted, separator-tight JSON containing only the schema version, package
identity/digests, profile, verdict, evaluation timestamp, and attempt number.

## Public methods

| Method | Access | Behavior |
| --- | --- | --- |
| `register_dataset` | write | Add one immutable package; duplicate IDs revert. |
| `certify_dataset` | write | Evaluate once through validator-backed nondeterminism. |
| `revoke_certificate` | write | Submitter-only controlled revocation of `CERTIFIED`. |
| `get_certificate` | view | Return one complete certificate dictionary. |
| `get_certificates` | view | Return all certificates keyed by dataset ID. |
| `get_certificate_ids` | view | Return registration order. |
| `get_certificate_count` | view | Return a `u256` count. |

The model's only accepted output is a JSON object with exactly one key, `verdict`, whose value is
one of the three allowed verdicts. The contract adds its own `evidence_verified` bit in the
nondeterministic result; that bit is never model-controlled and is not free-form explanation.
