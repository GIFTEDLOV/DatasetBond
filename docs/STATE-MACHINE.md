# DatasetBond state machine

```text
REGISTERED
    ├── certify_dataset ──> CERTIFIED
    ├── certify_dataset ──> NOT_CERTIFIED
    └── certify_dataset ──> INCONCLUSIVE ──(retry)──> CERTIFIED
                                                └──> NOT_CERTIFIED
CERTIFIED ── submitter-only revoke_certificate(reason) ──> REVOKED
```

`REGISTERED` has no verdict and no certification record. Each evaluation increments `attempts`,
stores its bounded canonical record, and sets `evaluated_at`. An `INCONCLUSIVE` evaluation is
retryable because a web or model provider can be temporarily unavailable. `CERTIFIED` and
`NOT_CERTIFIED` cannot be evaluated again, which prevents replaying until a desired answer appears.

Revocation is controlled: only the original submitter can revoke, only a live `CERTIFIED` record
can be revoked, and the reason is bounded. Revocation changes status and adds `revoked_at` and a
bounded reason; it does not rewrite the evidence references, digests, original verdict, or
certification record. There are no monetary transfers and no administrator override.
