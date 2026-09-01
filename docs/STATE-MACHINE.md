# DatasetBond v2 state machine

```text
REGISTERED
    |-- certify_dataset -- valid evidence ----------------------> CERTIFIED
    |-- certify_dataset -- verified incompatible license -------> NOT_CERTIFIED
    |-- certify_dataset -- unavailable/auth failure/ambiguity --> INCONCLUSIVE
                                                                    |-- retry --> CERTIFIED
                                                                    |-- retry --> NOT_CERTIFIED
CERTIFIED -- submitter-only revoke_certificate(reason) ---------> REVOKED
```

`REGISTERED` has no final verdict and all four level statuses are `NOT_EVALUATED`. Each evaluation
increments `attempts` and stores a bounded canonical record. `INCONCLUSIVE` is retryable until the
attempt limit because external evidence or model execution can be unavailable. `CERTIFIED` and
`NOT_CERTIFIED` consume the signed `manifest_id` and cannot be evaluated again; `REVOKED` is also
terminal.

The stored levels are independent:

- `integrity_status`: whether exact response bytes were available and matched their digest;
- `authentication_status`: whether the signed manifest matched the package and an active trusted
  issuer key verified it;
- `license_status`: the bounded semantic compatibility result;
- `provenance_status`: whether the linked provenance evidence was complete;
- `status`/`verdict`: the final allowed outcome.

Revocation changes only lifecycle fields and preserves all evidence digests, signed identity fields,
level statuses, original verdict, and certification record. Issuer-key rotation/revocation affects
future evaluations; it does not rewrite historical certificates. There are no monetary transfers.
