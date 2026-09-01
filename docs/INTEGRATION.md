# Integration guide

## Registration payload

An integrator first obtains exact bytes from an authoritative, immutable source, computes lowercase
SHA-256 off-chain, and submits the following argument order to `register_dataset`:

```json
[
  "demo-dataset-1",
  "https://raw.githubusercontent.com/acme/datasets/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/data.csv",
  "<sha256 of exact dataset bytes>",
  "https://raw.githubusercontent.com/spdx/license-list-data/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/licenses/MIT.json",
  "<sha256 of exact license bytes>",
  "https://raw.githubusercontent.com/acme/provenance/cccccccccccccccccccccccccccccccccccccccc/manifests/demo.json",
  "<sha256 of exact manifest bytes>",
  "MODEL_TRAINING"
]
```

The example references are shape examples only; they are not a claim that those placeholder commits
or paths exist. Use a real commit/content identifier and record the byte hashes next to the
submission in the integrator's audit trail.

## Call flow

```text
client -> register_dataset(package) -> dataset_id
client -> certify_dataset(dataset_id) -> Certificate
client -> get_certificate(dataset_id) -> status/verdict/record
submitter -> revoke_certificate(dataset_id, bounded_reason) -> REVOKED
```

`certify_dataset` can be requested by any caller, but the result is computed from the immutable
package and validator-backed evidence. Only the registration submitter can revoke a `CERTIFIED`
certificate. A caller should branch on `status`/`verdict`, not on a non-empty record.

## Example adapter

[`examples/integration.py`](../examples/integration.py) builds client-neutral method payloads and
shows how to validate the returned certificate. It does not connect to a network, sign a
transaction, deploy, or broadcast. A production client should use the supported GenLayer client
for the selected environment and pass these exact method names/argument order.

## Recommended consumer policy

1. Pin the contract address and deployment source hash through the consumer's normal release
   process.
2. Select canonical license authority and a publisher-controlled immutable manifest source.
3. Store the registration arguments and returned `certification_record` in the consumer audit log.
4. Accept only `CERTIFIED` for the exact declared profile; treat `INCONCLUSIVE` as pending, not as
   approval or rejection.
5. Treat `REVOKED` as no longer live while retaining the original record for audit.
6. Do not describe a certificate as proof that the dataset is factually correct or publisher-
   authenticated.
