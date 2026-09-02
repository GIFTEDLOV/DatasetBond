# DatasetBond v2.1

## Product

DatasetBond is a reusable GenLayer Intelligent Contract that certifies whether one exact dataset,
license, and provenance package satisfies a declared use profile. It is a contract primitive with
integration examples, not a chatbot, generic dataset-quality scorer, or frontend-computed verdict.

## Problem

Teams often make licensing decisions from mutable URLs, incomplete provenance, and claims that one
publisher or one AI provider supplied the right answer. Consumers need a bounded, inspectable record
of which bytes were reviewed, which issuer key signed the package, and what the evidence supports.

## Why GenLayer

Hashing and signature checks are deterministic, but a conventional contract cannot independently
retrieve license/provenance evidence and interpret its language. DatasetBond uses GenLayer's
validator-backed web and semantic boundary for that narrow interpretation. Validators may return only
`CERTIFIED`, `NOT_CERTIFIED`, or `INCONCLUSIVE`; the contract validates the result and stores the
state transition after consensus.

## How it works

1. The deployer is the immutable trust root and registers issuer verification keys.
2. A submitter registers exact HTTPS commit/content-addressed evidence references, their SHA-256
   digests, and a bounded inline canonical signed manifest.
3. Certification rechecks the manifest, issuer status, signature, expiry, nonce, exact evidence
   bytes, provenance shape, and profile-specific license meaning.
4. GenLayer consensus validates the bounded semantic result before the certificate is written.
5. Consumers accept only a certificate whose status, verdict, integrity, authentication, license, and
   provenance fields meet their policy.

## Architecture

- Audited readable source: [`contracts/datasetbond.py`](contracts/datasetbond.py).
- Exact compact deployment artifact: [`contracts/datasetbond_compact.py`](contracts/datasetbond_compact.py),
  deterministically generated from the readable source by [`tools/minify_contract.py`](tools/minify_contract.py).
- Machine-readable API/storage contract: [`schema/datasetbond.schema.json`](schema/datasetbond.schema.json).
- Reproducibility manifest: [`MANIFEST.sha256`](MANIFEST.sha256).
- CI quality gate: [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and [`docs/CI.md`](docs/CI.md).
- Release facts and live proof: [`release/datasetbond-bradbury.json`](release/datasetbond-bradbury.json),
  [`docs/RELEASE.md`](docs/RELEASE.md), and [`docs/BRADBURY-PROOF.md`](docs/BRADBURY-PROOF.md).

The readable source is the review source of truth. The compact artifact is the byte-identical
deployment target used because Bradbury rejected the larger source payload. The generator removes
non-authoritative comments/docstrings and one verified equivalent validation duplicate; the public
surface, GenVM dependency pin, executable AST, schema, and security mutation gate are checked.

## Use

Install the pinned development toolchain and run the offline release gate:

```bash
python -m pip install -r requirements-dev.txt
python tools/release_audit.py
python tools/source_hash.py --check
genvm-lint check contracts/datasetbond.py
genvm-lint validate contracts/datasetbond.py
genvm-lint check contracts/datasetbond_compact.py
genvm-lint validate contracts/datasetbond_compact.py
python -m pytest -q
python tools/mutation_test.py
python tools/mutation_test_compact.py
```

Build the call-shaped demonstration payload without signing, deploying, or broadcasting:

```bash
python examples/integration.py
```

The integration guide documents the exact 13-argument registration order and the required consumer
acceptance checks. Studio/localnet integration is opt-in:

```bash
DATASETBOND_RUN_INTEGRATION=1 gltest tests/integration/ -v -s
```

## Live proof

DatasetBond is deployed on GenLayer Bradbury (chain ID `4221`) at
`0xEdAbfD1BbC7F9979156391277FF7E1BB8e07B495`. The deployed compact artifact SHA-256 is
`146bea0d7be81aba5bef767decb2e3a838f7f1e4c29f4f14fc7530a1e36a979a`.

The recorded deployment, issuer registration, dataset registration, and certification transactions
all finalized with `AGREE` and `FINISHED_WITH_RETURN`. The live certificate is
`datasetbond-demo-observations` with verdict `CERTIFIED`, authentication `AUTHENTICATED`, integrity
`VERIFIED`, license `COMPATIBLE`, and provenance `COMPLETE`. See the full hashes and receipt facts in
[`docs/BRADBURY-PROOF.md`](docs/BRADBURY-PROOF.md).

## Security and trust model

DatasetBond uses a deployer-owned issuer trust root, registered/revoked/rotated low-`s` secp256k1
keys, canonical UTF-8 JSON, SHA-256 commitments, expiry and nonce replay protection, exact response
hashes, strict evidence bounds, prompt fencing, strict JSON output validation, post-consensus
revalidation, and submitter-only certificate revocation. Consensus proves agreement about
interpretation; it does not authenticate evidence. The evidence validator and semantic evaluator run
inside the contract boundary; the client cannot supply or override the verdict.

## Limitations

Cryptographic integrity proves exact bytes, not publisher authority, legal identity, legal ownership,
legal enforceability, factual correctness, absence of undisclosed sources, or permanent URL
availability. Trust-root governance is an external trust decision. Certification is not a legal
opinion. The pure-Python cryptographic verifier should receive independent security review before
high-value production use. See [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Developer/API detail

The contract exposes six writes (`register_issuer_key`, `revoke_issuer_key`, `rotate_issuer_key`,
`register_dataset`, `certify_dataset`, and `revoke_certificate`) and eight views. The exact argument
names, types, state fields, profiles, status enums, and canonical manifest rules are in
[`schema/datasetbond.schema.json`](schema/datasetbond.schema.json) and [`docs/SCHEMA.md`](docs/SCHEMA.md).
Provenance and architectural reuse are documented in [`docs/PROVENANCE.md`](docs/PROVENANCE.md).
