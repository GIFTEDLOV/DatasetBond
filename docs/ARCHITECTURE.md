# DatasetBond v2.1 architecture

## Product and trust problem

Dataset licenses are often evaluated against moving URLs or human-readable claims that are not tied
to the exact bytes reviewed. DatasetBond answers one narrower question:

> Does this exact, committed evidence package satisfy the declared use profile?

Version 2.1 adds a signed inline evidence manifest and a deployer-controlled issuer trust root. It separates
what the contract can verify from what it cannot claim: byte integrity, key authentication, license
compatibility, provenance completeness, and final certification are stored as separate levels.

## Why GenLayer is necessary

An ordinary deterministic contract can store hashes and signatures, but it cannot natively retrieve
arbitrary web evidence or interpret license language and provenance records. GenLayer supplies the
nondeterministic web/model boundary and validator-backed equivalence. DatasetBond keeps every state
write after consensus and asks validators only for a bounded semantic verdict.

The supported flow is:

1. The deployer becomes the trust root and registers issuer verification keys.
2. A submitter supplies one bounded canonical JSON manifest inline with exact dataset/license/
   provenance references and their digests. Registration parses it, rejects unknown/missing fields,
   checks its complete SHA-256, and binds every field to the registration arguments.
3. Certification reconstructs the anchored canonical manifest, checks its digest, validity window,
   issuer key status, nonce replay map, and low-s ECDSA signature before any semantic work.
4. Validators fetch only the dataset, license, and provenance manifest, require HTTP 200 byte bodies,
   size bounds, UTF-8 where required, exact SHA-256, and a complete linked provenance shape.
5. `gl.nondet.exec_prompt(..., response_format="json")` receives only license/provenance evidence
   and may return exactly `CERTIFIED`, `NOT_CERTIFIED`, or `INCONCLUSIVE`.
6. `gl.vm.run_nondet` reruns the complete bounded evaluation on a validator and the deterministic
   path revalidates all five result fields before storing state.

## Cryptographic boundary

The installed runner provides deterministic integer arithmetic and SHA-256, but no built-in
signature verifier. The contract therefore contains a small pure-Python secp256k1 verifier. It uses
the standard curve constants, validates the public point, validates `r`/`s` ranges and low-`s`,
hashes the canonical unsigned manifest with SHA-256, and checks ECDSA verification. No
`cryptography`, `nacl`, `eth_keys`, or host-only dependency is imported by the contract.

The trust root authenticates that a particular public key was registered for an issuer identifier
and is currently active. A valid signature authenticates control of that key over these exact
manifest fields. Neither assertion proves that the issuer is the legal publisher, owns the
dataset, has authority to license it, or that the license is enforceable.

## Authority versus integrity

The three evidence references must be content-addressed or commit-pinned HTTPS references. The
signed manifest has no external locator: its canonical UTF-8 bytes are supplied at registration and
anchored by `evidence_manifest_sha256`. The contract stores the digest and bounded signed fields,
then reconstructs the exact canonical object for certification. Neither an HTTPS URL nor SHA-256 is
publisher authentication. The trust root and issuer registry are the additional authentication
authority, and their scope is deliberately narrow.

## Failure semantics

- Registration validates only deterministic fields and never performs web or model work.
- A malformed, non-canonical, digest-mismatched, or argument-mismatched inline manifest is rejected
  at registration; a later digest/canonical reconstruction failure is an authentication failure.
- An unregistered, revoked, rotated, expired, replayed, malformed, non-canonical, or incorrectly
  signed manifest is recorded as an authentication failure and yields `INCONCLUSIVE`.
- Dataset/license/provenance availability and digest failures remain distinct from authentication.
- A malformed or incomplete provenance manifest yields `INCONCLUSIVE`; it is not silently repaired.
- A validator disagreement fails consensus; it does not produce a positive certificate.
- `INCONCLUSIVE` may be retried up to the bounded attempt limit. `CERTIFIED`, `NOT_CERTIFIED`, and
  `REVOKED` are terminal for that certificate.
