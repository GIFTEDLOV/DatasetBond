# DatasetBond v2 security model

## Exact cryptographic model

DatasetBond v2 uses `SECP256K1_ECDSA_SHA256`:

- issuer public keys are uncompressed secp256k1 `x||y`, 64 bytes / 128 lowercase hex characters;
- signatures are low-`s` ECDSA `r||s`, 64 bytes / 128 lowercase hex characters;
- the signed message is canonical UTF-8 JSON containing every manifest field except `signature`;
- the signature hash is SHA-256 of those canonical unsigned bytes;
- the complete canonical signed-manifest bytes are separately SHA-256 checked against the registered
  `evidence_manifest_sha256`.

The verifier is implemented inside the contract with curve constants, point validation, bounded
double-and-add scalar multiplication, modular arithmetic, SHA-256, and no external crypto import.
This is a genuine cryptographic verification path in the installed GenVM runner, not a signature
field check or a host-side dependency.

## Trust root and issuer scope

The deployer is recorded as `trust_root`. Only that address can register, revoke, or rotate issuer
keys. The registry authenticates that a specific public key was approved for an issuer identifier
and is active at evaluation time. It does not authenticate the issuer's legal identity, ownership,
rights, authorization, legal enforceability, or publisher status in the real world.

Rotation marks the old key `ROTATED` and creates a new `ACTIVE` successor. Revocation marks a key
`REVOKED`. Existing certificates preserve their historical authentication result; future
certification attempts using those keys become `INCONCLUSIVE`.

## Integrity and availability

- Dataset, license, and referenced provenance URLs must be HTTPS content-addressed or commit-pinned
  references. Ordinary HTTPS URLs are not called immutable.
- The signed-manifest URL is a credential-free HTTPS locator. Its bytes are still exact-digest
  checked and its content must be signed; the locator itself is not permanent.
- All retrieval uses supported `gl.nondet.web.request` and requires HTTP 200 plus a byte response.
- Oversized, malformed, unavailable, or digest-mismatched responses fail closed.
- `UNAVAILABLE`, `INVALID_RESPONSE`, and `DIGEST_MISMATCH` remain distinct integrity outcomes.
- A valid digest proves byte equality, not publisher authenticity.

## Consensus and semantic boundary

- Signed-manifest authentication happens before semantic evaluation.
- Validators independently execute the same bounded evidence fetch, signature check, provenance
  gate, and JSON-only model call inside nondeterministic evaluation.
- The only model output accepted is exactly `{"verdict":"CERTIFIED|NOT_CERTIFIED|INCONCLUSIVE"}`.
- Storage writes happen only after `gl.vm.run_nondet` and deterministic five-field result validation.
- No frontend/backend computes or overrides the verdict, and no explanation, score, or confidence is
  authoritative state.
- Validator consensus is not authentication of evidence; it only establishes agreement about the
  bounded evaluation.

## Explicit non-claims

Every returned certificate includes a fixed scope statement. DatasetBond does not prove dataset
factual correctness, legal ownership, legal enforceability, absence of undisclosed source material,
or permanent availability of external URLs.
