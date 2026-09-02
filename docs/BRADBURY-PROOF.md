# DatasetBond controlled Bradbury proof

This document records one controlled live proof of the self-owned DatasetBond demonstration package.
It is evidence of the deployed contract path and its bounded certification behavior. It is not a
claim of independent legal ownership, publisher authority, dataset factual correctness, legal
enforceability, or permanent availability of external URLs.

## Network and contract

- Network: GenLayer Bradbury
- Chain ID: `4221`
- Contract: `0xEdAbfD1BbC7F9979156391277FF7E1BB8e07B495`
- Audited source commit: `63652bf81c4a11b054cd58e18823fc0f455b3bc2`
- Audited source SHA-256: `54c670e65bbde020bc34675814ad71cc808a9dd5b4d1c03365748fd77a843040`
- Deployed compact artifact SHA-256:
  `146bea0d7be81aba5bef767decb2e3a838f7f1e4c29f4f14fc7530a1e36a979a`
- The compact artifact is the deployment target; the readable source remains the review source of truth.

## Transactions

| Operation | Transaction hash | Final receipt |
| --- | --- | --- |
| Deployment | `0xad87b5a79c3b41d047f9060eb63d605d1b8309d93e2d7142bfb2f46e2581f279` | `FINALIZED / AGREE / FINISHED_WITH_RETURN` |
| Issuer registration | `0xa37aff970ec06dc02a252c6a898508adb0339a5461c9ce115bfb76f856dfe0bf` | `FINALIZED / AGREE / FINISHED_WITH_RETURN` |
| Dataset registration | `0xf6d52709016200bba23407444ce1f2d02be38fb916e8bd00ab4b8bb9494bb673` | `FINALIZED / AGREE / FINISHED_WITH_RETURN` |
| Certification | `0xd847ea9c66f197babdb016bc8b121b2f8774d463dd0dac9f6bfa3c06eb902330` | `FINALIZED / AGREE / FINISHED_WITH_RETURN` |

The certification execution hash was
`0x1f2f23d3e704ef24639d2db208e988101da307e96b4b2f4e173c2c24290e4c62`.

The certification receipt reached `FINALIZED / AGREE / FINISHED_WITH_RETURN`.

## Certificate result

- Certificate: `datasetbond-demo-observations`
- Verdict: `CERTIFIED`
- Authentication: `AUTHENTICATED`
- Integrity: `VERIFIED`
- License: `COMPATIBLE`
- Provenance: `COMPLETE`
- Attempts: `1`
- Evidence manifest SHA-256: `a94a015b30697f8cea2536703b7b9790fc219c8fe94795484f27f0b11caa28c7`
- Dataset SHA-256: `7b24103a164674959d071b3e69baa2c194e4f24fdd373a5ea8a1e6f430d5eb12`
- License SHA-256: `8e28e056d91dbb82759a8e1b50ae0b81a07ddb3c2ee01e4592d38f9181a9881e`
- Provenance SHA-256: `179a3e8edb8ea41b2cc974e000a520a95f2d8bb1332fdc62dfacbcf5492a8479`

The stored certificate contains the exact registered evidence references and digests, the authenticated
issuer/key identity, the declared `RESEARCH_EVALUATION` profile, and the signed manifest digest.

## Trust and scope

The deployer-owned trust root approved issuer `datasetbond-demo` and key ID
`datasetbond-demo-key-2026-a`. This authenticates the on-chain issuer/key mapping and control of the
registered signing key. It does not prove that the issuer is a legal identity, owns the dataset, or
has authority to license it.

No private keys or secrets were published. The limitations in
[`LIMITATIONS.md`](LIMITATIONS.md) and [`SECURITY.md`](SECURITY.md) remain applicable.

## Proof coverage

| Coverage class | Proven behavior |
| --- | --- |
| Live Bradbury | Deployment, trust-root issuer registration, one dataset registration, and one successful certification with finalized state readback. |
| Direct/consensus-shaped tests | Validation, signatures, replay protection, authorization, malformed evidence/model output, state transitions, and critical guard mutations. |
| Not live-proven | Certificate revocation, issuer revocation, and issuer rotation were not submitted in the recorded proof; they remain covered by automated tests and documented integration calls. |

Two earlier finalized failed registration attempts remain part of the provenance record: one rejected a
double-encoded manifest (`0xce404ea3f38a535b25f2411e4ed66503b15cf9c2838b510b01a57d3f3968a1f3`), and one
rejected an obsolete 15-argument payload (`0x19843a2f5d7c40f1b86d81f059cecac200e9d440b5e890a33fbd2325fa7df6c4`).
Neither changed certificate state. No blind rebroadcast was used.
