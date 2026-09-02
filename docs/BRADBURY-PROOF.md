# DatasetBond controlled Bradbury proof

This document records one controlled live proof of the self-owned DatasetBond demonstration package.
It is evidence of the deployed contract path and its bounded certification behavior. It is not a
claim of independent legal ownership, publisher authority, dataset factual correctness, legal
enforceability, or permanent availability of external URLs.

## Network and contract

- Network: GenLayer Bradbury
- Chain ID: `4221`
- Contract: `0xEdAbfD1BbC7F9979156391277FF7E1BB8e07B495`
- Deployed compact artifact SHA-256:
  `146bea0d7be81aba5bef767decb2e3a838f7f1e4c29f4f14fc7530a1e36a979a`

## Transactions

| Operation | Transaction hash |
| --- | --- |
| Deployment | `0xad87b5a79c3b41d047f9060eb63d605d1b8309d93e2d7142bfb2f46e2581f279` |
| Issuer registration | `0xa37aff970ec06dc02a252c6a898508adb0339a5461c9ce115bfb76f856dfe0bf` |
| Dataset registration | `0xf6d52709016200bba23407444ce1f2d02be38fb916e8bd00ab4b8bb9494bb673` |
| Certification | `0xd847ea9c66f197babdb016bc8b121b2f8774d463dd0dac9f6bfa3c06eb902330` |

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

The stored certificate contains the exact registered evidence references and digests, the authenticated
issuer/key identity, the declared `RESEARCH_EVALUATION` profile, and the signed manifest digest.

## Trust and scope

The deployer-owned trust root approved issuer `datasetbond-demo` and key ID
`datasetbond-demo-key-2026-a`. This authenticates the on-chain issuer/key mapping and control of the
registered signing key. It does not prove that the issuer is a legal identity, owns the dataset, or
has authority to license it.

No private keys or secrets were published. The limitations in
[`LIMITATIONS.md`](LIMITATIONS.md) and [`SECURITY.md`](SECURITY.md) remain applicable.
