# Self-owned demonstration publication

This package is a DatasetBond-project-owned demonstration fixture for integration verification. It
is not third-party evidence and is not a claim of independent legal ownership or publisher
authority. The three objects deliberately use three immutable commits: dataset and license first,
provenance second, and the package/integration documentation third. This avoids the impossible
self-reference that would be required for a provenance file to contain the hash of the commit that
defines that same file.

## Immutable evidence

| Object | Commit | Public URL | HTTP status | Exact bytes | SHA-256 |
| --- | --- | --- | ---: | ---: | --- |
| Dataset JSON | `ac2cd29483d78adffc299f25c92702d6ffd05708` | `https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/ac2cd29483d78adffc299f25c92702d6ffd05708/examples/public-fixture/dataset.json` | 200 | 705 | `7b24103a164674959d071b3e69baa2c194e4f24fdd373a5ea8a1e6f430d5eb12` |
| MIT license | `ac2cd29483d78adffc299f25c92702d6ffd05708` | `https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/ac2cd29483d78adffc299f25c92702d6ffd05708/examples/public-fixture/LICENSE.txt` | 200 | 1076 | `8e28e056d91dbb82759a8e1b50ae0b81a07ddb3c2ee01e4592d38f9181a9881e` |
| Provenance JSON | `52f5b0c82a2e305b5e607818e69e5acc1ff063d5` | `https://raw.githubusercontent.com/GIFTEDLOV/DatasetBond/52f5b0c82a2e305b5e607818e69e5acc1ff063d5/examples/public-fixture/provenance.json` | 200 | 1024 | `179a3e8edb8ea41b2cc974e000a520a95f2d8bb1332fdc62dfacbcf5492a8479` |

The license is the actual MIT license text in the fixture. It grants broad permission for this
self-owned demonstration package but does not itself prove legal ownership or the authority of any
third party.

## Inline authentication

The package uses issuer `datasetbond-demo`, key ID `datasetbond-demo-key-2026-a`, and public
secp256k1 key:

```text
ec754b5dfd1c4678e36526ab729d8996eb1eecf344dc5e019c9352b5764e38096654c23b3876dc1f1e4572bc31c7713162f9f3324f6ffdd66dd00ae9e8cbbbe1
```

The canonical signed inline manifest has SHA-256:

```text
a94a015b30697f8cea2536703b7b9790fc219c8fe94795484f27f0b11caa28c7
```

The private signing key was generated and used locally in memory for this package and was not
printed, persisted, committed, or published. A deployed trust root must register the public key
before certification. Key registration authenticates only the deployer's approval of the issuer/key
mapping and control of that key; it does not prove legal ownership or publisher authority.

Run `python tools/validate_inline_fixture.py` to independently repeat the URL, byte, provenance,
and signature checks. No fixture file is created by the validator.
