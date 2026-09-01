# DatasetBond v2.1 limitations and non-claims

DatasetBond v2.1 improves authentication of signed evidence, but its trust model remains deliberately
narrow. It does not certify:

- dataset factual correctness, quality, completeness, representativeness, bias, or safety;
- legal ownership, legal enforceability, licensing authority, or legal identity of an issuer;
- absence of undisclosed source material, third-party rights, or personal data;
- that a trust-root key registry is an official publisher registry;
- that an immutable/content-addressed reference is hosted by an official source;
- that a valid signature means anything beyond control of the registered key over the exact manifest;
- that a semantic verdict is a legal opinion; or
- that `INCONCLUSIVE` means the license is incompatible.

The trust root authenticates an on-chain approval of an issuer identifier and public key. It does
not authenticate the real-world publisher. Governance must therefore choose and document how issuer
identifiers map to organizations, keys, and legal review outside the contract.

External dataset/license/provenance evidence can be unavailable, mutate behind a locator, exceed
bounded limits, or produce validator disagreement. The inline signed manifest is capped at 16 KiB;
dataset responses are limited to 1 MiB, licenses to 16 KiB, and provenance manifests to 32 KiB.
The raw inline manifest is not stored, only its digest and bounded signed fields. Signatures expire
after the configured maximum lifetime and nonces are single-use after terminal certification.
Inline anchoring removes the need to publish a signed manifest, but it does not make the three
underlying evidence URLs permanently available or authenticate their hosts.
