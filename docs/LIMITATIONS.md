# DatasetBond v2 limitations and non-claims

DatasetBond v2 improves authentication of signed evidence, but its trust model remains deliberately
narrow. It does not certify:

- dataset factual correctness, quality, completeness, representativeness, bias, or safety;
- legal ownership, legal enforceability, licensing authority, or legal identity of an issuer;
- absence of undisclosed source material, third-party rights, or personal data;
- that a trust-root key registry is an official publisher registry;
- that an immutable/content-addressed reference is hosted by an official source;
- that an ordinary HTTPS signed-manifest locator will remain available;
- that a valid signature means anything beyond control of the registered key over the exact manifest;
- that a semantic verdict is a legal opinion; or
- that `INCONCLUSIVE` means the license is incompatible.

The trust root authenticates an on-chain approval of an issuer identifier and public key. It does
not authenticate the real-world publisher. Governance must therefore choose and document how issuer
identifiers map to organizations, keys, and legal review outside the contract.

External evidence can be unavailable, mutate behind a locator, exceed bounded limits, or produce
validator disagreement. Dataset responses are limited to 1 MiB, licenses to 16 KiB, provenance
manifests to 32 KiB, and signed manifests to 16 KiB. Signatures expire after the configured maximum
lifetime and manifest IDs are single-use after terminal certification.
