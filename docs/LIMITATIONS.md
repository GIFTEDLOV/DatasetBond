# Limitations and non-claims

DatasetBond certifies only the narrow question encoded by its declared profile and the exact
evidence bytes that validators could verify. It does not certify:

- factual correctness, quality, completeness, representativeness, bias, or safety of the dataset;
- ownership, identity, authorization, or legal standing of the publisher or submitter;
- that an immutable URL is an official source merely because it is immutable;
- that consensus authenticates evidence or converts an untrusted manifest field into a verified
  identity;
- that a `NOT_CERTIFIED` result is a legal determination when license language is ambiguous; or
- that an `INCONCLUSIVE` result means the package is incompatible.

The contract intentionally returns `INCONCLUSIVE` when evidence is missing, unavailable,
contradictory, unauthenticated, oversized, malformed, or digest-mismatched. Consumers should keep
their own legal, publisher, privacy, and dataset-quality review processes alongside this primitive.
