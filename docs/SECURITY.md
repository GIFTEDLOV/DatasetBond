# Security model and limitations

## Integrity versus authority

DatasetBond proves an integrity statement: at evaluation time a supported GenLayer web request
returned HTTP 200 bytes whose SHA-256 matched the digest registered for that reference. The
content-addressed or commit-pinned reference proves which location/version was requested.

That is not an authority statement. SHA-256 does not prove that a publisher authored the bytes,
that a submitter has rights to the dataset, or that the URL is an official canonical source.
Consumers must select authoritative/canonical license sources and document immutable publisher or
registry sources. DatasetBond never treats validator consensus as authentication of the evidence.

## Security properties

- No frontend computes or submits the verdict.
- Registration rejects mutable references, unsupported schemes, credentials, query/fragment
  ambiguity, malformed digests, duplicate IDs, and oversized fields.
- All three references are retrieved only through `gl.nondet.web.request`; response status, body
  type, byte limit, UTF-8 requirements, and exact SHA-256 are checked.
- Dataset bytes are hashed as bytes; license and manifest bytes are hashed before decoding or
  prompt sanitisation.
- The manifest must exactly link the registered dataset and license references/digests.
- Evidence text is untrusted prompt data and cannot change the declared profile or contract state.
- `gl.vm.run_nondet` validates the complete evidence fetch, manifest gate, model call, and bounded
  result independently on a validator.
- A second deterministic result-validation gate runs before storage.
- No model explanation, confidence, score, authority claim, or factual-quality claim is stored.
- Revocation is submitter-only, certified-only, bounded, and history-preserving.
- There are no transfers, payable methods, admin keys, or hidden recovery paths.

## Known limitations

- A validator-backed semantic verdict is not a legal opinion. License language can be jurisdiction-
  specific, ambiguous, or inconsistent with external terms.
- A submitter can register an immutable copy from an unauthoritative source. The contract preserves
  integrity of that copy but cannot authenticate the publisher.
- If validators cannot obtain equivalent web/model results, the transaction can fail consensus and
  must be retried; the contract never guesses a positive result.
- `INCONCLUSIVE` is the only answer for unavailable or insufficient evidence. It is not evidence
  that the profile is violated.
- The dataset response is bounded at 1 MiB. Larger datasets must be represented by a smaller,
  immutable package or a separate content-addressed digest workflow.
- The license and manifest prompt is bounded. Oversized content is `INCONCLUSIVE`, not truncated
  into a misleading certification.
- The manifest fields are claims supplied by the evidence package. Their presence is checked;
  their real-world truth is not independently authenticated.
- Certification does not prove dataset facts, labels, safety, bias, completeness, provenance truth,
  ownership, or absence of personal data unless the committed evidence explicitly supports that
  narrower claim and the profile is extended accordingly.
