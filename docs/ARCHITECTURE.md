# DatasetBond architecture

## Product and trust problem

Dataset licenses are often evaluated against a moving URL, an unpinned repository branch, or a
human-readable claim that is not tied to the bytes reviewed. A consumer needs a small, reusable
primitive that answers a narrower question:

> Does this exact, committed evidence package satisfy the declared use profile?

DatasetBond binds a dataset reference, license reference, and provenance-manifest reference to
lowercase SHA-256 digests at registration. The contract later retrieves each reference, verifies
the HTTP response and exact bytes against the committed digest, checks the manifest's links, and
uses GenLayer validator judgement for the semantic license/provenance question.

This is a certification of evidence sufficiency for a profile. It is not a certification that the
dataset is factually correct, safe, unbiased, complete, or lawfully owned. Those claims require
additional evidence and are outside this primitive.

## Why GenLayer is necessary

An ordinary deterministic smart contract can store references and hashes, but it cannot natively
retrieve arbitrary web evidence or interpret license language and provenance records. A conventional
off-chain service could do both, but its verdict would be a server claim. GenLayer provides the
nondeterministic web and model boundary plus validator-backed equivalence so the state transition
is accepted only when validators independently reproduce the bounded result.

DatasetBond still keeps deterministic work in the contract:

1. Validate identifiers, URL scheme, immutability shape, digest syntax, profile, and bounds.
2. Store the evidence package exactly once for a unique `dataset_id`.
3. In each validator's nondeterministic execution, fetch all three references through
   `gl.nondet.web.request`, require HTTP 200 and a valid response shape, and hash exact response
   bytes with SHA-256.
4. Reject an unlinked, malformed, non-UTF-8, oversized, unavailable, or digest-mismatched
   license/manifest as `INCONCLUSIVE`.
5. Ask the model for only `{"verdict":"..."}` after the deterministic evidence gates pass.
6. Use `gl.vm.run_nondet` with a validator that independently repeats the complete evaluation and
   strictly compares the bounded result.
7. Revalidate the returned result before writing state.

## Trust boundary

The exact bytes are hashed before the license and manifest are shown to the model. Evidence text is
delimited and fence markers are neutralised in the prompt; instructions inside evidence are data,
not contract instructions. The model cannot select URLs, supply digests, set timestamps, set the
status, or write an explanation into authoritative state.

The dataset bytes are fetched and hashed but are not inserted into the prompt. License and
provenance content is sufficient for this primitive's declared question, while the dataset digest
binds the package to the exact dataset bytes. A consumer that needs content-level analysis should
build a separate, explicitly scoped primitive.

## Failure semantics

- Registration failures revert and write nothing.
- HTTP failure, malformed response, empty required text, oversized content, invalid UTF-8, digest
  mismatch, manifest contradiction, model exception, or malformed model output produces
  `INCONCLUSIVE` if both sides reach the same result.
- A validator that sees a different package result causes nondeterministic consensus to fail; it
  does not turn disagreement into a positive certificate.
- `INCONCLUSIVE` may be retried. `CERTIFIED` and `NOT_CERTIFIED` are terminal evaluations, and
  `REVOKED` is terminal.
