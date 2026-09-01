# Provenance of reused patterns

DatasetBond v2.1 is an in-place hardening of commit `7b6aec675bdcacad24e562cc06bf9b66ce27959e`.
The existing DatasetBond architecture, bounded verdict model, evidence-fetch boundary, and
submitter-only certificate revocation were preserved. The signed manifest is now supplied inline
and anchored by its canonical digest; no new external manifest file is required. No source file was
copied from another workspace, and Aegis, NimbusPact, and other repositories were not modified.

The implementation patterns were informed by:

- GenLayer's official project boilerplate and API guidance for `gl.public.view/write`,
  `gl.nondet.web.request`, JSON-mode `gl.nondet.exec_prompt`, `gl.vm.run_nondet`, and direct
  `gltest` usage. See the [official boilerplate](https://github.com/genlayerlabs/genlayer-project-boilerplate)
  and its [API notes](https://github.com/genlayerlabs/genlayer-project-boilerplate/blob/main/CLAUDE.md).
- The local source-consensus reference for deterministic validation, transaction timestamps,
  strict post-consensus validation, and bounded model output. It was inspected read-only.
- The local NimbusPact reference for response-shape checks and exact response hashing. It was
  inspected read-only.
- The local PatchBond reference for explicit access control, mutation gates, and no-transfer scope.
  It was inspected read-only.

The installed GenVM runner bundle was inspected directly. It provides deterministic integer
arithmetic, SHA-256 through the standard runtime, and Keccak, but no built-in ECDSA/Ed25519 verifier
and no approved host crypto dependency for contract use. DatasetBond therefore implements the
documented pure-Python secp256k1 verifier inside the contract; test-only signing uses the client
environment's `eth_keys` package and never enters the contract source.

The installed environment reported GenLayer CLI `0.39.1`, `genlayer-test` `0.29.2`, and
`genvm-linter` `0.10.0`. The contract remains pinned to the existing `py-genlayer` runner header;
verification must be repeated if that runner or CLI is upgraded.

These references describe API/design provenance only. They are not claims that DatasetBond inherits
the other projects' semantics or security guarantees.
