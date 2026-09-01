# Provenance of reused patterns

DatasetBond is new code in this repository. No source file was copied from another workspace. The
following references informed the implementation patterns:

- GenLayer's official project boilerplate and current API guidance: `gl.public.view/write`,
  `gl.nondet.web.request`, JSON-mode `gl.nondet.exec_prompt`, `gl.vm.run_nondet`, direct `gltest`
  mocks, and Studio integration collection. See the [official boilerplate](https://github.com/genlayerlabs/genlayer-project-boilerplate)
  and its [API notes](https://github.com/genlayerlabs/genlayer-project-boilerplate/blob/main/CLAUDE.md).
- The local `source-consensus` reference informed the discipline of deterministic validation,
  transaction-message timestamps, strict post-consensus revalidation, bounded model output, and
  retryable unavailable evaluation. It was inspected read-only at
  `C:\Users\DELL\source-consensus`.
- The local `NimbusPact` reference informed checking HTTP status/body shape and hashing exact
  response evidence. It was inspected read-only at `C:\Users\DELL\NimbusPact`.
- The local `PatchBond` reference informed keeping access control, mutation gates, and no-transfer
  scope explicit. It was inspected read-only at `C:\Users\DELL\PatchBond`.

The installed environment reported GenLayer CLI `0.39.1`. The contract dependency header uses the
same pinned `py-genlayer` runner identifier used by the installed local GenLayer test corpus; the
repository's verification commands must be rerun if that runner or the CLI is upgraded.

These are design and API provenance references, not claims that DatasetBond inherits their product
semantics or security guarantees.
