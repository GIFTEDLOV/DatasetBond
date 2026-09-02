# DatasetBond CI

The workflow in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) is a repository-quality
gate. It never deploys, broadcasts, changes environment variables, or reads private keys.

## Checks

Every push, pull request, and manual workflow run performs:

- LF line-ending and whitespace checks;
- the raw-byte reproducibility manifest check;
- readable-source, compact-artifact, schema, fixture, and Bradbury-proof parity;
- deterministic compact-artifact regeneration with a clean-diff requirement;
- GenVM lint and semantic validation for both contract artifacts;
- direct and release-consistency tests;
- readable and compact critical-guard mutation gates;
- public fixture URL, digest, provenance, and signature validation;
- secret scanning and dependency health.

The integration collection is intentionally not run against Bradbury in CI. It requires an explicit
local Studio/localnet configuration and is opt-in:

```bash
DATASETBOND_RUN_INTEGRATION=1 gltest tests/integration/ -v -s
```

## Pins

The release gate uses Python 3.12, `genlayer-test==0.29.2`, `genvm-linter==0.11.0`,
`pytest==8.3.4`, and `eth-keys==0.5.1`. The live Bradbury proof predates this clean CI gate and
used the cached `genvm-linter==0.10.0` environment. Direct tests explicitly use GenVM `v0.2.12`,
whose published `genvm-universal.tar.xz` archive is required by `gltest`; this avoids relying on a
moving latest-release endpoint. The contract runner pin remains in the first line of each contract
artifact and is checked for parity.

## Local release command

Run the same sequence from [`RELEASE.md`](RELEASE.md) before publishing a repository change. A
passing CI run proves repository consistency and test coverage; it does not replace finality,
execution, and state-readback evidence for a live transaction.
