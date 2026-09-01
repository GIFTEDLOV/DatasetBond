# DatasetBond

DatasetBond is a reusable GenLayer Intelligent Contract primitive for certifying whether an exact,
committed dataset evidence package satisfies a declared licensing and provenance profile.

It is deliberately not a dataset-quality score, chatbot, storage service, or frontend verdict. The
contract registers three immutable HTTPS references and their SHA-256 digests, retrieves and verifies
the exact bytes inside the GenLayer nondeterministic boundary, and asks validators for one bounded
semantic verdict:

`CERTIFIED | NOT_CERTIFIED | INCONCLUSIVE`

`CERTIFIED` requires evidence that explicitly supports the selected use profile. Missing,
unavailable, contradictory, unauthenticated, or digest-mismatched evidence is fail-closed and does
not become a positive result.

## Repository map

- [`contracts/datasetbond.py`](contracts/datasetbond.py) — production contract.
- [`schema/datasetbond.schema.json`](schema/datasetbond.schema.json) — exact public/input/storage schema.
- [`tests/direct/test_datasetbond.py`](tests/direct/test_datasetbond.py) — deterministic and consensus-shaped tests.
- [`tests/integration/test_datasetbond.py`](tests/integration/test_datasetbond.py) — Studio/gltest collection.
- [`tools/mutation_test.py`](tools/mutation_test.py) — critical-guard mutation gate.
- [`examples/integration.py`](examples/integration.py) — client-side call construction and read handling.
- [`docs/`](docs) — trust model, profiles, lifecycle, integration, limitations, and provenance.

## Local verification

The installed toolchain used for this deliverable is GenLayer CLI `0.39.1`, `genvm-lint`, and
`genlayer-test`. The repository intentionally contains no deployment or broadcast step.

```powershell
$env:PYTHONUTF8 = "1"
python -m pytest
python tools/mutation_test.py
genvm-lint check contracts/datasetbond.py
genvm-lint validate contracts/datasetbond.py
genvm-lint schema --json contracts/datasetbond.py
python tools/extract_schema.py
python tools/secret_scan.py
python -m pip check
git diff --check
```

Studio integration collection (requires a separately configured localnet or Studio; it is not run
by the offline verification above):

```powershell
$env:DATASETBOND_RUN_INTEGRATION = "1"
gltest tests/integration/ -v -s
```

See [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for the call contract and the operational rule
that a certificate is not publisher authentication or proof that the dataset is factually correct.
