# DatasetBond v2.1

DatasetBond is a reusable GenLayer Intelligent Contract for certifying whether one exact dataset,
license, and provenance evidence package satisfies a declared licensing/provenance use profile.
It is not generic dataset-quality scoring, a chatbot, or a frontend-computed verdict.

V2.1 adds a deployer-owned issuer trust root, registered/revoked/rotated secp256k1 keys, bounded
inline canonical signed evidence manifests anchored by their SHA-256 digest, expiry and single-use
nonce replay protection, exact byte/digest verification, and separate
integrity/authentication/license/provenance levels. The final semantic verdict remains only
`CERTIFIED`, `NOT_CERTIFIED`, or `INCONCLUSIVE`.

The certificate does not prove dataset factual correctness, legal ownership, legal enforceability,
absence of undisclosed source material, or permanent availability of external URLs. See
[`docs/SECURITY.md`](docs/SECURITY.md) and [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Repository map

- [`contracts/datasetbond.py`](contracts/datasetbond.py) - production contract.
- [`schema/datasetbond.schema.json`](schema/datasetbond.schema.json) - exact v2.1 API/storage schema.
- [`docs/`](docs) - architecture, schema, profiles, lifecycle, security, integration, limitations,
  and provenance.
- [`tests/direct/test_datasetbond.py`](tests/direct/test_datasetbond.py) - deterministic and
  consensus-shaped inline-manifest tests.
- [`tests/integration/test_datasetbond.py`](tests/integration/test_datasetbond.py) - Studio/gltest
  collection.
- [`tools/mutation_test.py`](tools/mutation_test.py) - critical-guard mutation gate.
- [`examples/integration.py`](examples/integration.py) - client-neutral call construction.
- [`tools/validate_inline_fixture.py`](tools/validate_inline_fixture.py) - read-only validator for
  the published self-owned demonstration package; it publishes no evidence and performs no chain
  write.

## Local verification

The checked environment uses GenLayer CLI `0.39.1`, `genvm-lint`, and `genlayer-test`. The repository
contains no deployment or broadcast step.

```powershell
$env:PYTHONUTF8 = "1"
python -m pytest
python tools/mutation_test.py
genvm-lint check contracts/datasetbond.py
genvm-lint validate contracts/datasetbond.py
genvm-lint schema --json contracts/datasetbond.py
python tools/extract_schema.py
python tools/validate_inline_fixture.py
python tools/secret_scan.py
python -m pip check
git diff --check
```

The fixture validator performs independent public URL fetches, exact-byte SHA-256 checks, provenance
linkage checks, and inline manifest signature verification. It requires network access but never
deploys or broadcasts. Studio integration is opt-in and requires a configured localnet or Studio:

```powershell
$env:DATASETBOND_RUN_INTEGRATION = "1"
gltest tests/integration/ -v -s
```

See [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for inline signed-manifest construction and
consumer acceptance rules.
