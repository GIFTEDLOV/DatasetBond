# DatasetBond v2.1 release record

This is the release-freeze record for the deployed DatasetBond Intelligent Contract. It separates
the reviewed source from the smaller artifact required by Bradbury's pubdata limit and binds both to
machine-readable release metadata in [`../release/datasetbond-bradbury.json`](../release/datasetbond-bradbury.json).

## Release identity

| Field | Value |
| --- | --- |
| Repository | [`GIFTEDLOV/DatasetBond`](https://github.com/GIFTEDLOV/DatasetBond) |
| Track | Intelligent Contract |
| Contract version | `2.1.0` |
| Contract-release commit | `63652bf81c4a11b054cd58e18823fc0f455b3bc2` |
| Network | GenLayer Bradbury, chain ID `4221` |
| Contract address | `0xEdAbfD1BbC7F9979156391277FF7E1BB8e07B495` |
| Audited source | `contracts/datasetbond.py` · 56,187 bytes · `54c670e65bbde020bc34675814ad71cc808a9dd5b4d1c03365748fd77a843040` |
| Deployed artifact | `contracts/datasetbond_compact.py` · 47,291 bytes · `146bea0d7be81aba5bef767decb2e3a838f7f1e4c29f4f14fc7530a1e36a979a` |
| Public surface | 14 methods: 8 views, 6 writes |

The compact artifact is generated from the readable source. The generator preserves the GenVM
dependency header and executable AST, and the release audit requires deterministic regeneration,
matching public signatures, matching schema surface, and matching recorded SHA-256 values. No
contract bytes were changed after the live deployment.

## Live transaction proof

All four successful transactions reached `FINALIZED / AGREE / FINISHED_WITH_RETURN`:

| Operation | Transaction |
| --- | --- |
| Deployment | `0xad87b5a79c3b41d047f9060eb63d605d1b8309d93e2d7142bfb2f46e2581f279` |
| Issuer registration | `0xa37aff970ec06dc02a252c6a898508adb0339a5461c9ce115bfb76f856dfe0bf` |
| Dataset registration | `0xf6d52709016200bba23407444ce1f2d02be38fb916e8bd00ab4b8bb9494bb673` |
| Certification | `0xd847ea9c66f197babdb016bc8b121b2f8774d463dd0dac9f6bfa3c06eb902330` |

The final certification execution hash was
`0x1f2f23d3e704ef24639d2db208e988101da307e96b4b2f4e173c2c24290e4c62`.

The resulting certificate `datasetbond-demo-observations` was `CERTIFIED` with
`AUTHENTICATED`, `VERIFIED`, `COMPATIBLE`, and `COMPLETE` level statuses. The stored dataset,
license, provenance, and inline-manifest digests are recorded in the public proof document.

## Validation classes

- Live-proven: deployment, issuer registration, dataset registration, certification, finality,
  successful execution, and expected certificate readback.
- Direct/consensus-shaped: deterministic guards, evidence admissibility, signature verification,
  trust-root authorization, replay protection, strict model output, and lifecycle transitions.
- Not live-proven: issuer revocation/rotation and certificate revocation. These are implemented and
  tested, but were deliberately not added to the representative live proof.

The failed registration attempts are retained in [`BRADBURY-PROOF.md`](BRADBURY-PROOF.md) with their
reasons. They are not hidden or reclassified as successful evidence.

## Reproduce the release gate

```bash
python -m pip install -r requirements-dev.txt
python tools/check_line_endings.py
python tools/source_hash.py --check
python tools/release_audit.py
python tools/extract_schema.py
genvm-lint check contracts/datasetbond.py
genvm-lint validate contracts/datasetbond.py
genvm-lint check contracts/datasetbond_compact.py
genvm-lint validate contracts/datasetbond_compact.py
python -m pytest -q
python tools/mutation_test.py
python tools/mutation_test_compact.py
python tools/secret_scan.py
python -m pip check
git diff --check
```

The online fixture validator is separate because it reads the public GitHub raw URLs:

```bash
python tools/validate_inline_fixture.py
```

No release command deploys or broadcasts. A live write must follow the documented
precondition-read, single-broadcast, immediate-hash-persistence, same-hash reconciliation, finality,
execution, and state-readback sequence.
