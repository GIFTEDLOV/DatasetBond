"""Mutation gate for DatasetBond's load-bearing security checks.

Each mutation removes one guard from the source text. The gate must identify the missing guard;
the behavioral direct tests then demonstrate the corresponding failure mode end-to-end. This is
intentionally conservative: a renamed or removed guard fails the gate instead of silently making
the security test decorative.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "contracts" / "datasetbond.py"


@dataclass(frozen=True)
class Mutation:
    name: str
    anchor: str


MUTATIONS = (
    Mutation("https-only", 'if not reference.startswith("https://"):'),
    Mutation("immutable-reference", "if not _is_immutable_reference(reference):"),
    Mutation("exact-http-status", "if type(status) is not int or isinstance(status, bool) or status != 200:"),
    Mutation("exact-digest", "if _sha256(raw) != expected_digest:"),
    Mutation("inline-manifest-digest-binding", "if _sha256(canonical_bytes) != evidence_manifest_digest:"),
    Mutation("inline-manifest-structure", "if not isinstance(manifest, dict) or set(manifest.keys()) != _SIGNED_MANIFEST_FIELDS:"),
    Mutation("response-size-bound", "if len(raw) > max_bytes or (not allow_empty and len(raw) == 0):"),
    Mutation("manifest-link-binding", "if not _manifest_is_linked("),
    Mutation("model-output-shape", 'if not isinstance(raw, dict) or len(raw) != 1 or "verdict" not in raw:'),
    Mutation(
        "model-verdict-enum",
        '    verdict = raw["verdict"]\n    if not isinstance(verdict, str) or verdict not in VERDICTS:',
    ),
    Mutation("signature-verification", "if not _verify_secp256k1_sha256(public_key, signature, unsigned_bytes):"),
    Mutation("trust-root-check", "if gl.message.sender_address.as_hex != self.trust_root:"),
    Mutation("issuer-registration-check", "if issuer_status is None:"),
    Mutation("issuer-identity-binding", "if issuer_id != publisher_identity:"),
    Mutation("signature-expiry", "if now > expires_at:"),
    Mutation("manifest-replay-protection", "if replay_blocked:"),
    Mutation("consensus-call", "result = gl.vm.run_nondet(leader_fn, validator_fn)"),
    Mutation("post-consensus-revalidation", "final = _validate_consensus_result(result)"),
    Mutation("duplicate-registration", "if clean_id in self.certificates:"),
    Mutation("revocation-authorization", "if sender != certificate.submitter:"),
    Mutation("revocation-state", "if certificate.status != STATUS_CERTIFIED:"),
    Mutation("duplicate-certification", "if certificate.status in (STATUS_CERTIFIED, STATUS_NOT_CERTIFIED, STATUS_REVOKED):"),
)


def security_violations(source: str) -> list[str]:
    return sorted(mutation.name for mutation in MUTATIONS if mutation.anchor not in source)


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    baseline = security_violations(source)
    if baseline:
        print("baseline security guard failure: " + ", ".join(baseline))
        return 1
    survivors: list[str] = []
    for mutation in MUTATIONS:
        mutated = source.replace(mutation.anchor, "# removed critical guard", 1)
        if not security_violations(mutated):
            survivors.append(mutation.name)
    if survivors:
        print("mutation survivors: " + ", ".join(survivors))
        return 1
    print(f"mutation gate passed: {len(MUTATIONS)} critical guard mutations killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
