"""Pytest coverage for the conservative critical-guard mutation gate."""

from tools.mutation_test import MUTATIONS, SOURCE, security_violations


def test_source_has_all_critical_security_guards():
    assert security_violations(SOURCE.read_text(encoding="utf-8")) == []


def test_each_critical_guard_mutation_is_killed():
    source = SOURCE.read_text(encoding="utf-8")
    for mutation in MUTATIONS:
        mutated = source.replace(mutation.anchor, "# removed critical guard", 1)
        assert mutation.name in security_violations(mutated)
