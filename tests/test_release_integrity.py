"""Offline release consistency tests."""

from tools.release_audit import audit


def test_release_surface_is_internally_consistent():
    assert audit() == []
