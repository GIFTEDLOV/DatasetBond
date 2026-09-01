"""Studio-mode integration collection.

Run with ``gltest tests/integration/ -v -s`` after configuring a localnet or Studio. This file is
not part of the offline pytest suite's default execution in CI environments without Studio.
"""

import os

import pytest

from gltest import get_contract_factory


@pytest.mark.integration
def test_datasetbond_deploys_with_empty_registry():
    if os.environ.get("DATASETBOND_RUN_INTEGRATION") != "1":
        pytest.skip("Studio/localnet integration requires DATASETBOND_RUN_INTEGRATION=1")
    contract = get_contract_factory("DatasetBond").deploy()
    assert contract.get_certificate_count().call() == 0
    assert contract.get_certificate_ids().call() == []
    assert contract.get_certificates().call() == {}
