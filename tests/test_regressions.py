"""Regressions for cryptographic-demo correctness, audit integrity, and CSV parsing."""
import csv

import pytest

from agents.base import AuditTrail
from psi_registry.engine import (
    cardinality_only_psi,
    communication_analysis,
    dh_psi,
    hash_based_psi,
)
from psi_registry.cli import main


def test_dh_no_spurious_matches_over_random_keys():
    alice = ["apple", "banana", "cherry", "date"]
    bob = ["banana", "date", "fig", "grape"]
    for _ in range(100):
        result = dh_psi(alice, bob, 65537)
        assert result["intersection"] == ["banana", "date"]
        assert result["elements_transmitted"] == 2 * (len(alice) + len(bob))


def test_dh_rejects_nonprime_and_mixed_elements():
    with pytest.raises(ValueError, match="prime"):
        dh_psi(["a"], ["a"], 15)
    with pytest.raises(ValueError, match="strings"):
        dh_psi(["a"], [3], 65537)


def test_cardinality_is_exact_and_deduplicated():
    result = cardinality_only_psi(["a", "a", "b"], ["b", "b", "c"], 5)
    assert result["cardinality"] == result["verified_cardinality"] == 1
    assert "intersection" not in result


def test_hash_intersection_is_deduplicated_in_alice_order():
    result = hash_based_psi(["z", "x", "x", "y"], ["x", "z", "z"])
    assert result["intersection"] == ["z", "x"]


def test_communication_dh_accounts_for_both_exchanges():
    result = communication_analysis(3, 2, element_bits=17, protocol="dh")
    assert result["total_elements_transmitted"] == 10
    assert result["total_bytes"] == 22
    with pytest.raises(ValueError):
        communication_analysis(-1, 2)


def test_audit_hmac_detects_entry_modification():
    trail = AuditTrail(secret_key="test-only-long-enough-secret")
    trail.log("worker", "system", "ok", {"status": "SUCCESS"})
    assert trail.verify_integrity()
    trail.logs[0]["event_type"] = "modified"
    assert not trail.verify_integrity()


def test_batch_csv_false_is_not_interpreted_as_true(tmp_path):
    source = tmp_path / "inputs.csv"
    output = tmp_path / "out.csv"
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "task_id", "target_identifier", "primary_metric",
            "secondary_metric", "status_descriptor", "is_critical_flag",
        ])
        writer.writeheader()
        writer.writerow(dict(task_id="t1", target_identifier="x",
                             primary_metric="10", secondary_metric="2",
                             status_descriptor="NOMINAL", is_critical_flag="False"))
    assert main(["batch", "-i", str(source), "-o", str(output)]) == 0
    with output.open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert row["overall_status"] == "NOMINAL_OPTIMAL"
