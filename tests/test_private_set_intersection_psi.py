"""
Real tests for Private Set Intersection (PSI) Engine.
"""
import random
import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from psi_registry.engine import (
    hash_element, hash_to_group, mod_pow, generate_private_key,
    DHPSIParty, dh_psi,
    hash_based_psi, cardinality_only_psi,
    communication_analysis, security_assumptions,
    run_psi,
)


class TestHashUtilities(unittest.TestCase):

    def test_hash_element_deterministic(self):
        h1 = hash_element("hello")
        h2 = hash_element("hello")
        self.assertEqual(h1, h2)

    def test_hash_element_different_inputs(self):
        h1 = hash_element("abc")
        h2 = hash_element("def")
        self.assertNotEqual(h1, h2)

    def test_hash_element_with_key(self):
        h1 = hash_element("hello", b"key1")
        h2 = hash_element("hello", b"key2")
        self.assertNotEqual(h1, h2)

    def test_hash_to_group_in_range(self):
        prime = 65537
        for elem in ["a", "b", "test", "hello"]:
            h = hash_to_group(elem, prime)
            self.assertGreaterEqual(h, 2)
            self.assertLess(h, prime)

    def test_hash_to_group_deterministic(self):
        prime = 65537
        h1 = hash_to_group("test", prime)
        h2 = hash_to_group("test", prime)
        self.assertEqual(h1, h2)


class TestModPow(unittest.TestCase):

    def test_basic(self):
        self.assertEqual(mod_pow(2, 10, 1000), 1024 % 1000)

    def test_fermat(self):
        p = 17
        self.assertEqual(mod_pow(3, p - 1, p), 1)


class TestPrivateKeyGeneration(unittest.TestCase):

    def test_in_range(self):
        prime = 65537
        for _ in range(100):
            key = generate_private_key(prime)
            self.assertGreaterEqual(key, 2)
            self.assertLess(key, prime - 1)


class TestDHPSIParty(unittest.TestCase):

    def test_party_creation(self):
        random.seed(42)
        party = DHPSIParty("Alice", ["a", "b", "c"], 65537)
        self.assertEqual(party.name, "Alice")
        self.assertEqual(len(party.elements), 3)

    def test_compute_hashed_powers(self):
        random.seed(42)
        party = DHPSIParty("Alice", ["a", "b", "c"], 65537)
        powers = party.compute_hashed_powers()
        self.assertEqual(len(powers), 3)
        for p in powers:
            self.assertGreaterEqual(p, 0)
            self.assertLess(p, 65537)

    def test_compute_double_powers(self):
        random.seed(42)
        party = DHPSIParty("Alice", ["a", "b"], 65537)
        powers = party.compute_hashed_powers()
        double = party.compute_double_powers(powers)
        self.assertEqual(len(double), 2)


class TestDHBasedPSI(unittest.TestCase):

    def test_correct_intersection(self):
        random.seed(42)
        alice = ["apple", "banana", "cherry", "date"]
        bob = ["banana", "date", "fig", "grape"]
        result = dh_psi(alice, bob, 65537)
        intersection = set(result["intersection"])
        expected = {"banana", "date"}
        self.assertEqual(intersection, expected)

    def test_empty_intersection(self):
        random.seed(42)
        alice = ["a", "b", "c"]
        bob = ["d", "e", "f"]
        result = dh_psi(alice, bob, 65537)
        self.assertEqual(result["intersection_size"], 0)
        self.assertEqual(len(result["intersection"]), 0)

    def test_full_intersection(self):
        random.seed(42)
        alice = ["x", "y", "z"]
        bob = ["x", "y", "z"]
        result = dh_psi(alice, bob, 65537)
        self.assertEqual(result["intersection_size"], 3)

    def test_single_element_intersection(self):
        random.seed(42)
        alice = ["only_this"]
        bob = ["only_this", "not_this"]
        result = dh_psi(alice, bob, 65537)
        self.assertEqual(result["intersection"], ["only_this"])

    def test_communication_stats(self):
        random.seed(42)
        alice = ["a", "b", "c"]
        bob = ["b", "c", "d"]
        result = dh_psi(alice, bob, 65537)
        self.assertIn("total_communication_bits", result)
        self.assertIn("communication_rounds", result)
        self.assertEqual(result["communication_rounds"], 2)


class TestHashBasedPSI(unittest.TestCase):

    def test_correct_intersection(self):
        alice = ["apple", "banana", "cherry"]
        bob = ["banana", "cherry", "date"]
        result = hash_based_psi(alice, bob)
        self.assertEqual(set(result["intersection"]), {"banana", "cherry"})

    def test_empty_intersection(self):
        alice = ["a", "b"]
        bob = ["c", "d"]
        result = hash_based_psi(alice, bob)
        self.assertEqual(result["intersection_size"], 0)

    def test_with_salt(self):
        alice = ["x", "y"]
        bob = ["x", "z"]
        result = hash_based_psi(alice, bob, salt="my_salt")
        self.assertEqual(result["intersection"], ["x"])

    def test_method_field(self):
        result = hash_based_psi(["a"], ["a"])
        self.assertEqual(result["method"], "hash-based")


class TestCardinalityOnlyPSI(unittest.TestCase):

    def test_correct_cardinality(self):
        random.seed(42)
        alice = ["a", "b", "c", "d"]
        bob = ["b", "d", "e", "f"]
        result = cardinality_only_psi(alice, bob, 65537)
        self.assertEqual(result["cardinality"], 2)

    def test_zero_cardinality(self):
        random.seed(42)
        alice = ["a", "b"]
        bob = ["c", "d"]
        result = cardinality_only_psi(alice, bob, 65537)
        self.assertEqual(result["cardinality"], 0)

    def test_full_overlap(self):
        random.seed(42)
        alice = ["x", "y"]
        bob = ["x", "y"]
        result = cardinality_only_psi(alice, bob, 65537)
        self.assertEqual(result["cardinality"], 2)

    def test_verified_cardinality(self):
        random.seed(42)
        alice = ["a", "b", "c"]
        bob = ["b", "c", "d"]
        result = cardinality_only_psi(alice, bob, 65537)
        self.assertTrue(result["cardinality_matches"])

    def test_method_field(self):
        random.seed(42)
        result = cardinality_only_psi(["a"], ["a"], 65537)
        self.assertEqual(result["method"], "cardinality-only")


class TestCommunicationAnalysis(unittest.TestCase):

    def test_dh_protocol(self):
        result = communication_analysis(100, 200, 256, "dh")
        self.assertEqual(result["protocol"], "dh")
        self.assertEqual(result["communication_rounds"], 2)

    def test_hash_protocol(self):
        result = communication_analysis(100, 200, 256, "hash")
        self.assertEqual(result["protocol"], "hash")
        self.assertEqual(result["communication_rounds"], 1)

    def test_cardinality_protocol(self):
        result = communication_analysis(100, 200, 256, "cardinality")
        self.assertEqual(result["protocol"], "cardinality")
        self.assertEqual(result["total_elements_transmitted"], 1)

    def test_larger_sets_more_communication(self):
        r1 = communication_analysis(10, 10, 256, "dh")
        r2 = communication_analysis(1000, 1000, 256, "dh")
        self.assertGreater(r2["total_bits"], r1["total_bits"])


class TestSecurityAssumptions(unittest.TestCase):

    def test_dh_assumptions(self):
        result = security_assumptions("dh")
        self.assertEqual(result["protocol"], "Diffie-Hellman PSI")
        self.assertIn("assumptions", result)
        self.assertGreater(len(result["assumptions"]), 0)

    def test_hash_assumptions(self):
        result = security_assumptions("hash")
        self.assertEqual(result["protocol"], "Hash-based PSI")

    def test_cardinality_assumptions(self):
        result = security_assumptions("cardinality")
        self.assertEqual(result["protocol"], "Cardinality-only PSI")

    def test_unknown_protocol(self):
        result = security_assumptions("unknown")
        self.assertIn("error", result)


class TestRunPSI(unittest.TestCase):

    def test_dh_method(self):
        random.seed(42)
        result = run_psi(["a", "b"], ["b", "c"], method="dh", prime=65537)
        self.assertEqual(result["intersection"], ["b"])
        self.assertEqual(result["method"], "dh")

    def test_hash_method(self):
        result = run_psi(["a", "b"], ["b", "c"], method="hash")
        self.assertEqual(result["intersection"], ["b"])

    def test_cardinality_method(self):
        random.seed(42)
        result = run_psi(["a", "b"], ["b", "c"], method="cardinality", prime=65537)
        self.assertEqual(result["cardinality"], 1)

    def test_unknown_method_raises(self):
        with self.assertRaises(ValueError):
            run_psi(["a"], ["a"], method="invalid")


if __name__ == "__main__":
    unittest.main()
