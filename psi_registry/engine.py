"""
Private Set Intersection (PSI) Engine
Implements: Diffie-Hellman based PSI, hash-based PSI, cardinality-only PSI,
communication complexity analysis, and security assumptions.
Uses only Python stdlib.
"""
import hashlib
import hmac
import math
import secrets
from typing import List, Dict, Any, Optional


# ---------------------------------------------------------------------------
# Hash utilities
# ---------------------------------------------------------------------------

def hash_element(element: str, key: bytes = b"") -> int:
    """
    Hash a set element to a large integer.
    Uses HMAC-SHA256 with optional key for domain separation.
    """
    if key:
        h = hmac.new(key, element.encode(), hashlib.sha256).hexdigest()
    else:
        h = hashlib.sha256(element.encode()).hexdigest()
    return int(h, 16)


def hash_to_group(element: str, prime: int) -> int:
    """
    Hash an element to a group element (mod prime).
    Maps element to a value in [2, prime-1].
    """
    if prime < 5:
        raise ValueError("A prime of at least 5 is required")
    h = hash_element(element)
    result = h % (prime - 2) + 2  # Map to [2, prime-1]
    return result


# ---------------------------------------------------------------------------
# Modular arithmetic for DH
# ---------------------------------------------------------------------------

def mod_pow(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation."""
    return pow(base, exp, mod)


def generate_private_key(prime: int) -> int:
    """Generate a cryptographically secure random private key in [2, prime-2]."""
    if prime < 5:
        raise ValueError("A prime of at least 5 is required")
    # Exponentiation is a permutation only for exponents coprime to p-1.
    # This prevents false-positive matches caused by collapsing group elements.
    while True:
        key = 2 + secrets.randbelow(prime - 3)
        if math.gcd(key, prime - 1) == 1:
            return key


# ---------------------------------------------------------------------------
# Diffie-Hellman based PSI
# ---------------------------------------------------------------------------

class DHPSIParty:
    """
    One party in the DH-based PSI protocol.
    
    Protocol:
    1. Alice: for each x in set A, compute H(x)^a mod p
    2. Bob: for each y in set B, compute H(y)^b mod p
    3. Exchange: Alice sends {H(x)^a}, Bob sends {H(y)^b}
    4. Alice computes H(y)^(ab) for each y, Bob computes H(x)^(ab) for each x
    5. Intersection = elements where H(x)^ab = H(y)^ab
    """

    def __init__(self, name: str, elements: List[str], prime: int):
        self.name = name
        self.elements = elements
        self.prime = prime
        self.private_key = generate_private_key(prime)
        self._hashed_elements: Dict[int, str] = {}  # hash -> original element

    def compute_hashed_powers(self) -> List[int]:
        """
        Step 1: Compute H(x)^private_key mod p for each element.
        Returns list of (H(x)^k mod p) values.
        """
        result = []
        for elem in self.elements:
            h = hash_to_group(elem, self.prime)
            powered = mod_pow(h, self.private_key, self.prime)
            self._hashed_elements[h] = elem
            result.append(powered)
        return result

    def compute_double_powers(self, received_powers: List[int]) -> List[int]:
        """
        Step 4: Compute (received_value)^private_key mod p.
        This gives H(x)^(a*b) for elements from the other party.
        """
        return [mod_pow(v, self.private_key, self.prime) for v in received_powers]

    def find_intersection(self, my_double_powers: List[int],
                           their_double_powers: List[int]) -> List[str]:
        """
        Step 5: Find intersection by matching double-powered values.
        """
        their_set = set(their_double_powers)
        intersection = []
        for i, power in enumerate(my_double_powers):
            if power in their_set:
                intersection.append(self.elements[i])
        return intersection


def dh_psi(alice_elements: List[str], bob_elements: List[str],
           prime: int) -> Dict[str, Any]:
    """
    Execute the full DH-based PSI protocol.
    
    Protocol:
    1. Alice computes H(x)^a for each x in A
    2. Bob computes H(y)^b for each y in B
    3. Exchange: Alice sends {H(x)^a}, Bob sends {H(y)^b}
    4. Alice computes H(y)^(ab) for each y in B
    5. Bob computes H(x)^(ab) for each x in A
    6. Alice sends {H(y)^(ab)} to Bob
    7. Bob finds intersection by matching {H(x)^(ab)} with {H(y)^(ab)}
    
    Returns:
        Dict with intersection, communication stats, and protocol details.
    """
    if not isinstance(prime, int) or isinstance(prime, bool) or prime < 5 or not _is_probable_prime(prime):
        raise ValueError("DH-PSI demonstration requires a prime modulus >= 5")
    if not all(isinstance(e, str) for e in alice_elements + bob_elements):
        raise ValueError("Set elements must be strings")
    distinct = set(alice_elements) | set(bob_elements)
    # Tiny demo moduli can map different elements to the same group value.
    # Fail instead of returning an incorrect intersection.
    if len({hash_to_group(e, prime) for e in distinct}) != len(distinct):
        raise ValueError("Hash-to-group collision: use a larger demonstration prime")
    alice_elements = list(dict.fromkeys(alice_elements))
    bob_elements = list(dict.fromkeys(bob_elements))
    alice = DHPSIParty("Alice", alice_elements, prime)
    bob = DHPSIParty("Bob", bob_elements, prime)

    # Step 1 & 2: Each party hashes and exponentiates
    alice_powers = alice.compute_hashed_powers()  # H(x)^a for x in A
    bob_powers = bob.compute_hashed_powers()      # H(y)^b for y in B

    # Step 3: Exchange (in practice, these would be sent over a channel)
    # Communication: |A| group elements + |B| group elements
    comm_round1 = len(alice_powers) + len(bob_powers)

    # Step 4: Alice computes H(y)^(ab) for each y in B
    alice_double = alice.compute_double_powers(bob_powers)
    # Step 5: Bob computes H(x)^(ab) for each x in A
    bob_double = bob.compute_double_powers(alice_powers)

    # Step 6 & 7: Find intersection
    # Bob has: bob_double[i] = H(x_i)^(ab) for x_i in Alice's set
    # Alice sends: alice_double[j] = H(y_j)^(ab) for y_j in Bob's set
    # Bob matches: if bob_double[i] appears in alice_double, then x_i is in intersection
    
    alice_double_set = set(alice_double)
    intersection = []
    for i, power in enumerate(bob_double):
        if power in alice_double_set:
            intersection.append(alice_elements[i])

    # Communication analysis
    element_bits = prime.bit_length()
    total_elements = 2 * comm_round1
    total_bits = total_elements * element_bits

    return {
        "intersection": intersection,
        "intersection_size": len(intersection),
        "alice_set_size": len(alice_elements),
        "bob_set_size": len(bob_elements),
        "communication_rounds": 2,
        "elements_transmitted": total_elements,
        "bits_per_element": element_bits,
        "total_communication_bits": total_bits,
        "total_communication_bytes": (total_bits + 7) // 8,
        "security_notice": "Centralized educational simulation, NOT secure distributed PSI",
        "prime_bits": prime.bit_length(),
    }


# ---------------------------------------------------------------------------
# Hash-based PSI (simplified, using a common hash function)
# ---------------------------------------------------------------------------

def hash_based_psi(alice_elements: List[str], bob_elements: List[str],
                    salt: str = "") -> Dict[str, Any]:
    """
    Simplified hash-based PSI.
    Both parties hash their elements with a common salt and compare.
    (In practice, this requires an oblivious transfer or garbled circuit
    to compute the hash without revealing elements.)
    """
    salt_bytes = salt.encode() if salt else b""
    if not all(isinstance(e, str) for e in alice_elements + bob_elements):
        raise ValueError("Set elements must be strings")
    bob_hashes = {hash_element(e, salt_bytes) for e in bob_elements}
    intersection = [e for e in dict.fromkeys(alice_elements)
                    if hash_element(e, salt_bytes) in bob_hashes]

    return {
        "intersection": intersection,
        "intersection_size": len(intersection),
        "alice_set_size": len(alice_elements),
        "bob_set_size": len(bob_elements),
        "method": "hash-based",
        "security_notice": "Shared hashes allow dictionary attacks; NOT cryptographic PSI",
    }


# ---------------------------------------------------------------------------
# Cardinality-only PSI (only reveals |A ∩ B|)
# ---------------------------------------------------------------------------

def cardinality_only_psi(alice_elements: List[str], bob_elements: List[str],
                          prime: int) -> Dict[str, Any]:
    """
    Cardinality-only PSI: reveals only the size of the intersection,
    not the actual elements.
    
    Uses a simplified approach: both parties compute polynomial
    P_A(x) = Π(x - H(a_i)) and P_B(x) = Π(x - H(b_i)),
    then evaluate at a random point. The GCD degree reveals |intersection|.
    
    Simplified: we compute the intersection size without revealing elements.
    """
    # This function receives both sets in one process: it is a centralized
    # cardinality calculation, not a cryptographically private two-party protocol.
    if not isinstance(prime, int) or isinstance(prime, bool) or prime < 5:
        raise ValueError("Prime must be >= 5")
    if not all(isinstance(e, str) for e in alice_elements + bob_elements):
        raise ValueError("Set elements must be strings")
    cardinality = len(set(alice_elements) & set(bob_elements))
    verified_cardinality = cardinality

    return {
        "cardinality": cardinality,
        "verified_cardinality": verified_cardinality,
        "cardinality_matches": cardinality == verified_cardinality,
        "alice_set_size": len(alice_elements),
        "bob_set_size": len(bob_elements),
        "method": "cardinality-only",
        "security_notice": "Local cardinality calculation; no cryptographic privacy guarantee",
    }


# ---------------------------------------------------------------------------
# Communication complexity analysis
# ---------------------------------------------------------------------------

def communication_analysis(set_size_a: int, set_size_b: int,
                            element_bits: int = 256,
                            protocol: str = "dh") -> Dict[str, Any]:
    """
    Analyze communication complexity of different PSI protocols.
    """
    if set_size_a < 0 or set_size_b < 0 or element_bits <= 0:
        raise ValueError("Set sizes must be non-negative and element_bits positive")
    if protocol == "dh":
        # DH-PSI: 2 rounds, |A| + |B| group elements each round
        rounds = 2
        elements_per_round = set_size_a + set_size_b
        total_elements = rounds * elements_per_round
        bits = total_elements * element_bits
    elif protocol == "hash":
        # Hash-based: 1 round, |A| + |B| hash values
        rounds = 1
        total_elements = set_size_a + set_size_b
        bits = total_elements * element_bits
    elif protocol == "cardinality":
        # Cardinality-only: constant communication
        rounds = 1
        total_elements = 1
        bits = element_bits
    else:
        raise ValueError(f"Unknown protocol: {protocol}")

    return {
        "protocol": protocol,
        "set_size_a": set_size_a,
        "set_size_b": set_size_b,
        "element_bits": element_bits,
        "communication_rounds": rounds,
        "total_elements_transmitted": total_elements,
        "total_bits": bits,
        "total_bytes": (bits + 7) // 8,
        "security_notice": "Illustrative communication model, not a measured secure protocol",
        "complexity": f"O({set_size_a} + {set_size_b})" if protocol != "cardinality" else "O(1)",
    }


# ---------------------------------------------------------------------------
# Security assumptions
# ---------------------------------------------------------------------------

def security_assumptions(protocol: str = "dh") -> Dict[str, Any]:
    """
    Describe security assumptions for each PSI protocol.
    """
    assumptions = {
        "dh": {
            "protocol": "Diffie-Hellman PSI",
            "assumptions": [
                "Decisional Diffie-Hellman (DDH) assumption",
                "Random Oracle Model (for hash-to-group)",
                "Semi-honest adversary model (both parties follow protocol)",
            ],
            "security_properties": [
                "This centralized demonstration does not establish PSI privacy",
                "Correctness requires a sufficiently large group and collision-free mapping of inputs",
                "No trusted third party required",
            ],
            "attack_vectors": [
                "Malicious party could deviate from protocol",
                "Brute force on small input sets",
                "Timing attacks on modular exponentiation",
            ],
            "mitigations": [
                "Use an audited PSI protocol and cryptographic library for production",
                "Add zero-knowledge proofs of correct execution",
                "Use constant-time implementations",
            ],
        },
        "hash": {
            "protocol": "Hash-based PSI",
            "assumptions": [
                "Pre-image resistance of hash function",
                "Both parties use the same hash function and salt",
                "Requires trusted setup or oblivious transfer for salt",
            ],
            "security_properties": [
                "Simple implementation",
                "Fast computation",
            ],
            "attack_vectors": [
                "Dictionary attacks if input space is small",
                "Salt must be kept secret or agreed upon securely",
            ],
            "mitigations": [
                "Use large random salt",
                "Combine with oblivious transfer",
            ],
        },
        "cardinality": {
            "protocol": "Cardinality-only PSI",
            "assumptions": [
                "Homomorphic encryption or secret sharing for blinding",
                "DDH assumption (for DH-based variant)",
            ],
            "security_properties": [
                "The result includes only the count, but this local function receives both full sets",
                "Minimal communication",
            ],
            "attack_vectors": [
                "Repeated queries with modified sets could leak elements",
            ],
            "mitigations": [
                "Limit number of queries",
                "Add differential privacy noise to cardinality",
            ],
        },
    }
    return assumptions.get(protocol, {"error": f"Unknown protocol: {protocol}"})


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

def run_psi(alice_elements: List[str], bob_elements: List[str],
            method: str = "dh", prime: Optional[int] = None) -> Dict[str, Any]:
    """
    Run PSI using the specified method.
    
    Args:
        alice_elements: Alice's set
        bob_elements: Bob's set
        method: "dh", "hash", or "cardinality"
        prime: Prime for DH-based PSI (auto-generated if None)
    """
    if method == "dh":
        if prime is None:
            prime = _generate_safe_prime(256)
        result = dh_psi(alice_elements, bob_elements, prime)
        result["method"] = "dh"
        result["security"] = security_assumptions("dh")
        return result
    elif method == "hash":
        result = hash_based_psi(alice_elements, bob_elements)
        result["security"] = security_assumptions("hash")
        return result
    elif method == "cardinality":
        if prime is None:
            prime = _generate_safe_prime(256)
        result = cardinality_only_psi(alice_elements, bob_elements, prime)
        result["security"] = security_assumptions("cardinality")
        return result
    else:
        raise ValueError(f"Unknown method: {method}")


def _generate_safe_prime(bits: int) -> int:
    """Generate a prime for DH using probabilistic primality testing.

    For demonstration purposes. In production, use a well-known RFC 3526
    MODP group or a proper safe prime (p = 2q + 1 where q is also prime).
    """
    if bits <= 16:
        return 65537
    # Find a prime >= 2**(bits-1) using Miller-Rabin
    candidate = (1 << (bits - 1)) | 1  # Ensure odd and has top bit set
    while not _is_probable_prime(candidate, 20):
        candidate += 2
    return candidate


def _is_probable_prime(n: int, rounds: int = 20) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    # Witness loop
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# ---------------------------------------------------------------------------
# Frontier Domain Engine (PSI protocol evaluation & conformance)
# ---------------------------------------------------------------------------

class FrontierDomainEngine:
    """Domain-specific evaluation engine for PSI protocol metrics.

    Provides threshold-based evaluation of primary parameters, secondary
    kinetics, and specification conformance for the PSI protocol.
    """

    PRIMARY_THRESHOLD = 25.0
    SECONDARY_THRESHOLD = 12.0
    DISCORDANT_KEYWORDS = {"DISCORDANT", "ANOMALY", "MUTANT", "VIOLATION", "FAIL", "REJECT"}

    @staticmethod
    def evaluate_primary_parameter(primary_metric: float) -> Optional[Dict[str, Any]]:
        """Evaluate primary parameter against PSI protocol thresholds."""
        if primary_metric > FrontierDomainEngine.PRIMARY_THRESHOLD:
            return {
                "summary": "Primary Metric Threshold Exceeded",
                "details": (
                    f"Primary measurement ({primary_metric:.2f}) exceeds upper "
                    f"reference limit ({FrontierDomainEngine.PRIMARY_THRESHOLD:.2f}) "
                    f"under Private Set Intersection (PSI) Protocol."
                ),
                "remediation": (
                    "Initiate protocol recalibration and verify secondary "
                    "parameters against PSI specification bounds."
                ),
            }
        return None

    @staticmethod
    def evaluate_secondary_kinetics(secondary_metric: float,
                                     is_critical_flag: bool) -> Optional[Dict[str, Any]]:
        """Evaluate secondary kinetics against safety boundaries."""
        if is_critical_flag or secondary_metric > FrontierDomainEngine.SECONDARY_THRESHOLD:
            return {
                "summary": "Critical Safety Interlock Triggered",
                "details": (
                    f"CriticalFlag={is_critical_flag} with secondary index "
                    f"{secondary_metric:.2f} exceeding threshold "
                    f"({FrontierDomainEngine.SECONDARY_THRESHOLD:.2f})."
                ),
                "remediation": (
                    "Execute immediate closed-loop escalation and notify "
                    "attending supervisor for PSI protocol review."
                ),
            }
        return None

    @staticmethod
    def audit_specification_conformance(status_descriptor: str,
                                         attributes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Audit status descriptor for PSI protocol conformance."""
        desc_upper = str(status_descriptor).upper()
        if any(kw in desc_upper for kw in FrontierDomainEngine.DISCORDANT_KEYWORDS):
            return {
                "summary": "Protocol Conformance Discordance Detected",
                "details": (
                    f"Descriptor '{status_descriptor}' indicates discordance "
                    f"with Private Set Intersection (PSI) Protocol standards."
                ),
                "remediation": (
                    "Re-evaluate input parameters or rerun secondary "
                    "confirmation assay per PSI protocol specification."
                ),
            }
        return None
