"""
CLI for Private Set Intersection (PSI) Calculator.
Supports: DH-PSI, hash-based PSI, cardinality-only PSI, communication analysis, security.
"""
import argparse
import json
import sys

from psi_registry.engine import (
    dh_psi, hash_based_psi, cardinality_only_psi,
    communication_analysis, security_assumptions,
    run_psi, hash_to_group, hash_element,
)


def cmd_run(args):
    """Run PSI protocol."""
    alice = json.loads(args.alice)
    bob = json.loads(args.bob)
    prime = args.prime if args.prime else None
    result = run_psi(alice, bob, args.method, prime)
    print(json.dumps(result, indent=2))


def cmd_dh(args):
    """Run DH-based PSI."""
    alice = json.loads(args.alice)
    bob = json.loads(args.bob)
    result = dh_psi(alice, bob, args.prime)
    print(json.dumps(result, indent=2))


def cmd_hash(args):
    """Run hash-based PSI."""
    alice = json.loads(args.alice)
    bob = json.loads(args.bob)
    result = hash_based_psi(alice, bob, args.salt)
    print(json.dumps(result, indent=2))


def cmd_cardinality(args):
    """Run cardinality-only PSI."""
    alice = json.loads(args.alice)
    bob = json.loads(args.bob)
    result = cardinality_only_psi(alice, bob, args.prime)
    print(json.dumps(result, indent=2))


def cmd_comm(args):
    """Communication complexity analysis."""
    result = communication_analysis(args.size_a, args.size_b,
                                     args.element_bits, args.protocol)
    print(json.dumps(result, indent=2))


def cmd_security(args):
    """Show security assumptions."""
    result = security_assumptions(args.protocol)
    print(json.dumps(result, indent=2))


def cmd_hash_element(args):
    """Hash an element to a group element."""
    h = hash_to_group(args.element, args.prime)
    print(json.dumps({"element": args.element, "hash": h, "prime": args.prime}, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="private-set-intersection-psi",
        description="Private Set Intersection Calculator: DH-based, hash-based, cardinality-only")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Run
    p_run = subparsers.add_parser("run", help="Run PSI with specified method")
    p_run.add_argument("--alice", type=str, required=True, help="Alice's set (JSON array)")
    p_run.add_argument("--bob", type=str, required=True, help="Bob's set (JSON array)")
    p_run.add_argument("--method", choices=["dh", "hash", "cardinality"], default="dh")
    p_run.add_argument("--prime", type=int, default=None)

    # DH
    p_dh = subparsers.add_parser("dh", help="Diffie-Hellman PSI")
    p_dh.add_argument("--alice", type=str, required=True)
    p_dh.add_argument("--bob", type=str, required=True)
    p_dh.add_argument("--prime", type=int, default=65537)

    # Hash
    p_hash = subparsers.add_parser("hash", help="Hash-based PSI")
    p_hash.add_argument("--alice", type=str, required=True)
    p_hash.add_argument("--bob", type=str, required=True)
    p_hash.add_argument("--salt", type=str, default="")

    # Cardinality
    p_card = subparsers.add_parser("cardinality", help="Cardinality-only PSI")
    p_card.add_argument("--alice", type=str, required=True)
    p_card.add_argument("--bob", type=str, required=True)
    p_card.add_argument("--prime", type=int, default=65537)

    # Communication analysis
    p_comm = subparsers.add_parser("comm", help="Communication complexity analysis")
    p_comm.add_argument("--size-a", type=int, required=True, help="Alice's set size")
    p_comm.add_argument("--size-b", type=int, required=True, help="Bob's set size")
    p_comm.add_argument("--element-bits", type=int, default=256)
    p_comm.add_argument("--protocol", choices=["dh", "hash", "cardinality"], default="dh")

    # Security
    p_sec = subparsers.add_parser("security", help="Security assumptions")
    p_sec.add_argument("--protocol", choices=["dh", "hash", "cardinality"], default="dh")

    # Hash element
    p_he = subparsers.add_parser("hash-element", help="Hash an element to group")
    p_he.add_argument("--element", type=str, required=True)
    p_he.add_argument("--prime", type=int, default=65537)

    args = parser.parse_args(argv)

    cmd_map = {
        "run": cmd_run,
        "dh": cmd_dh,
        "hash": cmd_hash,
        "cardinality": cmd_cardinality,
        "comm": cmd_comm,
        "security": cmd_security,
        "hash-element": cmd_hash_element,
    }
    return cmd_map[args.command](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
