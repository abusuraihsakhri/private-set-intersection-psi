# Private Set Intersection (PSI) Calculator

A pure-Python implementation of Private Set Intersection protocols: Diffie-Hellman based, hash-based, and cardinality-only PSI. Uses only the Python standard library.

## Features

- **Diffie-Hellman PSI**: `H(x)^a` / `H(y)^b` exchange with double exponentiation for intersection
- **Hash-based PSI**: SHA-256 hashing with common salt for simple intersection
- **Cardinality-only PSI**: Reveals only `|A ∩ B|` without exposing elements
- **Communication Complexity Analysis**: Compute bits/bytes transmitted per protocol
- **Security Assumptions**: Documented DDH, random oracle, and semi-honest model assumptions

## CLI Usage

```bash
# Run DH-based PSI
python cli.py dh --alice '["apple","banana","cherry"]' --bob '["banana","cherry","date"]' --prime 65537

# Run hash-based PSI
python cli.py hash --alice '["a","b","c"]' --bob '["b","c","d"]' --salt "my_salt"

# Run cardinality-only PSI
python cli.py cardinality --alice '["x","y","z"]' --bob '["y","z","w"]' --prime 65537

# Communication analysis
python cli.py comm --size-a 1000 --size-b 2000 --protocol dh --element-bits 256

# Security assumptions
python cli.py security --protocol dh

# Hash an element
python cli.py hash-element --element "hello" --prime 65537
```

## Python API

```python
from psi_registry.engine import run_psi, dh_psi, communication_analysis

# DH-based PSI
result = run_psi(
    alice_elements=["apple", "banana", "cherry"],
    bob_elements=["banana", "cherry", "date"],
    method="dh",
    prime=65537
)
print(result["intersection"])  # ["banana", "cherry"]

# Communication analysis
comm = communication_analysis(1000, 2000, 256, "dh")
print(comm["total_bytes"])
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## License

MIT License.
