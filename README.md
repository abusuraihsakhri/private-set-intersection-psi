# Private Set Intersection (PSI)

> **Domain:** Privacy-Preserving Healthcare & Federated Computing
> **Standards:** HIPAA Safe Harbor §164.514, Diffie-Hellman PSI Protocol

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## Overview

Private Set Intersection (PSI) is a cryptographic protocol that allows two parties
to compute the intersection of their sets without revealing any elements that are
not in the intersection. This implementation provides:

- **Diffie-Hellman based PSI** — Secure two-party PSI using modular exponentiation
- **Hash-based PSI** — Simplified PSI using salted HMAC-SHA256 hashing
- **Cardinality-only PSI** — Reveals only |A ∩ B|, not the actual elements
- **Communication analysis** — Compare protocol efficiency
- **PHI outbound guard** — HIPAA Safe Harbor compliance for healthcare data
- **Tamper-evident audit trail** — HMAC-SHA256 chained audit logging

---

## Installation

```bash
# Clone the repository
git clone https://github.com/abusuraihsakhri/private-set-intersection-psi.git
cd private-set-intersection-psi

# Install dependencies (Python 3.9+ required, no external deps for core PSI)
pip install -e .

# Optional: install FastAPI/uvicorn for REST API server
pip install fastapi uvicorn pydantic

# Optional: install pytest for running tests
pip install pytest
```

---

## Usage

### Command-Line Interface

The project provides two CLI entry points:

#### 1. PSI Protocol CLI (`cli.py`)
Direct access to PSI cryptographic operations:

```bash
# Run DH-based PSI
python cli.py dh --alice '["patient-001", "patient-002", "patient-003"]' \
                  --bob '["patient-002", "patient-003", "patient-004"]' \
                  --prime 65537

# Run hash-based PSI with salt
python cli.py hash --alice '["a", "b", "c"]' --bob '["b", "c", "d"]' --salt "shared-secret"

# Run cardinality-only PSI
python cli.py cardinality --alice '["x", "y"]' --bob '["y", "z"]' --prime 65537

# Communication complexity analysis
python cli.py comm --size-a 1000 --size-b 5000 --protocol dh

# Security assumptions reference
python cli.py security --protocol dh
```

#### 2. PSI Registry Agent CLI (`psi_registry/cli.py`)
Multi-agent evaluation system with PHI protection:

```bash
# Single audit evaluation
python -m psi_registry.cli audit --task-id "TASK-001" --primary 28.4 --secondary 14.2 --critical

# Batch CSV processing
python -m psi_registry.cli batch -i sample.csv -o results.csv

# Interactive supervisory chat
python -m psi_registry.cli chat "What is the system status?"

# Launch FastAPI REST server
python -m psi_registry.cli serve --host 127.0.0.1 --port 8000
```

### Python API

```python
from psi_registry.engine import dh_psi, hash_based_psi, cardinality_only_psi, run_psi

# DH-based PSI
result = dh_psi(
    alice_elements=["patient-001", "patient-002"],
    bob_elements=["patient-002", "patient-003"],
    prime=65537
)
print(result["intersection"])  # ["patient-002"]

# Hash-based PSI
result = hash_based_psi(["a", "b"], ["b", "c"], salt="shared-salt")

# Cardinality-only PSI
result = cardinality_only_psi(["x", "y"], ["y", "z"], prime=65537)
print(result["cardinality"])  # 1
```

### REST API (FastAPI)

```bash
# Start server
python -m psi_registry.cli serve

# Health check
curl http://localhost:8000/health

# Audit endpoint
curl -X POST http://localhost:8000/api/audit \
  -H "Content-Type: application/json" \
  -d @sample_payload.json

# Audit trail
curl http://localhost:8000/api/audit/logs
```

---

## Security Features

- **Cryptographically secure key generation** — Uses `secrets` module (CSPRNG) for private keys
- **PHI outbound guard** — Regex-based detection and blocking of SSNs, MRNs, phone numbers, emails
- **HMAC-SHA256 audit trail** — Tamper-evident chained logging with configurable secret
- **Input validation** — Bounds checking on primes, set sizes, and protocol parameters

### Environment Variables

| Variable | Description | Default |
|:---------|:------------|:--------|
| `AUDIT_SECRET_KEY` | HMAC key for audit trail integrity | Auto-generated (ephemeral) |

---

## Testing

```bash
# Run all tests
pytest -v

# Run specific test modules
pytest tests/test_private_set_intersection_psi.py -v
pytest tests/test_psi_registry.py -v
pytest tests/test_enrichment.py -v
```

---

## Project Structure

```
private-set-intersection-psi/
├── psi_registry/          # Core PSI engine & agent system
│   ├── engine.py          # DH-PSI, hash-PSI, cardinality-PSI implementations
│   ├── models.py          # Data models (FrontierPayload, alerts)
│   ├── agents.py          # Multi-agent coordinator & sub-agents
│   ├── cli.py             # Agent CLI (audit, batch, chat, serve)
│   └── server.py          # FastAPI REST server
├── agents/                # Enterprise agent suite
│   ├── base.py            # PHI guard, HMAC audit trail
│   ├── supervisor.py      # Multi-worker orchestration
│   ├── workers.py         # Domain-specific evaluation workers
│   ├── models.py          # Pydantic schemas
│   ├── api.py             # FastAPI endpoints
│   └── llm_factory.py     # LLM provider abstraction
├── tests/                 # Test suite
├── cli.py                 # PSI protocol CLI
├── enrichment.py          # Extended PSI feature engines
├── simulator.py           # High-throughput stress testing
├── Dockerfile             # Container build
└── docker-compose.yml     # Multi-service orchestration
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
