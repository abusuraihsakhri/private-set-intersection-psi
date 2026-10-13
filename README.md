# Private Set Intersection (PSI) Demonstrator

Two-set comparison tools, a Python implementation of simplified Diffie–Hellman-style matching, and a browser-based educational laboratory.

**Security scope:** This repository demonstrates PSI-related computations; it is **not** a cryptographically validated two-party PSI implementation. The Python and browser examples access both raw sets in one process. Do not use them to process patient records, protected health information, credentials, or other confidential data.

## Browser application

The interactive application in `web/` runs in the browser with no backend, telemetry, cookies, or remote processing. It supports:

- Exact set intersection (one item per line; case-sensitive; duplicates removed).
- Cardinality-only output (the number of shared items without listing them).
- SHA-256 hash-token matching using browser Web Crypto (educational, **not private PSI**).
- Overlap statistics, example data, set swapping, validation, and JSON export.

Input is held in the current tab and is not sent to a server. The browser page uses JavaScript rather than the Python engine; Pyodide is not required. SHA-256 hashes of small or guessable domains are subject to dictionary attacks.

For local use:

```bash
python -m http.server 8080 --directory web
# Open http://localhost:8080
```

JavaScript modules require HTTP(S); opening `web/index.html` directly as a `file://` URL may not work. Modern Chromium, Firefox, and Safari browsers support the required APIs. SHA-256 mode needs HTTPS or localhost.

## Python installation

Python 3.9+ is required for the core standard-library PSI examples. Python 3.10–3.12 are covered by CI.

```bash
git clone https://github.com/abusuraihsakhri/private-set-intersection-psi.git
cd private-set-intersection-psi
python -m pip install -e .
```

Install the optional API and testing dependencies when needed:

```bash
python -m pip install -e ".[api,test]"
```

## CLI and Python API

```bash
python cli.py dh --alice '["a","b"]' --bob '["b","c"]' --prime 65537
python cli.py hash --alice '["a","b"]' --bob '["b","c"]'
python cli.py cardinality --alice '["a","b"]' --bob '["b","c"]' --prime 65537
python cli.py comm --size-a 100 --size-b 200 --protocol dh
python cli.py security --protocol dh
```

```python
from psi_registry.engine import dh_psi, hash_based_psi, cardinality_only_psi

assert dh_psi(["a", "b"], ["b", "c"], 65537)["intersection"] == ["b"]
assert hash_based_psi(["a", "b"], ["b", "c"])["intersection"] == ["b"]
assert cardinality_only_psi(["a", "b"], ["b", "c"], 65537)["cardinality"] == 1
```

The DH demonstration requires a prime modulus and coprime exponents, and rejects detected hash-to-group collisions. Small primes such as 65537 and the 256-bit default parameter are **not suitable for production cryptography**. The cardinality function computes the count centrally, without secure multiparty computation. Public hash matching is not oblivious PRF or OT-based PSI. For confidential cross-institution data matching, use a formally specified and independently audited protocol/library, approved infrastructure, and an appropriate privacy assessment.

## Registry / audit demo and REST API

An independent `psi_registry` component evaluates generic numerical thresholds; it is not a validated clinical decision system and does not implement the PSI cryptographic exchange.

```bash
python -m psi_registry.cli audit --task-id TASK-001 --primary 28.4 --secondary 14.2 --critical
python -m psi_registry.cli batch -i sample.csv -o results.csv
python -m psi_registry.cli serve --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health
```

With API extras installed, `POST /api/audit` and `POST /api/chat` are exposed by `psi_registry.server`. The separate `agents.api` application provides its own audit endpoints (run with `uvicorn agents.api:app`); the two applications are not interchangeable.

## Docker

```bash
cp .env.example .env
# Set AUDIT_SECRET_KEY to a unique random secret (e.g. openssl rand -hex 32).
docker compose up --build
# API health endpoint: http://localhost:8000/health
```

The Compose configuration refuses to start without `AUDIT_SECRET_KEY`. Never commit a real key. For an existing installation, rotate any previously published example key. The audit trail is an in-memory, signed hash chain; it is **not durable storage** or a substitute for regulated audit logging.

## Testing and security

```bash
python -m pip install -e ".[api,test]"
pytest -q
node --check web/app.mjs
node --check web/psi.mjs
node --test tests/browser.test.mjs
```

CI runs Python 3.10–3.12 plus browser-module tests. The PHI regex guard detects selected identifier patterns only; it cannot prove that data is de-identified or satisfy HIPAA/GDPR compliance by itself. Use synthetic data only. The browser stores nothing persistently; Python registry audit state resides in process memory.

## Repository structure

- `psi_registry/engine.py`: simplified PSI and cardinality algorithms, communication analysis.
- `psi_registry/`: registry evaluation CLI, coordinator, and FastAPI application.
- `agents/`: separate Pydantic/worker audit demonstration with HMAC-signed log.
- `web/`: standalone static browser laboratory for GitHub Pages.
- `tests/`: Python regression and Node.js browser-module tests.
- `.github/workflows/`: CI and GitHub Pages deployment.

## License

MIT — see [LICENSE](LICENSE).
