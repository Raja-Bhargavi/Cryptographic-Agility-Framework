# Cryptographic Agility Framework — Second Review Prototype

This prototype demonstrates:
- A stable abstraction API
- An algorithm registry
- Policy-driven selection
- Client/server capability negotiation over a local TCP connection
- Explicit fallback and strict-policy rejection
- A real classical X25519 + HKDF shared-secret demonstration
- Unit tests for negotiation and policy enforcement

## Important implementation boundary

The negotiation demo advertises algorithm capabilities and selects a mutually supported
mechanism. The `ML-KEM-768` and `HYBRID-X25519-MLKEM768` entries are currently **capability
entries only**; they are not yet used to perform a real PQC or hybrid key exchange.
The classical X25519 demonstration is a real cryptographic operation using `cryptography`.

The TCP negotiation prototype is for a localhost academic demonstration. It is not a
production secure protocol: it does not authenticate peers or cryptographically bind the
negotiation transcript. Do not use it to protect real data.

## Setup (Windows PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

## Run the demonstration

From the project root:

```powershell
python main.py
```

The demo runs three cases:
1. PQC preferred, both peers support hybrid: hybrid is selected (negotiation demonstration).
2. PQC preferred, server supports only ECDH: permitted fallback to ECDH.
3. Hybrid required, server lacks hybrid: negotiation is rejected.

It also runs a real X25519 shared-secret check.

## Run tests

```powershell
pytest -q
```

## Project structure

- `core/crypto_api.py`: stable application-facing interface
- `core/algorithm_registry.py`: supported mechanism metadata
- `core/policy_engine.py`: policy validation and permitted algorithms
- `core/negotiation.py`: deterministic capability negotiation
- `providers/classical.py`: real X25519 shared-secret example
- `providers/pqc.py`: PQC capability adapter placeholder
- `providers/hybrid.py`: hybrid capability adapter placeholder
- `client/client.py`, `server/server.py`: TCP capability exchange
- `tests/`: automated tests

## Next implementation milestones

1. Replace the PQC capability placeholder with an actual ML-KEM provider (OpenSSL 3.5+
   or a compatible liboqs binding).
2. Implement a standardized hybrid key combiner using the component shared secrets and
   a suitable KDF, following the selected protocol specification.
3. Authenticate and bind negotiation messages to the secure-channel handshake.
4. Add TLS 1.3 integration and interoperability tests.
5. Add performance measurements and key/certificate lifecycle management.
