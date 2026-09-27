# Secure E2E Encrypted P2P File Transfer CLI

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Security: ChaCha20-Poly1305](https://img.shields.io/badge/Security-ChaCha20--Poly1305-green?style=flat&logo=lock)](https://cryptography.io/)
[![Key Exchange: ECDH P-256](https://img.shields.io/badge/ECDH-P--256-blue?style=flat)](https://cryptography.io/)
[![Async Engine: asyncio](https://img.shields.io/badge/Async-asyncio-orange?style=flat)](https://docs.python.org/3/library/asyncio.html)
[![Tests: 29 Passed](https://img.shields.io/badge/Tests-29%20Passed-brightgreen?style=flat&logo=pytest)](https://docs.pytest.org/)

A high-performance, production-grade end-to-end encrypted peer-to-peer (P2P) file transfer command-line tool built in Python 3.12. Designed for privacy, speed, and reliability, it enables direct client-to-client streaming without storing unencrypted files or private keys on any central infrastructure.

---

## Architecture Overview

The system uses a **hybrid network topology**: a central WebSocket signaling relay handles room creation, peer discovery, and initial key exchange, after which sender and receiver establish a **direct TCP socket connection** for encrypted payload streaming.

```text
       SENDER PEER                               SIGNALING SERVER                             RECEIVER PEER
 ┌──────────────────────┐                     ┌────────────────────┐                     ┌──────────────────────┐
 │  p2p-transfer send   │ ── 1. Create Room ─>│  WebSocket Relay   │                     │ p2p-transfer receive │
 │                      │ <─ 2. 6-Digit Code ─│   (ws://...:8765)  │ <─ 3. Join Room ─── │                      │
 │                      │                     │                    │    (with Code)      │                      │
 │                      │ <─────────── 4. Exchange ECDH Public Keys ───────────────────> │                      │
 └──────────┬───────────┘                     └────────────────────┘                     └──────────┬───────────┘
            │                                                                                       │
            └─────────────────────── 5. Direct TCP Encrypted Stream ────────────────────────────────┘
                                      (ChaCha20-Poly1305 + SHA-256)
```

---

## Key Features

- **Zero-Knowledge Privacy:** Files are encrypted and decrypted locally on peer devices. The signaling server never receives encryption keys or plaintext content.
- **Ephemeral ECDH Key Exchange:** Uses Curve P-256 Elliptic Curve Diffie-Hellman to derive unique, non-reused symmetric session keys via HKDF-SHA256.
- **AEAD Symmetric Encryption:** Uses ChaCha20-Poly1305 authenticated encryption with dynamic 12-byte nonces generated per chunk to guarantee message confidentiality and integrity.
- **Async Streaming Transport:** Driven by Python's `asyncio` loop with non-blocking 64 KB chunking, ensuring constant memory utilization regardless of file size (tested up to multi-gigabyte transfers).
- **Binary Length-Prefixed Framing:** Custom TCP streaming protocol using 4-byte big-endian uint32 headers to eliminate message tearing and boundary issues over stream sockets.
- **Automated Verification & Security Hardening:** End-to-end SHA-256 checksum validation, path traversal attack sanitization (`Path(filename).name`), and automatic partial file cleanup upon premature network failure.
- **Rich Terminal UI:** Formatted output powered by `rich` and `typer`, featuring live progress bars, transfer velocity indicators, ETA calculations, and clean error displays.

---

## Cryptographic & Security Specifications

| Property | Implementation Detail | Purpose |
| :--- | :--- | :--- |
| **Asymmetric Exchange** | ECDH over Curve SECP256R1 (P-256) | Ephemeral key exchange generated per transfer |
| **Key Derivation** | HKDF-SHA256 (`info=b"p2p-file-transfer-v1"`) | Derives a strong 256-bit symmetric key from shared secret |
| **Symmetric Encryption** | ChaCha20-Poly1305 (AEAD) | High-speed authenticated encryption with 12-byte per-chunk nonces |
| **Frame Protocol** | 4-byte uint32 Big-Endian Prefix | Handles streaming chunk boundaries cleanly |
| **Integrity Check** | SHA-256 | Bitwise verifying file authenticity post-transfer |
| **Path Traversal Shield** | `Path(file_name).name` | Strips relative/absolute path escaping attempts (`../../`) |
| **Cleanup Protocol** | Immediate Unlink | Partial/corrupted transfers are automatically purged on error |

---

## Performance & Benchmarks

Benchmarked on Windows 11 (Intel Core i7, NVMe SSD, loopback networking):

| Metric | Result |
| :--- | :--- |
| **100 MB File Transfer Speed** | **177.5 MB/s** |
| **100 MB Transfer Time** | **~0.56 seconds** |
| **Peak Memory Footprint** | **< 50 MB** (constant chunked buffer) |
| **Test Suite Execution** | **29 tests passed in ~1.1 seconds** |

---

## Repository Structure

```text
python-p2p-file-transfer/
├── p2p_transfer/
│   ├── __init__.py
│   ├── cli.py             # Typer CLI application (send, receive, server commands)
│   ├── crypto.py          # Ephemeral ECDH keypair generation, HKDF, ChaCha20-Poly1305
│   ├── transfer.py        # Async chunked disk I/O and SHA-256 hashing
│   ├── network.py         # Async TCP length-prefixed framing & encrypted streaming
│   └── signaling.py       # WebSocket client and base64 payload encoding
├── signaling_server.py    # Standalone WebSocket relay for peer pairing
├── tests/
│   ├── test_crypto.py     # Unit tests for cryptographic primitives
│   ├── test_transfer.py   # Unit tests for chunked I/O and hash verification
│   ├── test_signaling.py  # Integration tests for WebSocket room state
│   ├── test_network.py    # Integration tests for encrypted TCP socket transfer
│   ├── test_cli.py        # CLI command runner tests
│   └── test_edge_cases.py # Security path traversal & interruption resilience tests
├── pytest.ini             # Pytest configuration (asyncio support)
├── requirements.txt       # Project dependencies
└── README.md              # Project documentation
```

---

## Quickstart & Installation

### 1. Prerequisites
- Python 3.12+
- `pip` package manager

### 2. Setup Virtual Environment
```powershell
# Clone repository
git clone https://github.com/your-username/python-p2p-file-transfer.git
cd python-p2p-file-transfer

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1
# On Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Usage Guide

### Step 1: Start the Signaling Server
Run the signaling server locally or on a public relay node:
```powershell
python -m p2p_transfer.cli server --port 8765
```

### Step 2: Send a File
On the host machine containing the source file:
```powershell
python -m p2p_transfer.cli send ./document.pdf --server-url ws://localhost:8765/signaling
```
> The terminal will display a prominent **6-digit pairing code** (e.g. `JGP1OO`).

### Step 3: Receive the File
On the destination machine:
```powershell
python -m p2p_transfer.cli receive JGP1OO --output-dir ./downloads --server-url ws://localhost:8765/signaling
```

---

## Testing & Quality Assurance

The project includes an automated test suite covering unit operations, end-to-end socket transports, CLI commands, and security edge cases.

To execute the test suite:

```powershell
python -m pytest -v
```

### Verified Test Categories
- **`test_crypto.py`**: Keypair generation, PEM encoding/decoding, HKDF derivation, ChaCha20-Poly1305 encryption/decryption round-trips.
- **`test_transfer.py`**: Non-blocking chunk streaming, streaming SHA-256 calculation, corrupt chunk detection.
- **`test_signaling.py`**: WebSocket room generation, pairing code resolution, isolated peer message routing.
- **`test_network.py`**: 4-byte length-prefixed TCP binary framing and multi-megabyte socket streaming.
- **`test_cli.py`**: Typer command parameter parsing and rich output rendering.
- **`test_edge_cases.py`**: Path traversal attack prevention (`../../evil_script.py`), 0-byte file handling, UTF-8/Emoji filename preservation, and unexpected connection drop cleanup.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.