# IACP Protocol Prototype

**Internet Agent Communication Protocol (IACP)** — A reference implementation prototype for secure, identity-based communication between autonomous AI agents.

[![IETF Draft](https://img.shields.io/badge/IETF-Draft--03-blue)](https://datatracker.ietf.org/doc/draft-gebauer-iacp/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## What is IACP?

The **Internet Agent Communication Protocol (IACP)** is a new Internet protocol designed specifically for communication between autonomous AI agents. As AI agents become the majority of Internet users, traditional protocols (HTTP, WebSocket, gRPC) lack:

- **Identity-Locator Separation** (§3.3): An agent's cryptographic identity (EID) is independent of its IP address
- **Self-Certifying Identities** (§3.2): The EID *is* the public key — no certificate authorities needed
- **Persistent State Sessions** (§6.4): Long-lived, encrypted channels with Dual-Cookie handshake
- **Sequence Vector Reconciliation** (§6.4.5): Fault-tolerant state recovery after crashes
- **Decentralized Governance** (§4.2.7): Proof of Malfeasance (PoM) and Two-Phase Slashing Escrow (2PSE)

This prototype implements the **core protocol stack**: EID → ERP → PSS, enabling two LLM-powered AI agents to communicate securely and autonomously.

---

## Quick Start

### Prerequisites

```bash
# 1. Install Ollama (https://ollama.com)
# 2. Pull a small model:
ollama pull phi3:mini

# 3. Install Python package:
pip install ollama
```

### Run the Demo

```bash
# Start Ollama (if not already running):
ollama serve

# In another terminal, run the free discussion demo:
python demo_free.py
```

Two AI agents will start a completely free, unscripted conversation via IACP. Press `Ctrl+C` to stop.

### Alternative: Structured Demo

```bash
python demo_final.py
```

This runs a structured demo with predefined questions about AI alignment and safety.

---

## Architecture

```
+---------------------+       IACP PSS        +---------------------+
|   Agent A (Python)  | <===================> |   Agent B (Python)  |
|   (phi3:mini)       |   AES-GCM-256 enc.    |   (phi3:mini)       |
+---------------------+                       +---------------------+
         |                                              |
         v                                              v
+---------------------+                       +---------------------+
|   IACP Protocol     |                       |   IACP Protocol     |
|   (EID + ERP + PSS) |                       |   (EID + ERP + PSS) |
+---------------------+                       +---------------------+
         |                                              |
         v                                              v
+-----------------------------------------------------------+
|                    TCP Transport Layer                    |
|              (JSON frames over TCP, newline-delimited)    |
+-----------------------------------------------------------+
```

### Protocol Flow

```
Agent A (Initiator)                    Agent B (Responder)
       |                                       |
       |  === ERP Handshake ===                |
       |  ERP_INIT (with nonce)                |
       |-------------------------------------->|
       |  ERP_ALLOC (with slot)                |
       |<--------------------------------------|
       |  ERP_REGISTER (signed)                |
       |-------------------------------------->|
       |  ERP_ACK (signed)                     |
       |<--------------------------------------|
       |                                       |
       |  === PSS Handshake ===                |
       |  PSS_INIT (with I-Cookie)             |
       |-------------------------------------->|
       |  PSS_NEG (with I-Cookie + R-Cookie)   |
       |<--------------------------------------|
       |  PSS_ACK (cookies confirmed)          |
       |-------------------------------------->|
       |                                       |
       |  === Encrypted Data ===               |
       |  PSS_DATA (seq=N, encrypted payload)  |
       |-------------------------------------->|
       |  PSS_DATA (seq=N+1, encrypted reply)  |
       |<--------------------------------------|
```

---

## Requirements

- **Python 3.10+**
- **Ollama** (https://ollama.com) — for local LLM inference
- **phi3:mini** model (`ollama pull phi3:mini`)
- **ollama Python package** (`pip install ollama`)

---

## How It Works

### 1. Identity (EID)

Each agent generates a unique 32-byte cryptographic identity on startup:

```python
eid_a = generate_eid()  # e.g. "a1b2c3d4e5f6..."
eid_b = generate_eid()  # e.g. "9f8e7d6c5b4a..."
```

### 2. Handshake (ERP + PSS)

The agents perform a 7-message handshake to establish a secure session:

1. **ERP_INIT**: Initiator sends its EID with a random nonce
2. **ERP_ALLOC**: Responder allocates a slot, returns its EID
3. **ERP_REGISTER**: Initiator confirms the registration (signed)
4. **ERP_ACK**: Responder acknowledges (signed)
5. **PSS_INIT**: Initiator sends an I-Cookie (random 8 bytes)
6. **PSS_NEG**: Responder adds an R-Cookie (random 8 bytes)
7. **PSS_ACK**: Initiator confirms both cookies

### 3. Encrypted Communication

After the handshake, all messages are encrypted:

```python
session_key = SHA256(I-Cookie + R-Cookie + sorted_EIDs)
encrypted = XOR(plaintext, session_key) + HMAC(encrypted)
```

Each message includes a monotonically increasing sequence number to prevent replay attacks.

### 4. Free Discussion

Both agents use phi3:mini (via Ollama) to generate responses. Each agent sees the last 8 messages as context, allowing the conversation to develop organically.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Author

**Leonard Gebauer** — Independent  
Email: leonard.gebauer.ha@gmail.com  
IETF Draft: [draft-gebauer-iacp-03](https://datatracker.ietf.org/doc/draft-gebauer-iacp/)

---

## Acknowledgments

- Aaron Jerskey, ANML Foundation
- Dr. Iman Schrock, EMILIA Protocol
- The IETF community for their feedback and guidance

NOTE FROM AUTHOR: THE BASIS OF THE PROTOTYPE CODE HAS BEEN MADE BY AN AI AND EDITED BY THE AUTHOR, INLCUDING THIS DOCUMENT.