# IACP – Internet Agent Communication Protocol  
## Cross-Network Prototype – Complete Setup & Operations Guide

**Repository:** https://github.com/L-G-0-1/IACP  
**IETF Draft:** [draft-gebauer-iacp-03](https://datatracker.ietf.org/doc/draft-gebauer-iacp/)  
**Language:** Python 3.10+  
**Author:** Leonard Gebauer  

This document is the single, end-to-end reference for turning a blank machine into a working **cross-network IACP prototype**. It starts with installing programming languages and tools, continues through downloading models and the prototype itself, and ends with detailed instructions for simulating two separate networks on one PC (Docker, network namespaces, dual VMs). Every step is written so that a careful reader can follow it without prior knowledge of the stack.

---

## Table of contents

1. [What this prototype is (and is not)](#1-what-this-prototype-is-and-is-not)
2. [Hardware and software requirements](#2-hardware-and-software-requirements)
3. [Install Python](#3-install-python)
4. [Install Git](#4-install-git)
5. [Clone the prototype](#5-clone-the-prototype)
6. [Python virtual environment and dependencies](#6-python-virtual-environment-and-dependencies)
7. [Install and run Ollama (optional LLM)](#7-install-and-run-ollama-optional-llm)
8. [Download the language model](#8-download-the-language-model)
9. [First smoke tests (no network)](#9-first-smoke-tests-no-network)
10. [Local same-machine relay test (one PC, one network)](#10-local-same-machine-relay-test-one-pc-one-network)
11. [Direct TCP test (LAN)](#11-direct-tcp-test-lan)
12. [Simulating two separate networks on one PC](#12-simulating-two-separate-networks-on-one-pc)
    - 12.1 [Option A – Docker Compose (recommended)](#121-option-a--docker-compose-recommended)
    - 12.2 [Option B – Linux network namespaces](#122-option-b--linux-network-namespaces)
    - 12.3 [Option C – Two virtual machines](#123-option-c--two-virtual-machines)
    - 12.4 [Option D – Windows Hyper-V / WSL2 dual instances](#124-option-d--windows-hyper-v--wsl2-dual-instances)
13. [True cross-NAT test (two real machines or cloud)](#13-true-cross-nat-test-two-real-machines-or-cloud)
14. [Desktop GUI](#14-desktop-gui)
15. [File map and what each file does](#15-file-map-and-what-each-file-does)
16. [Protocol features implemented](#16-protocol-features-implemented)
17. [Troubleshooting](#17-troubleshooting)
18. [Security and prototype limits](#18-security-and-prototype-limits)
19. [License and references](#19-license-and-references)

---

## 1. What this prototype is (and is not)

This repository is a **working prototype** of the Internet Agent Communication Protocol (IACP). Two (or more) independent agent processes can:

- generate self-certifying Ephemeral Agent Identities (EID),
- register presence on a discovery server by topic,
- establish a Persistent State Session (PSS) with dual-cookie handshake,
- exchange ordered, integrity-protected messages,
- do all of the above **over a pure HTTP relay** when direct TCP is impossible (NAT, firewall, different networks).

It is **not**:

- a production-ready cryptographic implementation (signatures on the wire path use HMAC with the EID string as key for the prototype; real Ed25519 is available when the `cryptography` package is installed for internal managers),
- a full DHT overlay in production form (in-process Kademlia-style store for demos),
- a substitute for reading the IETF draft.

The relay path is real protocol logic: envelopes, signatures, sequence numbers, replay rejection, and an inbox so that handshake and data frames that arrive in the same poll batch are not discarded.

---

## 2. Hardware and software requirements

| Item    | Minimum                                                        | Recommended                                               |
|---------|----------------------------------------------------------------|-----------------------------------------------------------|
| CPU     | 2 cores                                                        | 4+ cores                                                  |
| RAM     | 4 GB (without LLM) / 8 GB (with phi3:mini)                     | 16 GB                                                     |
| Disk    | 5 GB free                                                      | 20 GB free (models + Docker images)                       |
| OS      | Windows 10/11, macOS 12+, Ubuntu 22.04+, Debian 12, Fedora 39+ | Same                                                      |
| Network | Loopback only for local tests; outbound HTTP for relay         | Optional second NIC / Docker networks for isolation demos |

Required software you will install in the following sections:

- Python 3.10 or newer (3.11 / 3.12 preferred)
- Git
- Optional: Ollama + a small chat model (phi3:mini)
- Optional for dual-network simulation: Docker Desktop or Docker Engine + Compose
- Optional: VirtualBox / Hyper-V / QEMU for full VMs

IMPORTANT NOTE: THERE MAY BE FILES THAT ARE ALREADY IN THE REPOSITORY BUT THAT THE README TELLS YOU TO CREATE, IF YOU FEEL CONFIDENT YOU CAN JUST KEEP THOSE FROM THE REPO, IF NOT, YOU CAN JUST FOLLOW THE README STEP BY STEP.

---

## 3. Install Python

### 3.1 Windows

1. Open https://www.python.org/downloads/windows/
2. Download the latest **Python 3.12.x** Windows installer (64-bit).
3. Run the installer.
4. **Important:** check the box **“Add python.exe to PATH”** on the first screen.
5. Choose “Install Now” (or Customize and enable pip + tcl/tk for the GUI).
6. Close and reopen PowerShell (or Windows Terminal).
7. Verify:

```powershell
python --version
# expected: Python 3.12.x (or 3.11.x / 3.10.x)

python -m pip --version
```

If `python` is not found, use the full path or the `py` launcher:

```powershell
py -3.12 --version
py -3.12 -m pip --version
```

### 3.2 macOS

Prefer the official installer or Homebrew.

**Homebrew (recommended):**

```bash
# Install Homebrew if needed: https://brew.sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install python@3.12
python3.12 --version
python3.12 -m pip --version
```

**Official installer:** https://www.python.org/downloads/macos/

### 3.3 Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-tk
python3 --version
```

On Ubuntu 22.04 the default may be 3.10, which is fine. For 3.12:

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3.12-tk
```

### 3.4 Fedora

```bash
sudo dnf install -y python3 python3-pip python3-tkinter
python3 --version
```

---

## 4. Install Git

### Windows

Download Git for Windows: https://git-scm.com/download/win  
Use the default options. After install, open a **new** PowerShell:

```powershell
git --version
```

### macOS

```bash
# Xcode CLT or Homebrew
xcode-select --install
# or
brew install git
git --version
```

### Linux

```bash
sudo apt install -y git    # Debian/Ubuntu
sudo dnf install -y git    # Fedora
git --version
```

---

## 5. Clone the prototype

Choose a working directory. Examples:

```text
Windows:  C:\IETF\Projekte\IACP
macOS:    ~/Projects/IACP
Linux:    ~/src/IACP
```

### Clone

```bash
# Create parent folder if you want
mkdir -p ~/src   # or the Windows equivalent
cd ~/src

git clone https://github.com/L-G-0-1/IACP.git
cd IACP
```

Windows PowerShell:

```powershell
mkdir C:\IETF\Projekte -Force
cd C:\IETF\Projekte
git clone https://github.com/L-G-0-1/IACP.git
cd IACP
```

If the repository layout uses a subdirectory for the demo (for example `iacp-demo-04`), enter that directory:

```bash
ls
# look for agent_a.py, agent_b.py, discovery_server.py, iacp_protocol.py
# if they live in a subfolder:
cd iacp-demo-04   # only if that folder exists
```

You should see at least:

```text
agent_a.py
agent_b.py
discovery_server.py
iacp_protocol.py
demo_core.py
demo_discovery.py
debug_relay.py
README.md
```

---

## 6. Python virtual environment and dependencies

Always use a virtual environment so system Python stays clean.

### Create and activate

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# If execution policy blocks activation:
# Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**Windows (cmd.exe):**

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Your prompt should show `(.venv)`.

### Install packages

Core prototype needs only the standard library plus optional packages:

```bash
python -m pip install --upgrade pip

# Recommended for real Ed25519 / X25519 / AES-GCM / HKDF
python -m pip install cryptography

# Optional: LLM conversation content
python -m pip install ollama

# Optional: GUI is pure Tkinter (usually bundled with Python)
# On some Linux distros: sudo apt install python3-tk
```

There is no mandatory `requirements.txt` beyond that. If a `requirements.txt` is present in the repo:

```bash
python -m pip install -r requirements.txt
```

Verify imports:

```bash
python -c "from iacp_protocol import perform_relay_handshake, RelayTransport; print('OK')"
```

---

## 7. Install and run Ollama (optional LLM)

Ollama is only required if you want the agents to generate natural-language replies. Discovery, handshake, and relay work **without** Ollama.

### Windows

1. Download the installer from https://ollama.com/download  
2. Run it and finish the setup.  
3. Ollama usually starts as a background service on `http://127.0.0.1:11434`.

Check:

```powershell
ollama --version
curl http://127.0.0.1:11434/api/tags
```

### macOS

```bash
# Official app: https://ollama.com/download
# or Homebrew:
brew install ollama
ollama serve
```

### Linux

```bash
curl -fsSL https://ollama.com/install.sh | sh
# Start the service (systemd on many distros):
sudo systemctl enable --now ollama
# or foreground:
ollama serve
```

Leave `ollama serve` running in a dedicated terminal if it is not a system service.

---

## 8. Download the language model

With Ollama running:

```bash
ollama pull phi3:mini
```

`phi3:mini` is small enough for laptops (on the order of ~2 GB download). Alternatives:

```bash
ollama pull llama3.2:1b
ollama pull qwen2.5:1.5b
```

List local models:

```bash
ollama list
```

Quick functional check:

```bash
ollama run phi3:mini "Reply with exactly: hello from ollama"
```

If this hangs or fails, fix Ollama before expecting LLM text in the agents. Protocol tests do not depend on it.

---

## 9. First smoke tests (no network)

Activate the venv, stay in the project directory.

### Protocol self-test inside `iacp_protocol.py`

```bash
python iacp_protocol.py
```

Expect lines ending with `=== All Self-Tests Passed ===`.

### Core component walkthrough

```bash
python demo_core.py
```

Expect reputation, PSS, ESE, PoM, migration sections and a successful completion message.

### Full discovery-oriented demo

```bash
python demo_discovery.py
```

Expect DHT, discovery spaces, anonymous discovery, forwarding tickets, and again a success banner.

### Relay unit suite (offline mock + optional live)

```bash
python debug_relay.py --skip-demo
```

All checks should report PASS. With a running discovery server later:

```bash
python debug_relay.py --skip-demo --live http://127.0.0.1:8888
```

---

## 10. Local same-machine relay test (one PC, one network)

This is the primary prototype path: both agents talk **only** via HTTP to the discovery/relay server. No direct TCP between agents is required.

Open **three** terminals. Activate the venv in each.

### Terminal 1 – Discovery / Relay server

```bash
python discovery_server.py
# or: python discovery_server.py 8888
```

You should see the server listening on `0.0.0.0:8888` and a list of endpoints (`/register`, `/discover`, `/relay_register`, `/relay`, `/relay_poll`, `/health`).

### Terminal 2 – Agent B (responder)

```bash
python agent_b.py --relay http://127.0.0.1:8888 --topic knowledge --rounds 3
```

Wait until you see:

```text
[Agent B] Registered on relay ...
[Agent B] Presence registered on topic 'knowledge'
[Agent B] Waiting for initiators on relay ...
```

### Terminal 3 – Agent A (initiator)

```bash
python agent_a.py --relay http://127.0.0.1:8888 --discover http://127.0.0.1:8888 --topic knowledge --rounds 3
```

Expected sequence:

1. A registers on the relay.  
2. A discovers B’s EID via topic `knowledge`.  
3. Relay PSS handshake completes on both sides.  
4. A few message rounds (with real LLM text if Ollama is up, otherwise fallback strings).  
5. Sessions close cleanly after `--rounds 3`.

Without `--rounds`, the conversation continues until you press Ctrl+C.

### Optional: fixed peer EID

If discovery is not used:

```bash
# On B, note the printed EID, then on A:
python agent_a.py --relay http://127.0.0.1:8888 --peer-eid <full_hex_eid_of_B> --rounds 3
```

---

## 11. Direct TCP test (LAN)

Same machine or two machines on the same LAN.

### Responder

```bash
python agent_b.py --bind 0.0.0.0:4001
```

### Initiator

```bash
python agent_a.py --peer 127.0.0.1:4001
# or peer 192.168.x.y:4001 on another host
```

Handshake and conversation use the TCP path (`perform_handshake` / `send_data` / `recv_data`).

With discovery for TCP (responder advertises IP:port):

```bash
# Terminal 1
python discovery_server.py

# Terminal 2
python agent_b.py --bind 0.0.0.0:4001 --discover http://127.0.0.1:8888 --topic knowledge

# Terminal 3
python agent_a.py --discover http://127.0.0.1:8888 --topic knowledge
```

Note: pure TCP discovery still needs a reachable IP and open port. Relay mode does not.

---

## 12. Simulating two separate networks on one PC

Goal: Agent A and Agent B must **not** be able to open a direct TCP connection to each other; they may only reach a shared relay. That is the cross-network prototype condition.

Below are four practical approaches, ordered by ease of use.

### 12.1 Option A – Docker Compose (recommended)

#### Install Docker

- **Windows / macOS:** install [Docker Desktop](https://www.docker.com/products/docker-desktop/). Enable WSL2 backend on Windows if prompted.  
- **Linux:** install Docker Engine and the Compose plugin:

```bash
# Ubuntu example – follow current docs on docs.docker.com for your distro
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER
# log out and back in
docker version
docker compose version
```

#### Project files for dual-network simulation

Create a file `Dockerfile` in the project root:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt* ./
RUN pip install --no-cache-dir cryptography ollama || true
COPY . .
ENV PYTHONUNBUFFERED=1
CMD ["python", "discovery_server.py"]
```

Create `docker-compose.crossnet.yml`:

Variant 1 – Without LLM

```yaml
services:
  relay:
    build: .
    command: ["python", "discovery_server.py", "8888"]
    networks:
      - net_shared
    ports:
      - "8888:8888"

  agent_b:
    build: .
    command:
      [
        "python", "agent_b.py",
        "--relay", "http://relay:8888",
        "--topic", "knowledge",
        "--rounds", "3"
      ]
    depends_on:
      - relay
    networks:
      - net_b
      - net_shared

  agent_a:
    build: .
    command:
      [
        "python", "agent_a.py",
        "--relay", "http://relay:8888",
        "--discover", "http://relay:8888",
        "--topic", "knowledge",
        "--rounds", "3"
      ]
    depends_on:
      - relay
      - agent_b
    networks:
      - net_a
      - net_shared

networks:
  net_a:
    driver: bridge
    internal: false
  net_b:
    driver: bridge
    internal: false
  net_shared:
    driver: bridge
```

Variant 2 – With LLM

```yaml
services:
  # -------------------------------------------------
  # Ollama – LLM service (shared network only)
  # -------------------------------------------------
  ollama:
    image: ollama/ollama:latest
    container_name: crossnet-ollama
    volumes:
      - ollama_data:/root/.ollama          # persist models across restarts
    networks:
      - net_shared
    healthcheck:
      test: ["CMD", "ollama", "list"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 20s

  # -------------------------------------------------
  # Shared relay
  # -------------------------------------------------
  relay:
    build: .
    command: ["python", "discovery_server.py", "8888"]
    networks:
      - net_shared
    ports:
      - "8888:8888"
    depends_on:
      - ollama

  # -------------------------------------------------
  # Agent B
  # -------------------------------------------------
  agent_b:
    build: .
    command:
      [
        "python", "agent_b.py",
        "--relay", "http://relay:8888",
        "--topic", "knowledge",
        "--rounds", "3"
      ]
    environment:
      - OLLAMA_HOST=http://ollama:11434
    depends_on:
      relay:
        condition: service_started
      ollama:
        condition: service_healthy
    networks:
      - net_b
      - net_shared

  # -------------------------------------------------
  # Agent A
  # -------------------------------------------------
  agent_a:
    build: .
    command:
      [
        "python", "agent_a.py",
        "--relay", "http://relay:8888",
        "--discover", "http://relay:8888",
        "--topic", "knowledge",
        "--rounds", "3"
      ]
    environment:
      - OLLAMA_HOST=http://ollama:11434
    depends_on:
      relay:
        condition: service_started
      agent_b:
        condition: service_started
      ollama:
        condition: service_healthy
    networks:
      - net_a
      - net_shared

networks:
  net_a:
    driver: bridge
  net_b:
    driver: bridge
  net_shared:
    driver: bridge

volumes:
  ollama_data:
```

One-time model download (after the first start of the ollama service):

```bash
docker compose -f docker-compose.crossnet-ollama.yml up -d ollama
# wait ~15–30 seconds until the healthcheck passes
docker exec -it crossnet-ollama ollama pull phi3:mini
```
Agents now receive real LLM replies instead of the fallback error strings. The network isolation remains identical to Variant 1: A and B still share only net_shared and can talk only via the relay.


Explanation:

Meaning of the networks:

- `net_a` – only Agent A (plus the shared relay network).  
- `net_b` – only Agent B.  
- `net_shared` – both agents and the relay.  

Agent A and Agent B do **not** share a common network except `net_shared`, where only the relay listens. They cannot open a direct TCP session to each other’s container IP on a private bridge.

#### Build and run

```bash
docker compose -f docker-compose.crossnet.yml build
docker compose -f docker-compose.crossnet.yml up
```

Watch the logs. You should see registration, discovery, PSS over relay, and message rounds. Stop with Ctrl+C, then:

```bash
docker compose -f docker-compose.crossnet.yml down
```

#### Stricter isolation (optional)

Mark `net_a` and `net_b` as `internal: true` and attach the relay only to `net_shared`. Then A and B can only talk to services on `net_shared` (the relay), never to arbitrary Internet hosts from those networks. Adjust the compose file accordingly if you need that policy.

#### Optional: no LLM in containers

The default agent commands work without Ollama. Container images above do not include the Ollama daemon. Message bodies will be the built-in fallback strings. That is enough to prove the cross-network path.

### 12.2 Option B – Linux network namespaces

Requires root on a Linux host. No Docker needed.

```bash
# Create namespaces
sudo ip netns add ns_a
sudo ip netns add ns_b
sudo ip netns add ns_relay

# Virtual ethernet pairs
sudo ip link add veth_a0 type veth peer name veth_a1
sudo ip link add veth_b0 type veth peer name veth_b1
sudo ip link add veth_r0 type veth peer name veth_r1

# Move ends into namespaces
sudo ip link set veth_a1 netns ns_a
sudo ip link set veth_b1 netns ns_b
sudo ip link set veth_r1 netns ns_relay

# Bridge for the "shared" segment (relay side)
sudo ip link add name br_shared type bridge
sudo ip link set veth_a0 master br_shared
sudo ip link set veth_b0 master br_shared
sudo ip link set veth_r0 master br_shared
sudo ip link set br_shared up
sudo ip link set veth_a0 up
sudo ip link set veth_b0 up
sudo ip link set veth_r0 up

# Address the namespace ends
sudo ip netns exec ns_a ip addr add 10.10.0.10/24 dev veth_a1
sudo ip netns exec ns_a ip link set veth_a1 up
sudo ip netns exec ns_a ip link set lo up

sudo ip netns exec ns_b ip addr add 10.10.0.20/24 dev veth_b1
sudo ip netns exec ns_b ip link set veth_b1 up
sudo ip netns exec ns_b ip link set lo up

sudo ip netns exec ns_relay ip addr add 10.10.0.1/24 dev veth_r1
sudo ip netns exec ns_relay ip link set veth_r1 up
sudo ip netns exec ns_relay ip link set lo up
```

Run processes:

```bash
# Terminal 1
sudo ip netns exec ns_relay bash -c 'cd /path/to/IACP && source .venv/bin/activate && python discovery_server.py 8888'

# Terminal 2
sudo ip netns exec ns_b bash -c 'cd /path/to/IACP && source .venv/bin/activate && python agent_b.py --relay http://10.10.0.1:8888 --topic knowledge --rounds 3'

# Terminal 3
sudo ip netns exec ns_a bash -c 'cd /path/to/IACP && source .venv/bin/activate && python agent_a.py --relay http://10.10.0.1:8888 --discover http://10.10.0.1:8888 --topic knowledge --rounds 3'
```

Cleanup:

```bash
sudo ip netns del ns_a
sudo ip netns del ns_b
sudo ip netns del ns_relay
sudo ip link del br_shared
```

To prove isolation, try `ping 10.10.0.20` from `ns_a` while both are up: with only the shared bridge this will succeed at L3. For stricter L3 isolation, use separate bridges and route **only** port 8888 through a small userspace proxy or iptables REDIRECT to the relay namespace. Docker’s separate bridges (Option A) are simpler for that policy.

### 12.3 Option C – Two virtual machines

1. Install VirtualBox (https://www.virtualbox.org/) or another hypervisor.  
2. Create **VM-Relay**: minimal Linux, bridged or host-only adapter, install Python + clone repo, run `discovery_server.py`. Note its IP (example `192.168.56.10`).  
3. Create **VM-A**: host-only network A, **no** route to VM-B. Install Python + clone repo.  
4. Create **VM-B**: host-only network B, **no** route to VM-A.  
5. Attach both VM-A and VM-B also to a network that can reach VM-Relay (or put the relay on a third adapter reachable from both).  
6. On VM-B:

```bash
python agent_b.py --relay http://192.168.56.10:8888 --topic knowledge --rounds 3
```

7. On VM-A:

```bash
python agent_a.py --relay http://192.168.56.10:8888 --discover http://192.168.56.10:8888 --topic knowledge --rounds 3
```

If the VMs cannot ping each other but both can HTTP to the relay, you have a valid cross-network simulation.

### 12.4 Option D – Windows Hyper-V / WSL2 dual instances

- Install two WSL2 distros (e.g. Ubuntu-A and Ubuntu-B), or one WSL2 plus a Hyper-V VM.  
- Run the relay on Windows host or a third WSL instance bound to `0.0.0.0:8888`.  
- From each distro, point `--relay` / `--discover` at the host IP as seen from WSL (`cat /etc/resolv.conf` often shows the host).  
- Firewall: allow inbound TCP 8888 on the Windows host.

WSL2 networking changes over time; if port forwarding is awkward, prefer Docker Desktop (Option A).

---

## 13. True cross-NAT test (two real machines or cloud)

1. Deploy `discovery_server.py` on a host with a public IP or a VPN endpoint (VPS, home server with port-forward of TCP 8888).  
2. On machine B (behind NAT):

```bash
python agent_b.py --relay http://PUBLIC_OR_VPN_HOST:8888 --topic knowledge --rounds 5
```

3. On machine A (different NAT):

```bash
python agent_a.py --relay http://PUBLIC_OR_VPN_HOST:8888 --discover http://PUBLIC_OR_VPN_HOST:8888 --topic knowledge --rounds 5
```

No inbound ports are required on A or B. Only outbound HTTP to the relay is used.

TLS is not enabled in this prototype. For any exposure beyond a lab, put the relay behind a reverse proxy (Caddy, nginx) with HTTPS and restrict access.

---

## 14. Desktop GUI

```bash
python iacp_app.py
```

Features:

- initiator / responder mode,
- discovery URL and topic,
- relay checkbox and URL,
- start/stop of a local discovery server,
- conversation log,
- optional LLM test button.

Relay mode in the GUI currently focuses on registration and polling visibility; full multi-round relay conversation is primarily exercised via `agent_a.py` / `agent_b.py` as in sections 10–13.

---

## 15. File map and what each file does

| File                                            | Role                                                                                                                                                         |
|-------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `iacp_protocol.py`                              | Unified protocol core: crypto helpers, DHT, reputation, PSS, ESE, PoM, 2PSE, migration, TCP wire, **relay handshake and data path**, agent class, self-tests |
| `agent_a.py`                                    | Initiator CLI – TCP and relay modes, discovery, conversation loop                                                                                            |
| `agent_b.py`                                    | Responder CLI – TCP listen and relay accept loop, one session per peer EID                                                                                   |
| `discovery_server.py`                           | HTTP discovery registry + relay queues (`/register`, `/discover`, `/relay_*`)                                                                                |
| `demo_core.py`                                  | In-process demo of reputation, PSS, ESE, PoM, migration                                                                                                      |
| `demo_discovery.py`                             | In-process demo of DHT, discovery spaces, anonymous discovery, tickets                                                                                       |
| `demo_network.py`                               | Launcher that starts discovery + agents (TCP-oriented)                                                                                                       |
| `debug_relay.py`                                | Automated relay checks (mock queue + optional live server)                                                                                                   |
| `debug_pss.py`                                  | Small PSS signature debug helper                                                                                                                             |
| `iacp_app.py`                                   | Tkinter desktop console                                                                                                                                      |
| `iacp_demo_visualizer.py`                       | Graphical protocol walkthrough                                                                                                                               |
| `IACP_Core.py`, `IACP_DHT.py`, `iacp_direct.py` | Legacy modules; superseded by `iacp_protocol.py`                                                                                                             |
| `README.md`                                     | This document                                                                                                                                                |
| `bof_live_demo.py`                              | Multi-agent in-process session illustration                                                                                                                  |

---

## 16. Protocol features implemented

Aligned with draft-gebauer-iacp-03 themes:

- EID generation and wire identity  
- ERP-style allocation/register flow on the TCP path  
- PSS dual-cookie handshake (TCP and relay)  
- Ordered `PSS_DATA` with sequence and integrity checks  
- Discovery by topic and relay registration  
- Relay transport for NAT traversal  
- Reputation EMA, PoM, 2PSE, migration generation counting (in-process managers)  
- Token bucket and circuit breaker helpers  
- Optional DHI content-equivalence helpers  

See the draft for normative definitions. This repository is a prototype, not a conformance suite.

---

## 17. Troubleshooting

### `ModuleNotFoundError: iacp_protocol`

Run commands from the directory that contains `iacp_protocol.py`, with the venv activated.

### Relay registration failed

- Is `discovery_server.py` running?  
- Is the URL correct (`http://127.0.0.1:8888` vs container DNS name `http://relay:8888`)?  
- Firewall blocking outbound HTTP?

### Handshake timeout

- Both agents must use the **same** relay base URL.  
- B must finish “Presence registered” before A’s discovery loop gives up (A retries for ~40 seconds).  
- Check server logs for `/relay` and `/relay_poll` activity.

### Data timeout after successful handshake

Ensure you are on a build that includes the **inbox** in `RelayTransport` (unmatched envelopes from a poll batch are re-queued). Update from the repository if your tree is older.

### Ollama errors in the conversation

Protocol still works; only message content falls back. Start `ollama serve` and `ollama pull phi3:mini`.

### Docker: agents exit immediately

Run `docker compose -f docker-compose.crossnet.yml logs agent_a` and `... agent_b`. Common causes: wrong working directory in the image, missing files in `COPY`, or relay not ready—`depends_on` does not wait for the HTTP port; restart A after the relay is up, or add a short retry loop (already present in agent A discovery).

### Windows: script execution disabled

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Port 8888 already in use

```bash
python discovery_server.py 8899
# then point agents at http://127.0.0.1:8899
```

---

## 18. Security and prototype limits

- Wire signatures for the agent TCP/relay path use HMAC over the EID string. Treat this as a **lab prototype**.  
- Discovery registration is unsigned in this version.  
- Relay cookies are bearer secrets; protect the relay URL.  
- No TLS on the discovery server; terminate TLS at a reverse proxy if exposed.  
- Do not use this code to protect real secrets or production agent traffic without a full cryptographic redesign per the draft (Ed25519, proper session keys, authenticated discovery).

---

## 19. License and references

- IETF draft: https://datatracker.ietf.org/doc/draft-gebauer-iacp/  
- Source: https://github.com/L-G-0-1/IACP  
- Copyright and license terms: follow the repository `LICENSE` file and IETF Trust provisions for code extracted from Internet-Drafts where applicable.

---

## Quick command cheat sheet

```bash
# venv
python -m venv .venv && source .venv/bin/activate   # Linux/macOS
python -m venv .venv && .\.venv\Scripts\Activate.ps1  # Windows

# deps
pip install cryptography ollama

# offline checks
python iacp_protocol.py
python demo_core.py
python debug_relay.py --skip-demo

# local relay (3 terminals)
python discovery_server.py
python agent_b.py --relay http://127.0.0.1:8888 --topic knowledge --rounds 3
python agent_a.py --relay http://127.0.0.1:8888 --discover http://127.0.0.1:8888 --topic knowledge --rounds 3

# docker dual-network
docker compose -f docker-compose.crossnet.yml up --build
```

End of guide.


---

## Appendix A – Glossary

| Term           | Meaning in this prototype                                                                         |
|----------------|---------------------------------------------------------------------------------------------------|
| EID            | Ephemeral Agent Identity – hex string (32 random bytes) used as agent ID on the wire              |
| PSS            | Persistent State Session – dual-cookie handshake then ordered data frames                         |
| ERP            | Endpoint Registration Protocol style frames used on the TCP path before PSS                       |
| Relay          | HTTP service that queues opaque envelopes between agents that cannot open direct TCP              |
| Discovery      | HTTP lookup of peers by topic; also used to advertise relay-only presence with port 0             |
| Topic          | String label (default `knowledge`) grouping agents that want to find each other                   |
| Session cookie | Secret string presented on every relay send/poll for that EID                                     |
| Inbox          | Local queue in `RelayTransport` holding envelopes polled but not yet consumed by the current wait |
| PoM            | Proof of Malfeasance – ticket for conflicting signed statements                                   |
| 2PSE           | Two-Phase Slashing Escrow – challenge window before reputation slash                              |
| DHI            | Deterministic Hypermedia Interpreter helpers (content equivalence)                                |
| HMAC wire path | Prototype signature for TCP/relay packets using the EID string as HMAC key                        |

---

## Appendix B – Windows step-by-step (PowerShell)

### B.1 Install Python from python.org

1. Open a browser and go to https://www.python.org/downloads/
2. Click the large yellow “Download Python 3.x.x” button.
3. Run the downloaded `python-3.x.x-amd64.exe`.
4. On the first page of the installer, enable **Add python.exe to PATH**.
5. Click **Install Now**.
6. When finished, open **Windows Terminal** or **PowerShell** (Win+X → Windows Terminal).
7. Type `python --version` and press Enter. You must see `Python 3.10` or newer.
8. Type `python -m pip --version`. Pip must print a version line.

If `python` is not recognized:

- Close and reopen the terminal (PATH is only refreshed for new sessions).
- Or use `py -3 --version` (Windows Python launcher).

### B.2 Install Git for Windows

1. https://git-scm.com/download/win  
2. Run the installer; defaults are acceptable.  
3. New terminal: `git --version`.

### B.3 Clone

```powershell
cd $env:USERPROFILE
mkdir Projects -Force
cd Projects
git clone https://github.com/L-G-0-1/IACP.git
cd IACP
dir
```

Confirm `agent_a.py`, `agent_b.py`, `discovery_server.py`, `iacp_protocol.py` are listed (or enter the subdirectory that contains them).

### B.4 Virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If you see an execution-policy error:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### B.5 Packages

```powershell
python -m pip install --upgrade pip
python -m pip install cryptography ollama
```

### B.6 Ollama on Windows

1. Download the Windows installer from https://ollama.com/download  
2. Install and let the service start.  
3. In PowerShell:

```powershell
ollama pull phi3:mini
ollama list
```

### B.7 Three-terminal local relay test on Windows

**Terminal 1:**

```powershell
cd $env:USERPROFILE\Projects\IACP
.\.venv\Scripts\Activate.ps1
python discovery_server.py
```

**Terminal 2:**

```powershell
cd $env:USERPROFILE\Projects\IACP
.\.venv\Scripts\Activate.ps1
python agent_b.py --relay http://127.0.0.1:8888 --topic knowledge --rounds 3
```

**Terminal 3:**

```powershell
cd $env:USERPROFILE\Projects\IACP
.\.venv\Scripts\Activate.ps1
python agent_a.py --relay http://127.0.0.1:8888 --discover http://127.0.0.1:8888 --topic knowledge --rounds 3
```

### B.8 Docker Desktop on Windows for dual-network

1. Install Docker Desktop from https://www.docker.com/products/docker-desktop/  
2. Enable the WSL2 backend when asked.  
3. Start Docker Desktop and wait until it reports “Running”.  
4. In PowerShell (venv not required for Docker builds):

```powershell
cd $env:USERPROFILE\Projects\IACP
docker compose -f docker-compose.crossnet.yml up --build
```

5. Read the interleaved logs. When finished:

```powershell
docker compose -f docker-compose.crossnet.yml down
```

---

## Appendix C – Ubuntu 24.04 step-by-step

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv python3-tk curl

# Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &   # or systemctl if the install enabled the service
ollama pull phi3:mini

# Project
cd ~
git clone https://github.com/L-G-0-1/IACP.git
cd IACP
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install cryptography ollama

python iacp_protocol.py
python debug_relay.py --skip-demo

# Three terminals for relay
python discovery_server.py
# elsewhere:
python agent_b.py --relay http://127.0.0.1:8888 --topic knowledge --rounds 3
python agent_a.py --relay http://127.0.0.1:8888 --discover http://127.0.0.1:8888 --topic knowledge --rounds 3
```

Docker Engine (optional):

```bash
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER
# re-login
docker compose -f docker-compose.crossnet.yml up --build
```

---

## Appendix D – macOS step-by-step

```bash
# Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python@3.12 git
brew install --cask ollama   # or download from ollama.com

ollama pull phi3:mini

git clone https://github.com/L-G-0-1/IACP.git
cd IACP
python3.12 -m venv .venv
source .venv/bin/activate
pip install cryptography ollama

python discovery_server.py
# other Terminal tabs for agent_b and agent_a as above
```

Docker Desktop for Mac: install from docker.com, then the same `docker compose -f docker-compose.crossnet.yml up --build` command.

---

## Appendix E – Expected log patterns (healthy run)

### discovery_server

```text
[Discovery] Server running on 0.0.0.0:8888
[Discovery] Relay registered: <eid>...
[Discovery] Registered: <eid>... @ 0.0.0.0:0 (knowledge)
[Discovery] Relay: <from>... -> <to>...
[Discovery] Relay poll: <eid>... received N messages
```

### agent_b (relay)

```text
[Agent B] My EID: ...
[Agent B] Registered on relay http://...
[Agent B] Presence registered on topic 'knowledge'
[Agent B] Waiting for initiators on relay ...
[Agent B] PSS with <peer>... (active: 1)
--- [<peer>] Round 1 ---
[Peer] Hello! Let's have a discussion...
[Agent B] ...
```

### agent_a (relay)

```text
[Agent A] Registered on relay ...
[Agent A] Looking up peer on topic 'knowledge'...
[Agent A] Found peer EID: ...
[Agent A] Relay handshake with ...
[Agent A] IACP PSS established over relay! Peer: ...
--- Round 1 ---
[Agent A] Starting discussion (relay)...
[Peer] ...
[Agent A] Done. 3 rounds completed.
```

If handshake succeeds but no peer messages appear, update `iacp_protocol.py` to a revision that includes `RelayTransport` inbox + `push_inbox`, and re-run `python debug_relay.py --skip-demo`.

---

## Appendix F – FAQ

**Q: Do both agents need Ollama?**  
A: No. Only message text uses the LLM. Discovery and PSS work without it.

**Q: Can I use a different topic?**  
A: Yes. Pass the same `--topic` string to A and B.

**Q: Can more than two agents join?**  
A: Agent B accepts multiple relay sessions (one worker thread per peer EID). Multiple initiators can discover the same topic; use distinct EIDs.

**Q: Is the discovery server a real DHT?**  
A: No. It is an HTTP stand-in for discovery and relay suitable for the prototype. In-process `SimpleDHT` is used inside `demo_discovery.py`.

**Q: Why port 0 in registration?**  
A: Relay-only agents have no TCP listen port. The server accepts port 0 for presence.

**Q: How do I change the relay port?**  
A: `python discovery_server.py 8899` and point agents at `http://HOST:8899`.

**Q: Does the prototype work offline?**  
A: Yes for local loopback and Docker internal networks. `agent_b` TCP mode may call `httpbin.org` only to guess an external IP for discovery registration; that call is best-effort and fails soft.

---

## Appendix G – Minimal architecture diagram (relay)

```text
┌─────────────┐       HTTP        ┌──────────────────┐       HTTP        ┌─────────────┐
│  Agent A    │ ────────────────► │ discovery_server │ ◄──────────────── │  Agent B    │
│  (net A)    │   register/poll   │  REGISTRY        │   register/poll   │  (net B)    │
│             │   send envelopes  │  RELAY_QUEUES    │   send envelopes  │             │
└─────────────┘                   └──────────────────┘                   └─────────────┘
        │                                  │                                     │
        │         no direct TCP path required between A and B                    │
        └──────────────────────────────────┴─────────────────────────────────────┘
```

Handshake and data are IACP packets wrapped in JSON envelopes, signed, queued by destination EID, and polled by the recipient.

---

## Appendix H – Checklist before a mailing-list demo

- [ ] `python iacp_protocol.py` self-test passes  
- [ ] `python debug_relay.py --skip-demo` all PASS  
- [ ] Local three-terminal relay test completes `--rounds 3`  
- [ ] Optional: `docker compose -f docker-compose.crossnet.yml up --build` completes  
- [ ] Optional: Ollama + phi3:mini for natural language  
- [ ] README and repo URL ready for participants  
- [ ] Clear statement that crypto is prototype-grade  

---

## Appendix I – Updating the prototype

```bash
cd IACP
git pull
source .venv/bin/activate   # or Windows Activate.ps1
pip install -U cryptography ollama
python debug_relay.py --skip-demo
```

If you maintain a fork, keep `iacp_protocol.py` as the single source of truth for wire and relay behaviour so agents do not drift.

---

## Appendix J – Contact and contribution

- Issues and pull requests: https://github.com/L-G-0-1/IACP  
- IETF discussion: follow the draft and relevant working-group lists  
- Author contact: as listed in the draft and repository profile  

When reporting bugs, include:

1. OS and Python version  
2. Exact command lines  
3. Full terminal output from discovery server and both agents  
4. Output of `python debug_relay.py --skip-demo`  

---

*End of README – Internet Agent Communication Protocol cross-network prototype setup guide.*


---

## Appendix K – Full network-namespace script (Linux)

Save as `scripts/crossnet_netns.sh`, make executable, run as root from the project directory (venv path adjusted).

```bash
#!/usr/bin/env bash
# crossnet_netns.sh – simulate two networks + shared relay on one Linux host
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${ROOT}/.venv/bin/activate"
RELAY_IP=10.10.0.1
A_IP=10.10.0.10
B_IP=10.10.0.20

cleanup() {
  ip netns del ns_a 2>/dev/null || true
  ip netns del ns_b 2>/dev/null || true
  ip netns del ns_relay 2>/dev/null || true
  ip link del br_shared 2>/dev/null || true
}
trap cleanup EXIT

cleanup
ip netns add ns_a
ip netns add ns_b
ip netns add ns_relay

ip link add veth_a0 type veth peer name veth_a1
ip link add veth_b0 type veth peer name veth_b1
ip link add veth_r0 type veth peer name veth_r1

ip link set veth_a1 netns ns_a
ip link set veth_b1 netns ns_b
ip link set veth_r1 netns ns_relay

ip link add name br_shared type bridge
ip link set veth_a0 master br_shared
ip link set veth_b0 master br_shared
ip link set veth_r0 master br_shared
ip link set br_shared up
ip link set veth_a0 up
ip link set veth_b0 up
ip link set veth_r0 up

ip netns exec ns_a bash -c "ip addr add ${A_IP}/24 dev veth_a1; ip link set veth_a1 up; ip link set lo up"
ip netns exec ns_b bash -c "ip addr add ${B_IP}/24 dev veth_b1; ip link set veth_b1 up; ip link set lo up"
ip netns exec ns_relay bash -c "ip addr add ${RELAY_IP}/24 dev veth_r1; ip link set veth_r1 up; ip link set lo up"

echo "Namespaces ready. Starting relay in background..."
ip netns exec ns_relay bash -c "source '${VENV}'; cd '${ROOT}'; python discovery_server.py 8888" &
RELAY_PID=$!
sleep 2

echo "Starting Agent B..."
ip netns exec ns_b bash -c "source '${VENV}'; cd '${ROOT}'; python agent_b.py --relay http://${RELAY_IP}:8888 --topic knowledge --rounds 3" &
B_PID=$!
sleep 2

echo "Starting Agent A..."
ip netns exec ns_a bash -c "source '${VENV}'; cd '${ROOT}'; python agent_a.py --relay http://${RELAY_IP}:8888 --discover http://${RELAY_IP}:8888 --topic knowledge --rounds 3"

wait $B_PID || true
kill $RELAY_PID 2>/dev/null || true
echo "Done."
```

Usage:

```bash
chmod +x scripts/crossnet_netns.sh
sudo ./scripts/crossnet_netns.sh
```

---

## Appendix L – Verifying that A and B cannot use direct TCP

After Docker or netns setup:

1. Obtain Agent B container/namespace IP.  
2. From Agent A’s network namespace or container, try:

```bash
nc -vz <B_IP> 4001
# or
python -c "import socket; s=socket.create_connection(('<B_IP>',4001),2)"
```

3. Expect **failure** if isolation is correct (no route or filtered).  
4. From the same place:

```bash
curl -s http://<RELAY_IP>:8888/health
```

Expect JSON `"status": "ok"`. That combination (relay OK, direct TCP fail) is the cross-network condition this prototype targets.

---

## Appendix M – Environment variables (optional conventions)

The stock scripts use CLI flags. If you wrap them in your own launchers, a consistent convention is:

```text
IACP_RELAY_URL=http://127.0.0.1:8888
IACP_DISCOVER_URL=http://127.0.0.1:8888
IACP_TOPIC=knowledge
IACP_ROUNDS=3
```

Example wrapper:

```bash
#!/bin/sh
python agent_a.py \
  --relay "${IACP_RELAY_URL}" \
  --discover "${IACP_DISCOVER_URL:-$IACP_RELAY_URL}" \
  --topic "${IACP_TOPIC:-knowledge}" \
  --rounds "${IACP_ROUNDS:-3}"
```

---

## Appendix N – Performance notes

- Poll interval defaults to about 0.5–1 s; latency is dominated by HTTP poll, not cryptography.  
- For demos, `--rounds 3` keeps runs short.  
- phi3:mini inference can take several seconds per reply on CPU-only machines; that is independent of IACP.  
- Relay queue max is 100 messages per destination EID in `discovery_server.py`.

---

## Appendix O – What “prototype success” means

A successful cross-network prototype run means all of the following:

1. Two agent processes with independent EIDs.  
2. No usable direct TCP path between them (or that path is simply not used).  
3. Both can complete HTTP to the same discovery/relay server.  
4. Topic discovery yields the responder’s EID.  
5. `perform_relay_handshake` completes on both sides.  
6. At least one `PSS_DATA` round-trip delivers the same plaintext the sender encrypted.  
7. Sequence/replay rules reject out-of-order and replayed frames (covered by `debug_relay.py`).

If those hold, the mailing-list demonstration of “agents behind different networks talking via IACP relay” is substantiated by the running system, not by a slide mockup.

---

*Document revision: cross-network prototype setup guide, extended appendices.*
*Note Regarding Scientific/Academic Integrity: The User used a LLM Modell to help with the programming and writting this README.*