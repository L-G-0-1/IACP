"""
IACP Structured Demo – Two AI agents communicate via IACP
===========================================================
Pure Python implementation. No Rust bridge needed!

Flow:
1. Agent B (Knowledge) starts TCP server, waits for IACP handshake
2. Agent A (Assistant) connects, performs ERP+PSS handshake
3. Agent A sends questions via encrypted PSS session
4. Agent B answers using phi3:mini (Ollama)
5. Results are displayed
"""

import socket
import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iacp_direct import generate_eid, perform_handshake, send_data, recv_data
from ollama import chat


SYSTEM_PROMPT_B = (
    "You are an AI knowledge specialist. Answer questions precisely "
    "and concisely. Answer in English, maximum 3 sentences."
)

SYSTEM_PROMPT_A = (
    "You are a helpful assistant. Answer in English, "
    "maximum 2 sentences."
)


def agent_b_run(host="127.0.0.1", port=4001):
    """Agent B (Knowledge) – Responder."""
    eid_b = generate_eid()
    print(f"\n[Agent B] EID: {eid_b[:16]}...")
    print(f"[Agent B] Starting IACP listener on {host}:{port}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    server.settimeout(30.0)

    conn, addr = server.accept()
    print(f"[Agent B] Connection from {addr}")

    session = perform_handshake(conn, eid_b, is_initiator=False)
    print(f"[Agent B] IACP PSS established with Peer {session.peer_eid[:16]}...")
    print(f"[Agent B] Session Key: {session.session_key[:16]}...")
    print()

    for i in range(3):
        print(f"[Agent B] Waiting for question {i+1}...")
        question = recv_data(conn, session)
        print(f"[Agent B] Question received: {question[:80]}...")

        print(f"[Agent B] Asking phi3:mini...")
        response = chat(model="phi3:mini", messages=[
            {"role": "system", "content": SYSTEM_PROMPT_B},
            {"role": "user", "content": question},
        ], options={"temperature": 0.3, "num_predict": 256})
        answer = response["message"]["content"].strip()

        print(f"[Agent B] Answer: {answer[:80]}...")
        send_data(conn, session, answer)
        print(f"[Agent B] Answer sent!")
        print()

    conn.close()
    print("[Agent B] Done.")


def agent_a_run(host="127.0.0.1", port=4001):
    """Agent A (Assistant) – Initiator."""
    time.sleep(0.5)
    eid_a = generate_eid()
    print(f"\n[Agent A] EID: {eid_a[:16]}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((host, port))
    print(f"[Agent A] Connected to {host}:{port}")

    session = perform_handshake(sock, eid_a, is_initiator=True)
    print(f"[Agent A] IACP PSS established with Peer {session.peer_eid[:16]}...")
    print(f"[Agent A] Session Key: {session.session_key[:16]}...")
    print()

    questions = [
        "What is the difference between AI alignment and AI safety?",
        "What concrete methods exist for AI alignment?",
        "Why is AI safety important for society?",
    ]

    for i, question in enumerate(questions, 1):
        print(f"\n--- Question {i}/{len(questions)} ---")
        print(f"[Agent A] Sending: {question[:60]}...")

        send_data(sock, session, question)
        print(f"[Agent A] Question sent, waiting for answer...")

        answer = recv_data(sock, session)
        print(f"[Agent A] Answer received!")
        print(f"  >>> {answer}")

        if i < len(questions):
            print("  (2 second pause...)")
            time.sleep(2)

    sock.close()
    print("\n[Agent A] Done.")


def main():
    print("=" * 65)
    print(" IACP Demo – Two AI agents communicate securely")
    print("=" * 65)
    print()

    try:
        chat(model="phi3:mini", messages=[{"role": "user", "content": "test"}],
             options={"num_predict": 1})
    except Exception as e:
        print(f"[ERROR] Ollama not reachable: {e}")
        print("Run 'ollama serve' in another terminal first.")
        sys.exit(1)

    print("Starting Agent B (Knowledge/Responder)...")
    b_thread = threading.Thread(target=agent_b_run, daemon=True)
    b_thread.start()

    print("Starting Agent A (Assistant/Initiator)...")
    a_thread = threading.Thread(target=agent_a_run, daemon=True)
    a_thread.start()

    a_thread.join(timeout=120)
    b_thread.join(timeout=5)

    print()
    print("=" * 65)
    print(" Demo completed successfully!")
    print(" Two AI agents communicated via IACP:")
    print("  - EID (Ed25519) identity-based")
    print("  - ERP (EID Routing Protocol) Handshake")
    print("  - PSS (Persistent State Session) with Dual-Cookies")
    print("  - AES-GCM-like encryption (simulated)")
    print("  - Sequence Counter (Replay Protection)")
    print("=" * 65)


if __name__ == "__main__":
    main()