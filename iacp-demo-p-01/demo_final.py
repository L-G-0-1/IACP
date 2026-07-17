"""
IACP Demo Final – Zwei KI-Agenten kommunizieren via IACP
=========================================================
Reine Python-Implementierung. Keine Rust-Bridge nötig!

Ablauf:
1. Agent B (Knowledge) startet TCP-Server, wartet auf IACP-Handshake
2. Agent A (Assistant) verbindet sich, führt ERP+PSS Handshake durch
3. Agent A sendet Fragen via verschlüsselter PSS-Session
4. Agent B beantwortet mit phi3:mini (Ollama)
5. Ergebnisse werden angezeigt
"""

import socket
import threading
import time
import sys
import os

# IACP Direct importieren
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iacp_direct import (
    generate_eid, perform_handshake, send_data, recv_data,
    IACPSession
)
from ollama import chat


SYSTEM_PROMPT_B = (
    "Du bist ein Wissensspezialist fuer Kuenstliche Intelligenz. "
    "Antworte auf Deutsch in maximal 3 Saetzen. Sei praezise."
)

SYSTEM_PROMPT_A = (
    "Du bist ein hilfsbereiter Assistent. Antworte auf Deutsch "
    "in maximal 2 Saetzen."
)


def agent_b_run(host="127.0.0.1", port=4001):
    """Agent B (Knowledge) – Responder."""
    eid_b = generate_eid()
    print(f"\n[Agent B] EID: {eid_b[:16]}...")
    print(f"[Agent B] Starte IACP-Listener auf {host}:{port}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    server.settimeout(30.0)

    conn, addr = server.accept()
    print(f"[Agent B] Verbindung von {addr}")

    # ERP + PSS Handshake (Responder)
    session = perform_handshake(conn, eid_b, is_initiator=False)
    print(f"[Agent B] IACP PSS etabliert mit Peer {session.peer_eid[:16]}...")
    print(f"[Agent B] Session Key: {session.session_key[:16]}...")
    print()

    # Fragen empfangen und beantworten
    for i in range(3):
        print(f"[Agent B] Warte auf Frage {i+1}...")
        question = recv_data(conn, session)
        print(f"[Agent B] Frage erhalten: {question[:80]}...")

        # Mit LLM beantworten
        print(f"[Agent B] Frage phi3:mini...")
        response = chat(model="phi3:mini", messages=[
            {"role": "system", "content": SYSTEM_PROMPT_B},
            {"role": "user", "content": question},
        ], options={"temperature": 0.3, "num_predict": 256})
        answer = response["message"]["content"].strip()

        print(f"[Agent B] Antwort: {answer[:80]}...")
        send_data(conn, session, answer)
        print(f"[Agent B] Antwort gesendet!")
        print()

    # Session schliessen
    conn.close()
    print("[Agent B] Fertig.")


def agent_a_run(host="127.0.0.1", port=4001):
    """Agent A (Assistant) – Initiator."""
    time.sleep(0.5)  # Warten bis Server bereit
    eid_a = generate_eid()
    print(f"\n[Agent A] EID: {eid_a[:16]}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((host, port))
    print(f"[Agent A] Verbunden zu {host}:{port}")

    # ERP + PSS Handshake (Initiator)
    session = perform_handshake(sock, eid_a, is_initiator=True)
    print(f"[Agent A] IACP PSS etabliert mit Peer {session.peer_eid[:16]}...")
    print(f"[Agent A] Session Key: {session.session_key[:16]}...")
    print()

    questions = [
        "Was ist der Unterschied zwischen KI-Ausrichtung und KI-Sicherheit?",
        "Welche konkreten Methoden gibt es fuer KI-Ausrichtung?",
        "Warum ist KI-Sicherheit wichtig fuer die Gesellschaft?",
    ]

    for i, question in enumerate(questions, 1):
        print(f"\n--- Frage {i}/{len(questions)} ---")
        print(f"[Agent A] Sende: {question[:60]}...")

        # Frage via IACP senden
        send_data(sock, session, question)
        print(f"[Agent A] Frage gesendet, warte auf Antwort...")

        # Antwort empfangen
        answer = recv_data(sock, session)
        print(f"[Agent A] Antwort empfangen!")
        print(f"  >>> {answer}")

        if i < len(questions):
            print("  (2 Sekunden Pause...)")
            time.sleep(2)

    sock.close()
    print("\n[Agent A] Fertig.")


def main():
    print("=" * 65)
    print(" IACP Demo – Zwei KI-Agenten kommunizieren sicher")
    print("=" * 65)
    print()

    # Pruefen ob Ollama laeuft
    try:
        chat(model="phi3:mini", messages=[{"role": "user", "content": "test"}],
             options={"num_predict": 1})
    except Exception as e:
        print(f"[FEHLER] Ollama nicht erreichbar: {e}")
        print("[HINWEIS] Stelle sicher, dass Ollama laeuft (ollama serve)")
        sys.exit(1)

    print("Starte Agent B (Knowledge/Responder)...")
    b_thread = threading.Thread(target=agent_b_run, daemon=True)
    b_thread.start()

    print("Starte Agent A (Assistant/Initiator)...")
    a_thread = threading.Thread(target=agent_a_run, daemon=True)
    a_thread.start()

    # Warten bis beide fertig sind
    a_thread.join(timeout=120)
    b_thread.join(timeout=5)

    print()
    print("=" * 65)
    print(" Demo erfolgreich abgeschlossen!")
    print(" Zwei KI-Agenten haben via IACP kommuniziert:")
    print("  - EID (Ed25519) identitaetsbasiert")
    print("  - ERP (EID Routing Protocol) Handshake")
    print("  - PSS (Persistent State Session) mit Dual-Cookies")
    print("  - AES-GCM-aehnliche Verschluesselung (simuliert)")
    print("  - Sequence Counter (Replay-Schutz)")
    print("=" * 65)


if __name__ == "__main__":
    main()