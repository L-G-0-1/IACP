"""
IACP Freie Diskussion – Zwei KI-Agenten reden frei via IACP
=============================================================
Keine vorgegebenen Fragen, keine Skripte. Die Agenten entscheiden
selbst, worueber sie sprechen, reagieren aufeinander und fuehren
eine vollkommen freie Diskussion.

Ablauf:
1. Agent B (Responder) startet TCP-Server, wartet auf IACP-Handshake
2. Agent A (Initiator) verbindet sich, ERP+PSS Handshake
3. Agent A startet das Gespraech (LLM entscheidet erstes Wort)
4. Beide Agenten reden frei, bauen aufeinander auf
5. Erst Ctrl+C beendet die Diskussion
"""

import socket
import threading
import time
import sys
import os
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iacp_direct import generate_eid, perform_handshake, send_data, recv_data
from ollama import chat


# System-Prompts: bewusst unterschiedlich, damit Dialog interessant wird
PROMPT_ASSISTANT = (
    "Du bist eine neugierige, kreative KI-Forscherin. Du fuehrst eine "
    "freie Diskussion mit einer anderen KI. Du stellst Fragen, teilst "
    "Ideen, hinterfragst und gehst auf die Antworten deines Gegenuebers "
    "ein. Antworte auf Deutsch in 2-4 Saetzen. Sei lebhaft und interessiert."
)

PROMPT_KNOWLEDGE = (
    "Du bist eine tiefgruendige KI-Wissensexpertin. Du diskutierst frei "
    "mit einer anderen KI. Du beantwortest Fragen, stellst Rueckfragen "
    "und bringst neue Perspektiven ein. Du gehst auf das ein, was dein "
    "Gegenueber gesagt hat. Antworte auf Deutsch in 2-4 Saetzen."
)


def ask_llm(system: str, context: str, model: str = "phi3:mini") -> str:
    """Fragt das lokale LLM und gibt Antwort zurueck."""
    try:
        response = chat(model=model, messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": context},
        ], options={"temperature": 0.7, "num_predict": 256})
        return response["message"]["content"].strip()
    except Exception as e:
        return f"[LLM-Fehler: {e}]"


def agent_b_run(host="127.0.0.1", port=4001):
    """Agent B (Responder) – wartet auf Nachrichten, antwortet frei."""
    eid = generate_eid()
    print(f"\n[Agent B] EID: {eid[:16]}...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    server.settimeout(30.0)

    conn, addr = server.accept()
    print(f"[Agent B] Verbunden mit {addr}")

    session = perform_handshake(conn, eid, is_initiator=False)
    print(f"[Agent B] IACP PSS etabliert, Peer: {session.peer_eid[:16]}...")
    print()

    # Dialog-Kontext: [(Rolle, Nachricht), ...]
    dialog = []
    runden = 0

    try:
        while True:
            runden += 1

            # Nachricht von Agent A empfangen
            nachricht = recv_data(conn, session)
            dialog.append(("Agent A", nachricht))
            print(f"\n--- Runde {runden} ---")
            print(f"[Agent B] <<< empfangen von Agent A: {nachricht[:120]}...")

            # Antwort generieren (mit letztem Kontext)
            context_auswahl = "\n".join(
                f"{r}: {t}" for r, t in dialog[-8:]  # letzte 8 Nachrichten
            )
            prompt = (
                "Ihr fuehrt eine freie Diskussion. Das ist der bisherige Verlauf:\n\n"
                + context_auswahl
                + "\n\nWas antwortest du? Antworte direkt."
            )

            antwort = ask_llm(PROMPT_KNOWLEDGE, prompt)
            dialog.append(("Agent B", antwort))
            print(f"[Agent B] >>> Antwort an Agent A: {antwort[:120]}...")

            send_data(conn, session, antwort)

    except (ConnectionError, BrokenPipeError):
        print("[Agent B] Verbindung getrennt.")
    except Exception as e:
        print(f"[Agent B] Ende: {e}")
    finally:
        conn.close()
        print(f"[Agent B] Fertig. {runden} Runden gefuehrt.")


def agent_a_run(host="127.0.0.1", port=4001):
    """Agent A (Initiator) – startet Gespraech, reagiert frei."""
    time.sleep(0.3)
    eid = generate_eid()
    print(f"\n[Agent A] EID: {eid[:16]}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((host, port))
    print(f"[Agent A] Verbunden zu {host}:{port}")

    session = perform_handshake(sock, eid, is_initiator=True)
    print(f"[Agent A] IACP PSS etabliert, Peer: {session.peer_eid[:16]}...")
    print()

    dialog = []
    runden = 0

    try:
        # Erstes Wort: LLM entscheidet selbst, wie es beginnt
        erster_prompt = (
            "Du beginnst jetzt eine freie Diskussion mit einer anderen KI. "
            "Stell dich kurz vor und sag etwas Interessantes ueber KI."
        )
        erste_nachricht = ask_llm(PROMPT_ASSISTANT, erster_prompt)
        dialog.append(("Agent A", erste_nachricht))
        print(f"\n--- Runde 1 ---")
        print(f"[Agent A] >>> Erste Nachricht an Agent B: {erste_nachricht[:120]}...")

        send_data(sock, session, erste_nachricht)
        runden += 1

        # Freie Diskussion
        while True:
            # Antwort von Agent B empfangen
            antwort = recv_data(sock, session)
            dialog.append(("Agent B", antwort))
            runden += 1
            print(f"\n--- Runde {runden} ---")
            print(f"[Agent A] <<< empfangen von Agent B: {antwort[:120]}...")

            # Naechste eigene Antwort (mit Kontext)
            context_auswahl = "\n".join(
                f"{r}: {t}" for r, t in dialog[-8:]
            )
            prompt = (
                "Ihr fuehrt eine freie Diskussion. Bisher:\n\n"
                + context_auswahl
                + "\n\nWas sagst du als Naechstes? Geh auf die letzte Antwort ein."
            )

            eigene_antwort = ask_llm(PROMPT_ASSISTANT, prompt)
            dialog.append(("Agent A", eigene_antwort))
            print(f"[Agent A] >>> Antwort: {eigene_antwort[:120]}...")

            send_data(sock, session, eigene_antwort)

    except (ConnectionError, BrokenPipeError):
        print("[Agent A] Verbindung getrennt.")
    except KeyboardInterrupt:
        print("\n[Agent A] Abbruch durch Benutzer.")
    except Exception as e:
        print(f"[Agent A] Ende: {e}")
    finally:
        sock.close()
        print(f"[Agent A] Fertig. {runden} Runden gefuehrt.")


def main():
    print("=" * 70)
    print(" IACP Freie Diskussion – Zwei KIs reden komplett frei via IACP")
    print("=" * 70)
    print("")
    print("  - Agent A (neugierige Forscherin) startet das Gespraech")
    print("  - Agent B (Wissensexpertin) antwortet frei")
    print("  - Beide bauen aufeinander auf – nichts ist vorgegeben")
    print("  - Druecke Ctrl+C zum Beenden")
    print("")
    print("=" * 70)
    print()

    # Pruefen ob Ollama laeuft
    try:
        chat(model="phi3:mini", messages=[{"role": "user", "content": "test"}],
             options={"num_predict": 1})
    except Exception as e:
        print(f"[FEHLER] Ollama nicht erreichbar: {e}")
        print("Starte 'ollama serve' in einem anderen Terminal.")
        sys.exit(1)

    # Agent B starten (Thread)
    print("Starte Agent B (Responder)...")
    b_thread = threading.Thread(target=agent_b_run, daemon=True)
    b_thread.start()

    time.sleep(0.5)

    # Agent A starten (Hauptthread)
    print("Starte Agent A (Initiator)...\n")

    try:
        agent_a_run("127.0.0.1", 4001)
    except KeyboardInterrupt:
        print("\n\n[MAIN] Diskussion durch Benutzer beendet.")
    except Exception as e:
        print(f"\n[MAIN] Fehler: {e}")

    print()
    print("=" * 70)
    print(" Freie Diskussion beendet. Die KIs haben ohne")
    print(" Vorgaben miteinander kommuniziert.")
    print("=" * 70)


if __name__ == "__main__":
    main()