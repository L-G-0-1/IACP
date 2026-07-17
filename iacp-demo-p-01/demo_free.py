"""
IACP Free Discussion – Two AI agents communicate freely via IACP
=================================================================
No predefined questions, no scripts. The agents decide for themselves
what to talk about, react to each other, and have a completely free
discussion.

Flow:
1. Agent B (Responder) starts TCP server, waits for IACP handshake
2. Agent A (Initiator) connects, performs ERP+PSS handshake
3. Agent A starts the conversation (LLM decides the first words)
4. Both agents talk freely, building on each other's responses
5. Press Ctrl+C to stop
"""

import socket
import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iacp_direct import generate_eid, perform_handshake, send_data, recv_data
from ollama import chat


# System prompts: deliberately different personalities for an interesting dialog
PROMPT_ASSISTANT = (
    "You are a curious, creative AI researcher. You are having a "
    "free discussion with another AI. You ask questions, share "
    "ideas, challenge assumptions, and respond to what your "
    "conversation partner says. Answer in English, 2-4 sentences. "
    "Be lively and engaged."
)

PROMPT_KNOWLEDGE = (
    "You are a thoughtful AI knowledge expert. You are having a free "
    "discussion with another AI. You answer questions, ask follow-up "
    "questions, and bring new perspectives. You build on what your "
    "conversation partner has said. Answer in English, 2-4 sentences."
)


def ask_llm(system: str, context: str, model: str = "phi3:mini") -> str:
    """Ask the local LLM and return the response."""
    try:
        response = chat(model=model, messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": context},
        ], options={"temperature": 0.7, "num_predict": 256})
        return response["message"]["content"].strip()
    except Exception as e:
        return f"[LLM Error: {e}]"


def agent_b_run(host="127.0.0.1", port=4001):
    """Agent B (Responder) – waits for messages, responds freely."""
    eid = generate_eid()
    print(f"\n[Agent B] EID: {eid[:16]}...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    server.settimeout(30.0)

    conn, addr = server.accept()
    print(f"[Agent B] Connected from {addr}")

    session = perform_handshake(conn, eid, is_initiator=False)
    print(f"[Agent B] IACP PSS established, Peer: {session.peer_eid[:16]}...")
    print()

    dialog = []
    rounds = 0

    try:
        while True:
            rounds += 1

            msg = recv_data(conn, session)
            dialog.append(("Agent A", msg))
            print(f"\n--- Round {rounds} ---")
            print(f"[Agent B] <<< received from Agent A: {msg[:120]}...")

            context = "\n".join(
                f"{r}: {t}" for r, t in dialog[-8:]
            )
            prompt = (
                "You are having a free discussion. Here is the conversation so far:\n\n"
                + context
                + "\n\nWhat do you reply? Answer directly."
            )

            reply = ask_llm(PROMPT_KNOWLEDGE, prompt)
            dialog.append(("Agent B", reply))
            print(f"[Agent B] >>> reply to Agent A: {reply[:120]}...")

            send_data(conn, session, reply)

    except (ConnectionError, BrokenPipeError):
        print("[Agent B] Connection closed.")
    except Exception as e:
        print(f"[Agent B] Ended: {e}")
    finally:
        conn.close()
        print(f"[Agent B] Done. {rounds} rounds completed.")


def agent_a_run(host="127.0.0.1", port=4001):
    """Agent A (Initiator) – starts conversation, responds freely."""
    time.sleep(0.3)
    eid = generate_eid()
    print(f"\n[Agent A] EID: {eid[:16]}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((host, port))
    print(f"[Agent A] Connected to {host}:{port}")

    session = perform_handshake(sock, eid, is_initiator=True)
    print(f"[Agent A] IACP PSS established, Peer: {session.peer_eid[:16]}...")
    print()

    dialog = []
    rounds = 0

    try:
        # First words: LLM decides how to start
        first_prompt = (
            "You are about to start a free discussion with another AI. "
            "Introduce yourself briefly and say something interesting about AI."
        )
        first_msg = ask_llm(PROMPT_ASSISTANT, first_prompt)
        dialog.append(("Agent A", first_msg))
        print(f"\n--- Round 1 ---")
        print(f"[Agent A] >>> First message to Agent B: {first_msg[:120]}...")

        send_data(sock, session, first_msg)
        rounds += 1

        while True:
            reply = recv_data(sock, session)
            dialog.append(("Agent B", reply))
            rounds += 1
            print(f"\n--- Round {rounds} ---")
            print(f"[Agent A] <<< received from Agent B: {reply[:120]}...")

            context = "\n".join(
                f"{r}: {t}" for r, t in dialog[-8:]
            )
            prompt = (
                "You are having a free discussion. So far:\n\n"
                + context
                + "\n\nWhat do you say next? Build on the last reply."
            )

            own_reply = ask_llm(PROMPT_ASSISTANT, prompt)
            dialog.append(("Agent A", own_reply))
            print(f"[Agent A] >>> reply: {own_reply[:120]}...")

            send_data(sock, session, own_reply)

    except (ConnectionError, BrokenPipeError):
        print("[Agent A] Connection closed.")
    except KeyboardInterrupt:
        print("\n[Agent A] Stopped by user.")
    except Exception as e:
        print(f"[Agent A] Ended: {e}")
    finally:
        sock.close()
        print(f"[Agent A] Done. {rounds} rounds completed.")


def main():
    print("=" * 70)
    print(" IACP Free Discussion – Two AIs talk completely freely via IACP")
    print("=" * 70)
    print("")
    print("  - Agent A (curious researcher) starts the conversation")
    print("  - Agent B (knowledge expert) responds freely")
    print("  - Both build on each other – nothing is predefined")
    print("  - Press Ctrl+C to stop")
    print("")
    print("=" * 70)
    print()

    # Check if Ollama is running
    try:
        chat(model="phi3:mini", messages=[{"role": "user", "content": "test"}],
             options={"num_predict": 1})
    except Exception as e:
        print(f"[ERROR] Ollama not reachable: {e}")
        print("Run 'ollama serve' in another terminal first.")
        sys.exit(1)

    print("Starting Agent B (Responder)...")
    b_thread = threading.Thread(target=agent_b_run, daemon=True)
    b_thread.start()

    time.sleep(0.5)

    print("Starting Agent A (Initiator)...\n")

    try:
        agent_a_run("127.0.0.1", 4001)
    except KeyboardInterrupt:
        print("\n\n[MAIN] Discussion stopped by user.")
    except Exception as e:
        print(f"\n[MAIN] Error: {e}")

    print()
    print("=" * 70)
    print(" Free discussion ended. The AIs communicated without")
    print(" any predefined scripts or questions.")
    print("=" * 70)


if __name__ == "__main__":
    main()