"""
IACP Network Demo
=================
Demonstrates IACP agents communicating across a network with Discovery.

Usage (all on one PC for testing, or on separate PCs):
  1. Run this script (starts discovery + responder + initiator)
  2. Watch two AI agents communicate freely via IACP

For two separate PCs:
  PC 1: python discovery_server.py
  PC 1: python agent_b.py --bind 0.0.0.0:4001 --discover http://PC1_IP:8888 --topic knowledge
  PC 2: python agent_a.py --discover http://PC1_IP:8888 --topic knowledge

Or use the desktop app:
  PC 1: python iacp_app.py (mode: responder)
  PC 2: python iacp_app.py (mode: initiator, peer: PC1_IP:4001)
"""

import subprocess
import sys
import os
import time
import threading


def main():
    print("=" * 70)
    print(" IACP Network Demo – Two AIs talk across a network via IACP")
    print("=" * 70)
    print()
    print(" This demo starts all components locally. For two PCs,")
    print(" see the instructions in the README.")
    print()

    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Check Ollama
    try:
        from ollama import chat
        chat(model="phi3:mini", messages=[{"role": "user", "content": "test"}],
             options={"num_predict": 1})
    except Exception as e:
        print(f"[ERROR] Ollama not reachable: {e}")
        print("Run 'ollama serve' in another terminal first.")
        sys.exit(1)

    processes = []

    try:
        # 1. Start discovery server
        print("[MAIN] Starting Discovery Server on port 8888...")
        disc_proc = subprocess.Popen(
            [sys.executable, os.path.join(script_dir, "discovery_server.py"), "8888"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        processes.append(("Discovery Server", disc_proc))
        time.sleep(1)

        # 2. Start Agent B (Responder)
        print()
        print("[MAIN] Starting Agent B (Responder) on port 4001...")
        agent_b_proc = subprocess.Popen(
            [sys.executable, os.path.join(script_dir, "agent_b.py"),
             "--bind", "0.0.0.0:4001",
             "--discover", "http://localhost:8888",
             "--topic", "knowledge"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        processes.append(("Agent B", agent_b_proc))
        time.sleep(3)

        # 3. Start Agent A (Initiator) – will discover B via discovery server
        print()
        print("[MAIN] Starting Agent A (Initiator)...")
        print("[MAIN] Agent A will discover Agent B via the Discovery Server")
        print()
        agent_a_proc = subprocess.Popen(
            [sys.executable, os.path.join(script_dir, "agent_a.py"),
             "--discover", "http://localhost:8888",
             "--topic", "knowledge"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        processes.append(("Agent A", agent_a_proc))

        # Show output from Agent A live
        print("[MAIN] === Agent A Output ===")
        print()
        for line in agent_a_proc.stdout:
            print(f"  {line}", end="")
            if "Done." in line or "Error" in line:
                break

        # Brief pause, then show Agent B output
        time.sleep(1)
        print()
        print("[MAIN] === Agent B Output ===")
        print()
        try:
            remaining = agent_b_proc.stdout.read()
            if remaining:
                print(f"  {remaining}")
        except:
            pass

        print()
        print("=" * 70)
        print(" Demo complete!")
        print("=" * 70)

    except KeyboardInterrupt:
        print("\n[MAIN] Stopping...")
    finally:
        for name, proc in processes:
            print(f"[MAIN] Stopping {name}...")
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    main()