"""
IACP Agent B (Responder) – TCP + Relay (Phases 1–5)
One session per peer EID over relay.
"""
import socket, sys, os, argparse, threading, time, urllib.request, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iacp_protocol import (
    generate_eid_str, generate_cookie_str,
    perform_handshake, send_data, recv_data, RelayTransport,
    IACPSessionWire, FrameBuffer,
    perform_relay_handshake, send_data_relay, recv_data_relay,
    register_discovery_presence, close_relay_session, RelaySessionError,
    RELAY_HANDSHAKE_TIMEOUT, RELAY_DATA_TIMEOUT,
)

SYSTEM_PROMPT = (
    "You are a thoughtful AI knowledge expert. You are having a free "
    "discussion with another AI. You answer questions, ask follow-up "
    "questions, and bring new perspectives. Answer in English, 2-4 sentences."
)

def ask_llm(context: str) -> str:
    try:
        from ollama import chat
        response = chat(model="phi3:mini", messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": context},
        ], options={"temperature": 0.7, "num_predict": 256})
        return response["message"]["content"].strip()
    except ImportError:
        return "[LLM: Ollama not installed. Install with: pip install ollama]"
    except Exception as e:
        return f"[LLM Error: {e}]"

def register_with_discovery(discover_url, eid, ip, port, topic):
    try:
        data = json.dumps({"eid": eid, "ip": ip, "port": port, "topic": topic}).encode()
        req = urllib.request.Request(f"{discover_url.rstrip('/')}/register", data=data,
                                     headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=5)
        print(f"[Agent B] Discovery registration: {json.loads(resp.read().decode()).get('message', 'ok')}")
    except Exception as e:
        print(f"[Agent B] Discovery registration failed: {e}")

def handle_client(conn, addr, my_eid, no_llm=False):
    print(f"\n[Agent B] Client connected from {addr[0]}:{addr[1]}")
    try:
        session = perform_handshake(conn, my_eid, is_initiator=False)
        print(f"[Agent B] IACP PSS established with {session.peer_eid[:16]}...")
    except (ValueError, AssertionError) as e:
        print(f"[Agent B] Handshake failed: {e}"); conn.close(); return
    round_num, buf, context_log = 0, FrameBuffer(), []
    try:
        while True:
            try:
                peer_message = recv_data(conn, session, buf)
                print(f"\n--- Round {round_num + 1} ---\n[Peer] {peer_message}")
                context_log.append(f"Peer: {peer_message}")
            except (ConnectionError, ValueError) as e:
                print(f"[Agent B] Peer disconnected: {e}"); break
            my_message = ask_llm(f"Continue the discussion. Previous context: {' '.join(context_log[-3:])}")
            print(f"[Agent B] {my_message}")
            context_log.append(f"Me: {my_message}")
            send_data(conn, session, my_message)
            round_num += 1
    except KeyboardInterrupt:
        print("\n[Agent B] Stopped by user.")
    finally:
        conn.close(); print(f"[Agent B] Connection closed. {round_num} rounds.")

def talk_relay_session(relay, session, rounds=None, recv_timeout=RELAY_DATA_TIMEOUT):
    round_num, context_log = 0, []
    peer = session.peer_eid[:16]
    try:
        while True:
            try:
                peer_message = recv_data_relay(relay, session, timeout=recv_timeout)
                print(f"\n--- [{peer}] Round {round_num + 1} ---\n[Peer] {peer_message}")
                context_log.append(f"Peer: {peer_message}")
            except RelaySessionError as e:
                print(f"[Agent B] Session error with {peer}: {e}"); break
            except TimeoutError as e:
                print(f"[Agent B] Timeout with {peer}: {e}"); break
            my_message = ask_llm(f"Continue the discussion. Previous context: {' '.join(context_log[-3:])}")
            print(f"[Agent B] {my_message}")
            context_log.append(f"Me: {my_message}")
            if not send_data_relay(relay, session, my_message):
                print(f"[Agent B] Relay send failed for {peer}"); break
            round_num += 1
            if rounds and round_num >= rounds:
                print(f"\n[Agent B] Done with {peer}. {round_num} rounds."); break
    finally:
        close_relay_session(relay, session)
        print(f"[Agent B] Session with {peer} closed ({round_num} rounds).")

def run_relay_mode(args, my_eid, session_cookie):
    relay_url = args.relay.rstrip("/")
    discover_url = (args.discover or args.relay).rstrip("/")
    relay = RelayTransport(relay_url, my_eid, session_cookie)
    if not relay.register():
        print("[Agent B] Relay registration failed."); return
    print(f"[Agent B] Registered on relay {relay_url}")
    if register_discovery_presence(discover_url, my_eid, args.topic):
        print(f"[Agent B] Presence registered on topic '{args.topic}'")
    else:
        print("[Agent B] Presence registration FAILED – initiator cannot discover us")
    sessions, sessions_lock = {}, threading.Lock()
    print("[Agent B] Waiting for initiators on relay (Ctrl+C to stop)...")
    try:
        while True:
            try:
                session = perform_relay_handshake(
                    relay, my_eid, args.peer_eid or None, False, RELAY_HANDSHAKE_TIMEOUT)
            except TimeoutError:
                continue
            except Exception as e:
                print(f"[Agent B] Handshake error: {e}"); continue
            peer = session.peer_eid
            with sessions_lock:
                if peer in sessions:
                    close_relay_session(relay, sessions.pop(peer))
                sessions[peer] = session
            print(f"[Agent B] PSS with {peer[:16]}... (active: {len(sessions)})")
            def worker(sess=session):
                try:
                    talk_relay_session(relay, sess, rounds=args.rounds)
                finally:
                    with sessions_lock:
                        sessions.pop(sess.peer_eid, None)
            t = threading.Thread(target=worker, daemon=True); t.start()
            if args.rounds:
                t.join()
    except KeyboardInterrupt:
        print("\n[Agent B] Stopped by user.")
        with sessions_lock:
            for s in list(sessions.values()):
                close_relay_session(relay, s)
            sessions.clear()
    print("[Agent B] Done.")

def main():
    parser = argparse.ArgumentParser(description="IACP Agent B (Responder)")
    parser.add_argument("--bind", default="0.0.0.0:4001")
    parser.add_argument("--discover")
    parser.add_argument("--relay")
    parser.add_argument("--peer-eid")
    parser.add_argument("--topic", default="knowledge")
    parser.add_argument("--rounds", type=int)
    parser.add_argument("--no-llm", action="store_true")
    args = parser.parse_args()
    my_eid = generate_eid_str()
    session_cookie = generate_cookie_str()
    print(f"[Agent B] My EID: {my_eid[:16]}...\n[Agent B] Session cookie: {session_cookie[:16]}...")
    if args.relay:
        run_relay_mode(args, my_eid, session_cookie); return
    bind_ip, bind_port = args.bind.split(":"); bind_port = int(bind_port)
    if args.discover:
        try:
            external_ip = json.loads(urllib.request.urlopen("http://httpbin.org/ip", timeout=5).read())["origin"]
        except Exception:
            external_ip = bind_ip
        register_with_discovery(args.discover, my_eid, external_ip, bind_port, args.topic)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((bind_ip, bind_port)); server.listen(5)
        print(f"[Agent B] Listening on {bind_ip}:{bind_port}")
    except Exception as e:
        print(f"[Agent B] Failed to bind: {e}"); return
    threads = []
    try:
        while True:
            try:
                server.settimeout(1.0); conn, addr = server.accept()
            except socket.timeout:
                continue
            t = threading.Thread(target=handle_client, args=(conn, addr, my_eid, args.no_llm), daemon=True)
            t.start(); threads.append(t)
    except KeyboardInterrupt:
        print("\n[Agent B] Stopped by user.")
    finally:
        server.close()
        for t in threads: t.join(timeout=2)

if __name__ == "__main__":
    main()
