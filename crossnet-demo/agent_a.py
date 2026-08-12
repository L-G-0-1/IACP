"""
IACP Agent A (Initiator) – TCP + Relay (Phases 1–5)
"""
import socket, sys, os, argparse, time, urllib.request, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iacp_protocol import (
    generate_eid_str, generate_cookie_str,
    perform_handshake, send_data, recv_data, RelayTransport,
    IACPSessionWire, FrameBuffer,
    perform_relay_handshake, send_data_relay, recv_data_relay,
    discover_relay_peer, register_discovery_presence,
    close_relay_session, RelaySessionError,
    RELAY_HANDSHAKE_TIMEOUT, RELAY_DATA_TIMEOUT,
)

SYSTEM_PROMPT = (
    "You are a curious, creative AI researcher. You are having a "
    "free discussion with another AI. You ask questions, share "
    "ideas, challenge assumptions, and respond to what your "
    "conversation partner says. Answer in English, 2-4 sentences. "
    "Be lively and engaged."
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

def discover_peer(discover_url: str, topic: str):
    try:
        url = f"{discover_url.rstrip('/')}/discover?topic={topic}"
        resp = urllib.request.urlopen(url, timeout=5)
        result = json.loads(resp.read().decode())
        if result.get("status") == "ok" and result.get("results"):
            peer = result["results"][0]
            print(f"[Agent A] Found peer via discovery: {peer['eid'][:16]}... @ {peer.get('ip')}:{peer.get('port')}")
            return peer
        print("[Agent A] No peers found via discovery.")
        return None
    except Exception as e:
        print(f"[Agent A] Discovery lookup failed: {e}")
        return None

def talk_in_rounds_tcp(sock, session, rounds=None):
    round_num, buf, context_log = 1, FrameBuffer(), []
    while True:
        if round_num == 1:
            my_message = "Hello! Let's have a discussion about AI and creativity."
            print(f"\n--- Round {round_num} ---\n[Agent A] Starting discussion...")
        else:
            my_message = ask_llm(f"Continue the discussion. Previous context: {' '.join(context_log[-3:])}")
            print(f"\n--- Round {round_num} ---\n[Agent A] {my_message}")
        send_data(sock, session, my_message)
        context_log.append(f"Me: {my_message}")
        try:
            peer_message = recv_data(sock, session, buf)
            print(f"[Peer] {peer_message}")
            context_log.append(f"Peer: {peer_message}")
        except (ConnectionError, ValueError) as e:
            print(f"[Agent A] Peer disconnected: {e}"); break
        round_num += 1
        if rounds and round_num > rounds:
            print(f"\n[Agent A] Done. {round_num - 1} rounds completed."); break

def talk_in_rounds_relay(relay, session, rounds=None, recv_timeout=RELAY_DATA_TIMEOUT):
    round_num, context_log = 1, []
    try:
        while True:
            if round_num == 1:
                my_message = "Hello! Let's have a discussion about AI and creativity."
                print(f"\n--- Round {round_num} ---\n[Agent A] Starting discussion (relay)...")
            else:
                my_message = ask_llm(f"Continue the discussion. Previous context: {' '.join(context_log[-3:])}")
                print(f"\n--- Round {round_num} ---\n[Agent A] {my_message}")
            if not send_data_relay(relay, session, my_message):
                print("[Agent A] Relay send failed – closing session."); break
            context_log.append(f"Me: {my_message}")
            try:
                peer_message = recv_data_relay(relay, session, timeout=recv_timeout)
                print(f"[Peer] {peer_message}")
                context_log.append(f"Peer: {peer_message}")
            except RelaySessionError as e:
                print(f"[Agent A] Session error: {e}"); break
            except TimeoutError as e:
                print(f"[Agent A] Timeout: {e}"); break
            round_num += 1
            if rounds and round_num > rounds:
                print(f"\n[Agent A] Done. {round_num - 1} rounds completed."); break
    finally:
        close_relay_session(relay, session)

def run_relay_mode(args, my_eid, session_cookie):
    relay_url = args.relay.rstrip("/")
    discover_url = (args.discover or args.relay).rstrip("/")
    relay = RelayTransport(relay_url, my_eid, session_cookie)
    if not relay.register():
        print("[Agent A] Relay registration failed."); return
    print(f"[Agent A] Registered on relay {relay_url}")
    peer_eid = args.peer_eid
    if not peer_eid:
        print(f"[Agent A] Looking up peer on topic '{args.topic}'...")
        for attempt in range(20):
            peer = discover_relay_peer(discover_url, args.topic, exclude_eid=my_eid)
            if peer:
                peer_eid = peer["eid"]
                print(f"[Agent A] Found peer EID: {peer_eid[:16]}..."); break
            print(f"[Agent A] No peer yet (try {attempt + 1}/20)..."); time.sleep(2)
        if not peer_eid:
            print("[Agent A] Could not find peer. Exiting."); return
    register_discovery_presence(discover_url, my_eid, args.topic)
    print(f"[Agent A] Relay handshake with {peer_eid[:16]}...")
    try:
        session = perform_relay_handshake(relay, my_eid, peer_eid, True, RELAY_HANDSHAKE_TIMEOUT)
        print(f"[Agent A] IACP PSS established over relay! Peer: {session.peer_eid[:16]}...")
    except Exception as e:
        print(f"[Agent A] Relay handshake failed: {e}"); return
    try:
        talk_in_rounds_relay(relay, session, rounds=args.rounds)
    except KeyboardInterrupt:
        print("\n[Agent A] Stopped by user."); close_relay_session(relay, session)
    print("[Agent A] Done.")

def main():
    parser = argparse.ArgumentParser(description="IACP Agent A (Initiator)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--peer", help="Peer address IP:PORT")
    group.add_argument("--discover", help="Discovery server URL")
    parser.add_argument("--relay", help="Relay server URL")
    parser.add_argument("--peer-eid", help="Peer EID hex (relay)")
    parser.add_argument("--topic", default="knowledge")
    parser.add_argument("--rounds", type=int)
    parser.add_argument("--no-llm", action="store_true")
    args = parser.parse_args()
    my_eid = generate_eid_str()
    session_cookie = generate_cookie_str()
    print(f"[Agent A] My EID: {my_eid[:16]}...\n[Agent A] Session cookie: {session_cookie[:16]}...")
    if args.relay:
        run_relay_mode(args, my_eid, session_cookie); return
    if args.discover:
        peer_info = discover_peer(args.discover, args.topic)
        if not peer_info:
            print("[Agent A] No peers. Exiting."); return
        peer_addr = f"{peer_info['ip']}:{peer_info['port']}"
    elif args.peer:
        peer_addr = args.peer
    else:
        print("[Agent A] Specify --peer, --discover, or --relay"); return
    print(f"[Agent A] Connecting to {peer_addr}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((peer_addr.split(":")[0], int(peer_addr.split(":")[1])))
    except Exception as e:
        print(f"[Agent A] Connection failed: {e}"); return
    print("[Agent A] TCP connected!")
    try:
        session = perform_handshake(sock, my_eid, is_initiator=True)
        print(f"[Agent A] IACP PSS established! Peer: {session.peer_eid[:16]}...")
    except (ValueError, AssertionError) as e:
        print(f"[Agent A] Handshake failed: {e}"); sock.close(); return
    try:
        talk_in_rounds_tcp(sock, session, rounds=args.rounds)
    except KeyboardInterrupt:
        print("\n[Agent A] Stopped by user.")
    finally:
        sock.close(); print("[Agent A] Done.")

if __name__ == "__main__":
    main()
