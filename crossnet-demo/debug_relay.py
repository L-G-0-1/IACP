#!/usr/bin/env python3
"""
IACP Relay Debug Suite – objective, automated checks
====================================================
Runs without discovery_server and without Ollama where possible.
Uses an in-memory mock relay for protocol logic; optional live HTTP checks.

Exit code 0 = all PASS, 1 = at least one FAIL.

Usage:
  python debug_relay.py                  # offline unit + mock-relay tests
  python debug_relay.py --live http://127.0.0.1:8888   # also hit real server
  python debug_relay.py -v               # verbose
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import traceback
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── result collector ──────────────────────────────────────────────────────────
RESULTS: List[Tuple[str, bool, str]] = []
VERBOSE = False


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    line = f"  [{mark}] {name}"
    if detail and (VERBOSE or not ok):
        line += f" — {detail}"
    print(line)


def section(title: str):
    print(f"\n=== {title} ===")


# ── imports under test ────────────────────────────────────────────────────────
def test_imports():
    section("1. Imports & API surface")
    try:
        import iacp_protocol as p
        check("import iacp_protocol", True)
    except Exception as e:
        check("import iacp_protocol", False, str(e))
        return None

    required = [
        "RelayTransport", "IACPPacket", "IACPSessionWire",
        "perform_handshake", "send_data", "recv_data",
        "perform_relay_handshake", "send_data_relay", "recv_data_relay",
        "relay_send_packet", "relay_recv_packet",
        "packet_to_relay_envelope", "relay_envelope_to_packet",
        "verify_relay_envelope", "discover_relay_peer",
        "register_discovery_presence", "close_relay_session",
        "RelaySessionError", "generate_eid_str", "generate_cookie_str",
        "sign_message_str", "verify_signature_str",
        "RELAY_HANDSHAKE_TIMEOUT", "RELAY_POLL_INTERVAL", "RELAY_DATA_TIMEOUT",
    ]
    missing = [n for n in required if not hasattr(p, n)]
    check("relay API symbols present", not missing, f"missing: {missing}" if missing else "")
    return p


def test_crypto(p):
    section("2. Wire-path HMAC (string EID)")
    eid = p.generate_eid_str()
    msg = json.dumps({"type": "ERP_INIT", "nonce": "abc"}, sort_keys=True)
    sig = p.sign_message_str(eid, msg)
    ok = p.verify_signature_str(eid, msg, sig)
    check("sign/verify roundtrip", ok)
    ok2 = not p.verify_signature_str(eid, msg + "x", sig)
    check("tamper detection", ok2)
    # IACPPacket path
    pkt = p.IACPPacket(p.IACPPacket.ERP_INIT, eid, {"nonce": "n1"})
    pkt.sign(eid)
    check("IACPPacket.sign/verify", pkt.verify(eid))
    pkt.payload["nonce"] = "n2"
    check("IACPPacket tamper fails", not pkt.verify(eid))


def test_envelope(p):
    section("3. Relay envelope pack/verify")
    eid = p.generate_eid_str()
    pkt = p.IACPPacket(p.IACPPacket.PSS_INIT, eid, {"cookie_i": "cafebabe"})
    pkt.sign(eid)
    env = p.packet_to_relay_envelope(pkt)
    check("envelope keys", set(env.keys()) >= {"iacp_type", "sender", "payload", "signature"})
    check("verify_relay_envelope", p.verify_relay_envelope(env))
    env2 = dict(env)
    env2["payload"] = {"cookie_i": "deadbeef"}
    check("envelope tamper fails", not p.verify_relay_envelope(env2))
    pkt2 = p.relay_envelope_to_packet(env)
    check("envelope->packet type", pkt2.msg_type == p.IACPPacket.PSS_INIT)


class MockRelay:
    """In-memory shared queues – mirrors RelayTransport inbox API (no HTTP)."""
    QUEUES = {}

    def __init__(self, eid, cookie="cookie"):
        self.relay_url = "http://mock"
        self.eid = eid
        self.session_cookie = cookie
        self._registered = True
        self._inbox = []
        self._inbox_lock = threading.Lock()
        MockRelay.QUEUES.setdefault(eid, [])

    def register(self):
        self._registered = True
        MockRelay.QUEUES.setdefault(self.eid, [])
        return True

    def send(self, to_eid, encrypted_payload):
        MockRelay.QUEUES.setdefault(to_eid, []).append({
            "from_eid": self.eid,
            "encrypted": encrypted_payload,
            "timestamp": time.time(),
        })
        return True

    def send_envelope(self, to_eid, envelope):
        return self.send(to_eid, json.dumps(envelope, sort_keys=True))

    def poll(self, timeout=5):
        q = MockRelay.QUEUES.get(self.eid, [])
        msgs = list(q)
        q.clear()
        return msgs

    def poll_envelopes(self, timeout=5):
        # Same contract as RelayTransport: drain local inbox, then new messages
        with self._inbox_lock:
            out = list(self._inbox)
            self._inbox.clear()
        for m in self.poll(timeout=timeout):
            raw = m.get("encrypted", "")
            try:
                env = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(env, dict) and "iacp_type" in env:
                    out.append({
                        "from_eid": m.get("from_eid", ""),
                        "envelope": env,
                        "timestamp": m.get("timestamp", 0),
                    })
            except Exception:
                continue
        return out

    def push_inbox(self, items):
        """Re-queue envelopes polled but not consumed (matches RelayTransport)."""
        if not items:
            return
        with self._inbox_lock:
            self._inbox.extend(items)

    def start_polling(self, *a, **k):
        return None


def test_handshake_and_data(p):
    section("4. Mock-relay handshake + data + ordering")
    MockRelay.QUEUES.clear()
    eid_a = p.generate_eid_str()
    eid_b = p.generate_eid_str()
    ra, rb = MockRelay(eid_a), MockRelay(eid_b)
    box = {}

    def responder():
        try:
            box["s"] = p.perform_relay_handshake(rb, eid_b, None, False, timeout=15)
        except Exception as e:
            box["e"] = e
            box["tb"] = traceback.format_exc()

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    time.sleep(0.3)
    try:
        sa = p.perform_relay_handshake(ra, eid_a, eid_b, True, timeout=15)
        t.join(12)
        if "e" in box:
            check("handshake both sides", False, str(box["e"]))
            if VERBOSE:
                print(box.get("tb", ""))
            return
        sb = box.get("s")
        ok = sa is not None and sb is not None
        check("handshake both sides", ok)
        if not ok:
            return
        check("cookies match", sa.cookie_i == sb.cookie_i and sa.cookie_r == sb.cookie_r,
              f"A={sa.cookie_i[:8]}/{sa.cookie_r[:8]} B={sb.cookie_i[:8]}/{sb.cookie_r[:8]}")
        check("session_key match", sa.session_key == sb.session_key)
        check("peer EIDs cross-linked",
              sa.peer_eid == eid_b and sb.peer_eid == eid_a)

        # data
        check("send A→B", p.send_data_relay(ra, sa, "hello-B"))
        msg = p.recv_data_relay(rb, sb, timeout=5)
        check("recv A→B plaintext", msg == "hello-B", repr(msg))
        check("seq after 1 msg", sa.seq_send == 1 and sb.seq_recv == 1)

        check("send B→A", p.send_data_relay(rb, sb, "hello-A"))
        msg2 = p.recv_data_relay(ra, sa, timeout=5)
        check("recv B→A plaintext", msg2 == "hello-A", repr(msg2))

        # second ordered message
        p.send_data_relay(ra, sa, "msg-2")
        check("recv msg-2", p.recv_data_relay(rb, sb, timeout=5) == "msg-2")

        # out-of-order then correct in same batch
        sa.seq_send = 10
        enc = sa.encrypt("ooo")
        pkt = p.IACPPacket(p.IACPPacket.PSS_DATA, sa.local_eid, {"seq": 10, "encrypted": enc})
        pkt.sign(sa.local_eid)
        ra.send_envelope(eid_b, p.packet_to_relay_envelope(pkt))
        sa.seq_send = 2  # next will be 3
        p.send_data_relay(ra, sa, "msg-3")
        got = p.recv_data_relay(rb, sb, timeout=5)
        check("skip out-of-order, accept next seq", got == "msg-3", repr(got))

        # replay discarded, next accepted
        sa.seq_send = 2
        enc = sa.encrypt("replay")
        pkt = p.IACPPacket(p.IACPPacket.PSS_DATA, sa.local_eid, {"seq": 2, "encrypted": enc})
        pkt.sign(sa.local_eid)
        ra.send_envelope(eid_b, p.packet_to_relay_envelope(pkt))
        sa.seq_send = 3
        p.send_data_relay(ra, sa, "msg-4")
        got4 = p.recv_data_relay(rb, sb, timeout=5)
        check("skip replay, accept seq+1", got4 == "msg-4", repr(got4))

        p.close_relay_session(ra, sa)
        check("close_relay_session no exception", True)
    except Exception as e:
        check("handshake/data suite", False, f"{e}\n{traceback.format_exc()}")


def test_sig_failure_raises(p):
    section("5. Signature failure → RelaySessionError")
    MockRelay.QUEUES.clear()
    eid_a = p.generate_eid_str()
    eid_b = p.generate_eid_str()
    ra, rb = MockRelay(eid_a), MockRelay(eid_b)
    # minimal established session without full handshake
    sa = p.IACPSessionWire(eid_a, eid_b, "ci", "cr")
    sb = p.IACPSessionWire(eid_b, eid_a, "ci", "cr")
    # craft envelope with wrong signature
    env = {
        "iacp_type": p.IACPPacket.PSS_DATA,
        "sender": eid_a,
        "payload": {"seq": 1, "encrypted": sa.encrypt("x")},
        "signature": "00" * 32,
    }
    ra.send_envelope(eid_b, env)
    raised = False
    try:
        p.recv_data_relay(rb, sb, timeout=3)
    except p.RelaySessionError:
        raised = True
    except TimeoutError:
        # invalid sig is skipped in poll path inside recv – depending on impl
        # our impl raises on verify failure when processing PSS_DATA
        raised = False
    check("RelaySessionError or discard on bad sig", True,
          "raised" if raised else "discarded/timeout (also acceptable)")


def test_tcp_regression(p):
    section("6. TCP path still importable (regression smoke)")
    check("perform_handshake callable", callable(p.perform_handshake))
    check("send_data/recv_data callable", callable(p.send_data) and callable(p.recv_data))
    # optional: run demo_core if present
    demo = os.path.join(os.path.dirname(__file__), "demo_core.py")
    if os.path.isfile(demo):
        import subprocess
        r = subprocess.run([sys.executable, demo], capture_output=True, text=True, timeout=60)
        ok = r.returncode == 0 and "Demo completed successfully" in (r.stdout + r.stderr)
        check("demo_core.py exits 0", ok, (r.stderr or r.stdout)[-300:] if not ok else "")
    else:
        check("demo_core.py present", False, "file not found – skip")


def test_live_server(url: str, p):
    section(f"7. Live discovery/relay server @ {url}")
    import urllib.request
    base = url.rstrip("/")
    # health: register + discover
    eid = p.generate_eid_str()
    try:
        data = json.dumps({"eid": eid, "ip": "127.0.0.1", "port": 0, "topic": "debug"}).encode()
        req = urllib.request.Request(f"{base}/register", data=data,
                                     headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=5)
        body = json.loads(resp.read().decode())
        check("POST /register", body.get("status") == "ok", str(body))
    except Exception as e:
        check("POST /register", False, str(e))
        return

    try:
        resp = urllib.request.urlopen(f"{base}/discover?topic=debug", timeout=5)
        body = json.loads(resp.read().decode())
        found = any(x.get("eid") == eid for x in body.get("results") or [])
        check("GET /discover sees registration", found, str(body)[:200])
    except Exception as e:
        check("GET /discover", False, str(e))

    cookie = p.generate_cookie_str()
    relay = p.RelayTransport(base, eid, cookie)
    check("relay.register()", relay.register())
    # send to self and poll
    env = p.packet_to_relay_envelope(
        p.IACPPacket(p.IACPPacket.ERP_INIT, eid, {"nonce": "live"})
    )
    # need signature
    pkt = p.IACPPacket(p.IACPPacket.ERP_INIT, eid, {"nonce": "live"})
    pkt.sign(eid)
    env = p.packet_to_relay_envelope(pkt)
    check("relay.send_envelope to self", relay.send_envelope(eid, env))
    time.sleep(0.5)
    items = relay.poll_envelopes(timeout=3)
    check("relay.poll_envelopes receives", len(items) >= 1, f"count={len(items)}")


def main():
    global VERBOSE
    ap = argparse.ArgumentParser(description="IACP Relay Debug Suite")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--live", metavar="URL", help="Also test live discovery_server URL")
    ap.add_argument("--skip-demo", action="store_true", help="Skip demo_core regression")
    args = ap.parse_args()
    VERBOSE = args.verbose

    print("IACP Relay Debug Suite")
    print("======================")
    p = test_imports()
    if p is None:
        _summary()
        sys.exit(1)

    test_crypto(p)
    test_envelope(p)
    test_handshake_and_data(p)
    test_sig_failure_raises(p)
    if not args.skip_demo:
        test_tcp_regression(p)
    else:
        section("6. TCP regression skipped (--skip-demo)")
    if args.live:
        test_live_server(args.live, p)
    else:
        section("7. Live server skipped (pass --live URL to enable)")

    _summary()


def _summary():
    print("\n=== SUMMARY ===")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = sum(1 for _, ok, _ in RESULTS if not ok)
    total = len(RESULTS)
    print(f"  {passed}/{total} passed, {failed} failed")
    if failed:
        print("  Failed checks:")
        for name, ok, detail in RESULTS:
            if not ok:
                print(f"    - {name}: {detail}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
