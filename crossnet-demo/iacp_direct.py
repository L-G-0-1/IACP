"""
IACP Direct – Pure Python IACP Core Implementation
====================================================
Enables two AI agents to communicate directly via TCP using the IACP protocol
(EID, ERP, PSS). This is a protocol-flow demonstrator for the IETF draft.

WARNING: This is a DEMONSTRATION implementation. It illustrates the intended
ERP/PSS message flow but uses simplified cryptography (HMAC instead of Ed25519,
XOR+HMAC instead of AES-GCM). It is NOT suitable for production security.
"""

import socket
import json
import hashlib
import hmac
import os
import time
import urllib.request
import threading
from typing import Optional


# ---------------------------------------------------------------------------
# Cryptographic helpers (simplified for demonstration)
# ---------------------------------------------------------------------------

def generate_eid() -> str:
    """Generate an Ephemeral Agent Identity (32-byte hex string)."""
    return os.urandom(32).hex()


def sign_message(eid: str, msg: str) -> str:
    """Simulate Ed25519 signing via HMAC-SHA256 (simplified for demo)."""
    return hmac.new(eid.encode(), msg.encode(), hashlib.sha256).hexdigest()


def verify_signature(eid: str, msg: str, sig: str) -> bool:
    """Verify a simulated signature."""
    expected = sign_message(eid, msg)
    return hmac.compare_digest(expected, sig)


# ---------------------------------------------------------------------------
# Stream-safe TCP framing with persistent receive buffer
# ---------------------------------------------------------------------------

class FrameBuffer:
    """Persistent per-connection receive buffer for stream-safe TCP framing."""

    def __init__(self):
        self._buf = b""

    def feed(self, data: bytes):
        """Add received data to the buffer."""
        self._buf += data

    def read_line(self) -> Optional[bytes]:
        """Extract one newline-delimited frame if available. Returns None if incomplete."""
        if b"\n" not in self._buf:
            return None
        line, self._buf = self._buf.split(b"\n", 1)
        return line

    def has_data(self) -> bool:
        return len(self._buf) > 0


# ---------------------------------------------------------------------------
# IACP Wire Protocol (JSON lines over TCP)
# ---------------------------------------------------------------------------

class IACPPacket:
    """An IACP protocol packet (simulates ERP + PSS frames)."""

    ERP_INIT = "ERP_INIT"
    ERP_ALLOC = "ERP_ALLOC"
    ERP_REGISTER = "ERP_REGISTER"
    ERP_ACK = "ERP_ACK"
    PSS_INIT = "PSS_INIT"
    PSS_NEG = "PSS_NEG"
    PSS_ACK = "PSS_ACK"
    PSS_DATA = "PSS_DATA"
    PSS_CLOSE = "PSS_CLOSE"

    MAX_FRAME_SIZE = 1 << 20  # 1 MB maximum frame size

    def __init__(self, msg_type: str, sender: str, payload: dict):
        self.msg_type = msg_type
        self.sender = sender
        self.payload = payload
        self.signature = ""

    def sign(self, eid: str):
        """Sign this packet with the given EID."""
        self.signature = sign_message(eid, json.dumps(self.to_dict(), sort_keys=True))

    def verify(self, eid: str) -> bool:
        """Verify this packet's signature against the given EID."""
        sig = self.signature
        self.signature = ""
        result = verify_signature(eid, json.dumps(self.to_dict(), sort_keys=True), sig)
        self.signature = sig
        return result

    def to_dict(self) -> dict:
        return {
            "type": self.msg_type,
            "sender": self.sender,
            "payload": self.payload,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IACPPacket":
        pkt = cls(d["type"], d["sender"], d["payload"])
        pkt.signature = d.get("signature", "")
        return pkt


# ---------------------------------------------------------------------------
# IACP Session (ERP + PSS Handshake)
# ---------------------------------------------------------------------------

class IACPSession:
    """Represents an established IACP PSS session."""

    def __init__(self, local_eid: str, peer_eid: str, cookie_i: str, cookie_r: str):
        self.local_eid = local_eid
        self.peer_eid = peer_eid
        self.cookie_i = cookie_i
        self.cookie_r = cookie_r
        self.seq_send = 0
        self.seq_recv = 0
        # Symmetric key: sorted EIDs so both sides derive the same key
        sorted_eids = "".join(sorted([local_eid, peer_eid]))
        self.session_key = hashlib.sha256(
            (cookie_i + cookie_r + sorted_eids).encode()
        ).hexdigest()[:32]

    def encrypt(self, plaintext: str) -> str:
        """Encrypt with integrity protection (XOR + HMAC, simulating AES-GCM)."""
        key = self.session_key.encode()
        nonce = os.urandom(12).hex()
        pt_bytes = plaintext.encode("utf-8")
        ct_bytes = bytes([pt_bytes[i] ^ key[i % len(key)] for i in range(len(pt_bytes))])
        # MAC covers nonce + ciphertext for integrity
        mac = hmac.new(key, (nonce + ct_bytes.hex()).encode(), hashlib.sha256).hexdigest()[:16]
        return json.dumps({"nonce": nonce, "ct": ct_bytes.hex(), "mac": mac})

    def decrypt(self, encrypted: str) -> str:
        """Decrypt and verify integrity. Raises ValueError on MAC mismatch."""
        data = json.loads(encrypted)
        key = self.session_key.encode()
        nonce = data.get("nonce", "")
        ct_hex = data.get("ct", "")
        mac = data.get("mac", "")

        # Verify MAC before decryption
        expected_mac = hmac.new(key, (nonce + ct_hex).encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(expected_mac, mac):
            raise ValueError("MAC verification failed: ciphertext has been tampered with")

        ct_bytes = bytes.fromhex(ct_hex)
        pt_bytes = bytes([ct_bytes[i] ^ key[i % len(key)] for i in range(len(ct_bytes))])
        return pt_bytes.decode("utf-8", errors="replace")


def recv_frame(sock: socket.socket, buf: FrameBuffer, timeout: float = 30.0) -> IACPPacket:
    """Read one complete frame from the socket using the persistent buffer."""
    sock.settimeout(timeout)
    while True:
        line = buf.read_line()
        if line is not None:
            if len(line) > IACPPacket.MAX_FRAME_SIZE:
                raise ValueError(f"Frame too large: {len(line)} bytes")
            return IACPPacket.from_dict(json.loads(line.decode()))
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        buf.feed(chunk)


def perform_handshake(sock: socket.socket, my_eid: str, is_initiator: bool) -> IACPSession:
    """Perform the IACP ERP + PSS handshake over a connected socket.

    This implements the full handshake sequence from IETF Draft §4.2.3 and §6.4.3.
    All handshake packets are signed and signatures are verified.
    """
    buf = FrameBuffer()

    def send_pkt(pkt: IACPPacket):
        pkt.sign(my_eid)
        sock.sendall((json.dumps(pkt.to_dict()) + "\n").encode())

    def recv_pkt() -> IACPPacket:
        return recv_frame(sock, buf)

    if is_initiator:
        # ERP: INIT
        send_pkt(IACPPacket(IACPPacket.ERP_INIT, my_eid, {"nonce": os.urandom(16).hex()}))
        alloc = recv_pkt()
        if alloc.msg_type != IACPPacket.ERP_ALLOC:
            raise ValueError(f"Expected ERP_ALLOC, got {alloc.msg_type}")
        if not alloc.verify(alloc.sender):
            raise ValueError("ERP_ALLOC signature verification failed")
        peer_eid = alloc.sender

        # ERP: REGISTER
        send_pkt(IACPPacket(IACPPacket.ERP_REGISTER, my_eid,
                             {"peer_eid": peer_eid, "slot": alloc.payload.get("slot", 0)}))
        ack = recv_pkt()
        if ack.msg_type != IACPPacket.ERP_ACK:
            raise ValueError(f"Expected ERP_ACK, got {ack.msg_type}")
        if not ack.verify(ack.sender):
            raise ValueError("ERP_ACK signature verification failed")

        # PSS: INIT (Dual-Cookie)
        cookie_i = os.urandom(8).hex()
        send_pkt(IACPPacket(IACPPacket.PSS_INIT, my_eid, {"cookie_i": cookie_i}))
        neg = recv_pkt()
        if neg.msg_type != IACPPacket.PSS_NEG:
            raise ValueError(f"Expected PSS_NEG, got {neg.msg_type}")
        if not neg.verify(neg.sender):
            raise ValueError("PSS_NEG signature verification failed")
        cookie_r = neg.payload.get("cookie_r", "")

        # PSS: ACK
        send_pkt(IACPPacket(IACPPacket.PSS_ACK, my_eid,
                             {"cookie_i": cookie_i, "cookie_r": cookie_r}))

        return IACPSession(my_eid, peer_eid, cookie_i, cookie_r)

    else:
        # Responder: receive ERP_INIT
        init = recv_pkt()
        if init.msg_type != IACPPacket.ERP_INIT:
            raise ValueError(f"Expected ERP_INIT, got {init.msg_type}")
        if not init.verify(init.sender):
            raise ValueError("ERP_INIT signature verification failed")
        peer_eid = init.sender

        # ERP: ALLOC
        send_pkt(IACPPacket(IACPPacket.ERP_ALLOC, my_eid,
                             {"slot": int.from_bytes(os.urandom(4), "big")}))
        reg = recv_pkt()
        if reg.msg_type != IACPPacket.ERP_REGISTER:
            raise ValueError(f"Expected ERP_REGISTER, got {reg.msg_type}")
        if not reg.verify(reg.sender):
            raise ValueError("ERP_REGISTER signature verification failed")

        # ERP: ACK
        send_pkt(IACPPacket(IACPPacket.ERP_ACK, my_eid, {}))

        # PSS: INIT
        pss_init = recv_pkt()
        if pss_init.msg_type != IACPPacket.PSS_INIT:
            raise ValueError(f"Expected PSS_INIT, got {pss_init.msg_type}")
        if not pss_init.verify(pss_init.sender):
            raise ValueError("PSS_INIT signature verification failed")
        cookie_i = pss_init.payload.get("cookie_i", "")
        cookie_r = os.urandom(8).hex()

        # PSS: NEG
        send_pkt(IACPPacket(IACPPacket.PSS_NEG, my_eid,
                             {"cookie_i": cookie_i, "cookie_r": cookie_r}))

        # PSS: ACK
        ack = recv_pkt()
        if ack.msg_type != IACPPacket.PSS_ACK:
            raise ValueError(f"Expected PSS_ACK, got {ack.msg_type}")
        if not ack.verify(ack.sender):
            raise ValueError("PSS_ACK signature verification failed")

        return IACPSession(my_eid, peer_eid, cookie_i, cookie_r)


def send_data(sock: socket.socket, session: IACPSession, message: str):
    """Send encrypted data over an established PSS session."""
    session.seq_send += 1
    encrypted = session.encrypt(message)
    pkt = IACPPacket(IACPPacket.PSS_DATA, session.local_eid, {
        "seq": session.seq_send,
        "encrypted": encrypted,
    })
    pkt.sign(session.local_eid)
    sock.sendall((json.dumps(pkt.to_dict()) + "\n").encode())


def recv_data(sock: socket.socket, session: IACPSession, buf: Optional[FrameBuffer] = None) -> str:
    """Receive and decrypt data over an established PSS session.

    Uses a persistent FrameBuffer for stream-safe TCP framing.
    If no buffer is provided, a new one is created (for single-use scenarios).
    """
    if buf is None:
        buf = FrameBuffer()

    pkt = recv_frame(sock, buf)

    if pkt.msg_type != IACPPacket.PSS_DATA:
        raise ValueError(f"Expected PSS_DATA, got {pkt.msg_type}")

    # Verify packet signature
    if not pkt.verify(session.peer_eid):
        raise ValueError("PSS_DATA signature verification failed")

    seq = pkt.payload.get("seq", 0)
    if seq <= session.seq_recv:
        raise ValueError(f"Replay attack detected! seq={seq} <= recv={session.seq_recv}")
    session.seq_recv = seq

    return session.decrypt(pkt.payload["encrypted"])


# ---------------------------------------------------------------------------
# Relay transport helpers (cross-network via discovery server)
# ---------------------------------------------------------------------------

class RelayTransport:
    """Provides message delivery via the discovery server relay API.
    
    This is used when direct TCP is not possible (e.g., NAT, firewall).
    """

    def __init__(self, relay_url: str, eid: str, session_cookie: str):
        self.relay_url = relay_url.rstrip("/")
        self.eid = eid
        self.session_cookie = session_cookie
        self._registered = False

    def register(self) -> bool:
        """Register this agent for relay mode."""
        try:
            data = json.dumps({
                "eid": self.eid,
                "session_cookie": self.session_cookie
            }).encode()
            req = urllib.request.Request(
                f"{self.relay_url}/relay_register",
                data=data,
                headers={"Content-Type": "application/json"}
            )
            resp = urllib.request.urlopen(req, timeout=5)
            result = json.loads(resp.read().decode())
            print(f"[Relay] Registration: {result.get('message', 'ok')}")
            self._registered = True
            return True
        except Exception as e:
            print(f"[Relay] Registration failed: {e}")
            return False

    def send(self, to_eid: str, encrypted_payload: str) -> bool:
        """Send an encrypted message to another agent via relay."""
        if not self._registered:
            print("[Relay] Not registered. Call register() first.")
            return False
        try:
            data = json.dumps({
                "from_eid": self.eid,
                "to_eid": to_eid,
                "encrypted": encrypted_payload,
                "session_cookie": self.session_cookie
            }).encode()
            req = urllib.request.Request(
                f"{self.relay_url}/relay",
                data=data,
                headers={"Content-Type": "application/json"}
            )
            resp = urllib.request.urlopen(req, timeout=10)
            result = json.loads(resp.read().decode())
            return result.get("status") == "ok"
        except Exception as e:
            print(f"[Relay] Send failed: {e}")
            return False

    def poll(self, timeout: int = 5) -> list:
        """Poll for incoming relayed messages.
        
        Returns a list of messages: [{"from_eid": "...", "encrypted": "...", "timestamp": ...}, ...]
        """
        if not self._registered:
            print("[Relay] Not registered. Call register() first.")
            return []
        try:
            url = f"{self.relay_url}/relay_poll?eid={self.eid}&session_cookie={self.session_cookie}&timeout={timeout}"
            resp = urllib.request.urlopen(url, timeout=timeout + 5)
            result = json.loads(resp.read().decode())
            if result.get("status") == "ok":
                return result.get("messages", [])
            return []
        except Exception as e:
            print(f"[Relay] Poll error: {e}")
            return []

    def start_polling(self, callback, stop_event: threading.Event, poll_interval: int = 1):
        """Start a background polling thread for incoming messages.
        
        Args:
            callback: Function to call with each received message.
            stop_event: Threading event to signal stopping.
            poll_interval: Seconds to wait between polls.
        """
        print(f"[Relay] Starting background poll for {self.eid[:16]}...")
        
        def poll_loop():
            while not stop_event.is_set():
                messages = self.poll(timeout=5)
                for msg in messages:
                    if not stop_event.is_set():
                        callback(msg)
                stop_event.wait(poll_interval)
        
        thread = threading.Thread(target=poll_loop, daemon=True)
        thread.start()
        return thread
