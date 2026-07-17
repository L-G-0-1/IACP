"""
IACP Direct – Python-Implementierung der IACP Kernkomponenten
=============================================================
Ermöglicht zwei KI-Agenten direkt via TCP + IACP-Protokoll zu kommunizieren,
ohne die Rust-Bridge. Enthält EID, ERP, PSS in Pure Python.
"""

import socket
import threading
import json
import hashlib
import hmac
import os
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Kryptografie-Hilfsfunktionen (vereinfacht für Demo)
# ---------------------------------------------------------------------------

def generate_eid() -> str:
    """Erzeugt eine EID (32-Byte hex)."""
    return os.urandom(32).hex()

def sign_message(eid: str, msg: str) -> str:
    """Simuliert Ed25519-Signatur via HMAC-SHA256."""
    return hmac.new(eid.encode(), msg.encode(), hashlib.sha256).hexdigest()

def verify_signature(eid: str, msg: str, sig: str) -> bool:
    """Verifiziert die simulierte Signatur."""
    expected = sign_message(eid, msg)
    return hmac.compare_digest(expected, sig)


# ---------------------------------------------------------------------------
# IACP Wire Protocol (simpel: JSON-Zeilen über TCP)
# ---------------------------------------------------------------------------

class IACPPacket:
    """Ein IACP-Paket (simuliert ERP + PSS Frames)."""

    ERP_INIT = "ERP_INIT"
    ERP_ALLOC = "ERP_ALLOC"
    ERP_REGISTER = "ERP_REGISTER"
    ERP_ACK = "ERP_ACK"
    PSS_INIT = "PSS_INIT"
    PSS_NEG = "PSS_NEG"
    PSS_ACK = "PSS_ACK"
    PSS_DATA = "PSS_DATA"
    PSS_CLOSE = "PSS_CLOSE"

    def __init__(self, msg_type: str, sender: str, payload: dict):
        self.msg_type = msg_type
        self.sender = sender
        self.payload = payload
        self.signature = ""

    def sign(self, eid: str):
        self.signature = sign_message(eid, json.dumps(self.to_dict(), sort_keys=True))

    def verify(self, eid: str) -> bool:
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
    """Repräsentiert eine etablierte IACP PSS Session."""

    def __init__(self, local_eid: str, peer_eid: str, cookie_i: str, cookie_r: str):
        self.local_eid = local_eid
        self.peer_eid = peer_eid
        self.cookie_i = cookie_i
        self.cookie_r = cookie_r
        self.seq_send = 0
        self.seq_recv = 0
        # Symmetrischer Key: Sortierte EIDs damit beide Seiten identischen Key haben
        sorted_eids = "".join(sorted([local_eid, peer_eid]))
        self.session_key = hashlib.sha256(
            (cookie_i + cookie_r + sorted_eids).encode()
        ).hexdigest()[:32]

    def encrypt(self, plaintext: str) -> str:
        """Simuliert AES-GCM-256 (XOR + HMAC)."""
        key = self.session_key.encode()
        nonce = os.urandom(12).hex()
        pt_bytes = plaintext.encode("utf-8")
        ct_bytes = bytes([pt_bytes[i] ^ key[i % len(key)] for i in range(len(pt_bytes))])
        mac = hmac.new(key, (nonce + ct_bytes.hex()).encode(), hashlib.sha256).hexdigest()[:16]
        return json.dumps({"nonce": nonce, "ct": ct_bytes.hex(), "mac": mac})

    def decrypt(self, encrypted: str) -> str:
        """Entschlüsselt die simulierte AES-GCM."""
        data = json.loads(encrypted)
        key = self.session_key.encode()
        ct_bytes = bytes.fromhex(data["ct"])
        pt_bytes = bytes([ct_bytes[i] ^ key[i % len(key)] for i in range(len(ct_bytes))])
        return pt_bytes.decode("utf-8", errors="replace")


def perform_handshake(sock: socket.socket, my_eid: str, is_initiator: bool, peer_eid_hint: str = "") -> IACPSession:
    """Führt den IACP ERP + PSS Handshake über einen Socket durch."""

    def send_pkt(pkt: IACPPacket):
        pkt.sign(my_eid)
        sock.sendall((json.dumps(pkt.to_dict()) + "\n").encode())

    def recv_pkt() -> IACPPacket:
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("Verbindung geschlossen")
            buf += chunk
        line, _ = buf.split(b"\n", 1)
        return IACPPacket.from_dict(json.loads(line.decode()))

    if is_initiator:
        # ERP: INIT
        send_pkt(IACPPacket(IACPPacket.ERP_INIT, my_eid, {"nonce": os.urandom(16).hex()}))
        alloc = recv_pkt()
        if alloc.msg_type != IACPPacket.ERP_ALLOC:
            raise ValueError(f"Erwartet ERP_ALLOC, bekam {alloc.msg_type}")

        # ERP: REGISTER
        send_pkt(IACPPacket(IACPPacket.ERP_REGISTER, my_eid,
                             {"peer_eid": alloc.sender, "slot": alloc.payload.get("slot", 0)}))
        ack = recv_pkt()
        if ack.msg_type != IACPPacket.ERP_ACK:
            raise ValueError(f"Erwartet ERP_ACK, bekam {ack.msg_type}")

        peer_eid = alloc.sender

        # PSS: INIT (Dual-Cookie)
        cookie_i = os.urandom(8).hex()
        send_pkt(IACPPacket(IACPPacket.PSS_INIT, my_eid, {"cookie_i": cookie_i}))
        neg = recv_pkt()
        if neg.msg_type != IACPPacket.PSS_NEG:
            raise ValueError(f"Erwartet PSS_NEG, bekam {neg.msg_type}")

        cookie_r = neg.payload.get("cookie_r", "")
        # PSS: ACK
        send_pkt(IACPPacket(IACPPacket.PSS_ACK, my_eid,
                             {"cookie_i": cookie_i, "cookie_r": cookie_r}))

        return IACPSession(my_eid, peer_eid, cookie_i, cookie_r)

    else:
        # Responder: ERP empfangen
        init = recv_pkt()
        if init.msg_type != IACPPacket.ERP_INIT:
            raise ValueError(f"Erwartet ERP_INIT, bekam {init.msg_type}")

        # ERP: ALLOC senden
        send_pkt(IACPPacket(IACPPacket.ERP_ALLOC, my_eid,
                             {"slot": int.from_bytes(os.urandom(4), "big")}))
        reg = recv_pkt()
        if reg.msg_type != IACPPacket.ERP_REGISTER:
            raise ValueError(f"Erwartet ERP_REGISTER, bekam {reg.msg_type}")

        # ERP: ACK
        peer_eid = init.sender
        send_pkt(IACPPacket(IACPPacket.ERP_ACK, my_eid, {}))

        # PSS: INIT empfangen
        pss_init = recv_pkt()
        if pss_init.msg_type != IACPPacket.PSS_INIT:
            raise ValueError(f"Erwartet PSS_INIT, bekam {pss_init.msg_type}")

        cookie_i = pss_init.payload.get("cookie_i", "")
        cookie_r = os.urandom(8).hex()

        # PSS: NEG senden
        send_pkt(IACPPacket(IACPPacket.PSS_NEG, my_eid,
                             {"cookie_i": cookie_i, "cookie_r": cookie_r}))

        # PSS: ACK empfangen
        ack = recv_pkt()
        if ack.msg_type != IACPPacket.PSS_ACK:
            raise ValueError(f"Erwartet PSS_ACK, bekam {ack.msg_type}")

        return IACPSession(my_eid, peer_eid, cookie_i, cookie_r)


def send_data(sock: socket.socket, session: IACPSession, message: str):
    """Sendet Daten über eine etablierte PSS Session."""
    session.seq_send += 1
    encrypted = session.encrypt(message)
    pkt = IACPPacket(IACPPacket.PSS_DATA, session.local_eid, {
        "seq": session.seq_send,
        "encrypted": encrypted,
    })
    pkt.sign(session.local_eid)
    sock.sendall((json.dumps(pkt.to_dict()) + "\n").encode())


def recv_data(sock: socket.socket, session: IACPSession) -> str:
    """Empfängt Daten über eine etablierte PSS Session."""
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Verbindung geschlossen")
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    pkt = IACPPacket.from_dict(json.loads(line.decode()))

    if pkt.msg_type != IACPPacket.PSS_DATA:
        raise ValueError(f"Erwartet PSS_DATA, bekam {pkt.msg_type}")

    seq = pkt.payload.get("seq", 0)
    if seq <= session.seq_recv:
        raise ValueError(f"Replay-Angriff erkannt! seq={seq} <= recv={session.seq_recv}")
    session.seq_recv = seq

    return session.decrypt(pkt.payload["encrypted"])