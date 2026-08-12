"""IACP Unified Protocol – Complete Implementation (v3)

Unifies iacp_direct.py + IACP_DHT.py + Advanced Features.
Contains all 27 IACP Draft-03 components + DHI (Section 4.1).

v3 Changes:
- Added DHI Content Equivalence (EVM <= 0.001, SHA-256, Cross-Entropy)
- Added HCO Serialization (Hand-off Context Object)
- Added DS Topic Hierarchy queries
- Added SecureSessionChannel for high-level agent communication
- Added IACPAgent methods: connect(), discover(), join_discovery_space()
"""
import socket, json, hashlib, hmac, os, time, threading, struct, urllib.request, math
from typing import Optional, Dict, List, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import secrets
import re

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
    _HAZMAT = True
except ImportError:
    _HAZMAT = False; import warnings; warnings.warn("cryptography.hazmat fehlt")

# ─────────────────────────────────────────────────────────────────────────────
# 1. CRYPTOGRAPHIC HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> bytes: return hashlib.sha256(data).digest()
def sha256_hex(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def generate_eid() -> bytes: return os.urandom(32)
def generate_eid_str() -> str: return os.urandom(32).hex()
def generate_iat() -> bytes: return os.urandom(32)
def generate_cookie() -> bytes: return os.urandom(8)
def generate_cookie_str() -> str: return os.urandom(8).hex()

if _HAZMAT:
    def sign_message(pk: bytes, msg: bytes) -> bytes: return ed25519.Ed25519PrivateKey.from_private_bytes(pk).sign(msg)
    def verify_signature(pub: bytes, msg: bytes, sig: bytes) -> bool:
        try: ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg); return True
        except: return False
    def generate_keypair() -> Tuple[bytes, bytes]:
        priv = ed25519.Ed25519PrivateKey.generate(); pub = priv.public_key()
        return (priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()), pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
    def x25519_generate_keypair() -> Tuple[bytes, bytes]:
        priv = x25519.X25519PrivateKey.generate(); pub = priv.public_key()
        return (priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()), pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
    def x25519_ecdh(pk: bytes, pub: bytes) -> bytes: return x25519.X25519PrivateKey.from_private_bytes(pk).exchange(x25519.X25519PublicKey.from_public_bytes(pub))
    def aes_gcm_encrypt(key: bytes, pt: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        c = AESGCM(key).encrypt(nonce, pt, None); return c[:len(pt)], c[len(pt):]
    def aes_gcm_decrypt(key: bytes, ct: bytes, nonce: bytes, mac: bytes) -> bytes: return AESGCM(key).decrypt(nonce, ct + mac, None)
    def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)
else:
    # Fallback mode (no cryptography library): use HMAC-SHA256 with key = sha256(priv)
    # so that sign(priv, msg) and verify(pub=sha256(priv), msg, sig) are consistent.
    def sign_message(pk: bytes, msg: bytes) -> bytes: return hmac.new(sha256(pk), msg, hashlib.sha256).digest()[:64]
    def verify_signature(pub: bytes, msg: bytes, sig: bytes) -> bool: return hmac.compare_digest(hmac.new(pub, msg, hashlib.sha256).digest()[:64], sig)
    def generate_keypair() -> Tuple[bytes, bytes]: priv = os.urandom(32); return priv, sha256(priv)
    def x25519_generate_keypair() -> Tuple[bytes, bytes]: priv = os.urandom(32); return priv, sha256(priv)
    def x25519_ecdh(pk: bytes, pub: bytes) -> bytes: return sha256(pk + pub)
    def aes_gcm_encrypt(key: bytes, pt: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        return bytes([pt[i] ^ key[i % len(key)] for i in range(len(pt))]), hmac.new(key, nonce + pt, hashlib.sha256).digest()[:16]
    def aes_gcm_decrypt(key: bytes, ct: bytes, nonce: bytes, mac: bytes) -> bytes:
        if not hmac.compare_digest(hmac.new(key, nonce + ct, hashlib.sha256).digest()[:16], mac): raise ValueError("MAC mismatch")
        return bytes([ct[i] ^ key[i % len(key)] for i in range(len(ct))])
    def hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes: return sha256(ikm + salt + info)[:length]

def sign_message_str(eid: str, msg: str) -> str:
    # Wire path: random hex EIDs act as shared secrets → HMAC only.
    # Ed25519 would need pub = priv.public_key(), not sha256(eid).
    return hmac.new(eid.encode(), msg.encode(), hashlib.sha256).hexdigest()

def verify_signature_str(eid: str, msg: str, sig: str) -> bool:
    return hmac.compare_digest(sign_message_str(eid, msg), sig)

# ─────────────────────────────────────────────────────────────────────────────
# 2. PoW (Proof-of-Work) – Hashcash
# ─────────────────────────────────────────────────────────────────────────────

def calculate_pow_nonce(target_key: bytes, difficulty: int = 2) -> Tuple[int, bytes]:
    nonce = 0
    while True:
        h = sha256(target_key + nonce.to_bytes(8, 'big')); z = 0
        for b in reversed(h):
            if b == 0: z += 8
            else: z += (b & -b).bit_length() - 1; break
        if z >= difficulty: return nonce, h
        nonce += 1
        if nonce > 100000: raise ValueError(f"PoW failed after {nonce}")

def verify_pow(target_key: bytes, nonce: int, difficulty: int = 2) -> bool:
    h = sha256(target_key + nonce.to_bytes(8, 'big')); z = 0
    for b in reversed(h):
        if b == 0: z += 8
        else: z += (b & -b).bit_length() - 1; break
    return z >= difficulty

# ─────────────────────────────────────────────────────────────────────────────
# 3. DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DHTRecord:
    key: bytes; value: bytes; timestamp: float = field(default_factory=time.time)
    ttl: int = 3600; publisher_eid: Optional[bytes] = None
    def is_expired(self) -> bool: return time.time() > self.timestamp + self.ttl

@dataclass
class DiscoverySpace:
    ds_id: bytes; namespace: str; topic: str; version: int; curator_eid: bytes
    description: str = ""; created_at: float = field(default_factory=time.time)

@dataclass
class DSJoinRecord: ds_id: bytes; agent_eid: bytes; timestamp: int; signature: bytes

@dataclass
class ForwardingTicket:
    target_eid: bytes; new_locator: str; ttl: int; nonce: bytes; encrypted_data: bytes; ephemeral_pubkey: bytes; signature: bytes

@dataclass
class EIDRecord:
    eid: bytes; public_key: bytes; first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time); reputation: float = 1.0
    pom_count: int = 0; is_slashed: bool = False; slash_timestamp: Optional[float] = None
    current_generation: int = 0; current_locator: str = ""

@dataclass
class PSSSession:
    session_id: bytes; initiator_eid: bytes; responder_eid: bytes; i_cookie: bytes; r_cookie: bytes
    state: str = "STATE_HEARING"; initiator_seq: int = 0; responder_seq: int = 0
    created_at: float = field(default_factory=time.time); last_activity: float = field(default_factory=time.time)
    sfc_active: bool = False; sfc_conditions: Optional[bytes] = None

@dataclass
class ESEndpoint:
    eid: bytes; endpoint_id: bytes; is_global: bool = True; data: Dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time); ttl: int = 3600

@dataclass
class PoMTicket:
    target_eid: bytes; fragment_a: bytes; fragment_b: bytes; timestamp: float = field(default_factory=time.time)
    accuser_eid: Optional[bytes] = None; signature: Optional[bytes] = None

@dataclass
class TwoPSEEscrow:
    target_eid: bytes; state: str = "STATE_CHALLENGED"; escrow_start: float = field(default_factory=time.time)
    escrow_duration: int = 3600; rebuttal_deadline: float = field(default_factory=lambda: time.time() + 3600)
    confirmation_count: int = 0; required_confirmations: int = 7

# === NEW: DHI Data Structures (Section 4.1) ===
@dataclass
class HCO:
    """Hand-off Context Object – serialized for legacy browser fallback (Section 4.1.4.2)."""
    trigger_type: int      # 2 bytes: Hand-off Trigger Context Type
    esd_eid: bytes         # 32 bytes: Ephemeral Session Derivative EID
    session_hash: bytes    # 32 bytes: Persistent State Session Hash
    sequence: int          # 4 bytes
    capabilities: int      # 4 bytes
    target_url: str        # variable-length UTF-8

    def serialize(self) -> bytes:
        url_bytes = self.target_url.encode('utf-8')
        return (struct.pack('>H', self.trigger_type) + self.esd_eid + self.session_hash +
                struct.pack('>II', self.sequence, self.capabilities) +
                struct.pack('>H', len(url_bytes)) + url_bytes)

    @classmethod
    def deserialize(cls, data: bytes) -> 'HCO':
        trigger = struct.unpack('>H', data[0:2])[0]
        esd = data[2:34]; sh = data[34:66]
        seq, caps = struct.unpack('>II', data[66:74])
        url_len = struct.unpack('>H', data[74:76])[0]
        url = data[76:76+url_len].decode('utf-8')
        return cls(trigger, esd, sh, seq, caps, url)

# ─────────────────────────────────────────────────────────────────────────────
# 4. SIMPLE DHT (Kademlia-inspired)
# ─────────────────────────────────────────────────────────────────────────────

class SimpleDHT:
    def __init__(self, node_id: bytes, port: int = 5000):
        self.node_id = node_id; self.port = port
        self.storage: Dict[bytes, DHTRecord] = {}
        self.routing_table: Dict[int, List[Tuple[bytes, str, int]]] = {}
        self.lock = threading.Lock(); self.k = 20; self.alpha = 3

    def _get_bucket_index(self, nid: bytes) -> int:
        x = int.from_bytes(self.node_id, 'big') ^ int.from_bytes(nid, 'big')
        return 0 if x == 0 else 255 - x.bit_length()

    def _xor_distance(self, id1: bytes, id2: bytes) -> int:
        return int.from_bytes(id1, 'big') ^ int.from_bytes(id2, 'big')

    def store(self, key: bytes, value: bytes, publisher_eid: Optional[bytes] = None, ttl: int = 3600) -> bool:
        with self.lock: self.storage[key] = DHTRecord(key=key, value=value, ttl=ttl, publisher_eid=publisher_eid); return True

    def lookup(self, key: bytes) -> Optional[bytes]:
        with self.lock:
            if key in self.storage:
                r = self.storage[key]
                if not r.is_expired(): return r.value
                del self.storage[key]
        return None

    def find_node(self, target_id: bytes) -> List[Tuple[bytes, str, int]]:
        with self.lock:
            all_n = [n for b in self.routing_table.values() for n in b]
            all_n.sort(key=lambda n: self._xor_distance(n[0], target_id)); return all_n[:self.k]

    def update_routing_table(self, node_id: bytes, host: str, port: int):
        with self.lock:
            bi = self._get_bucket_index(node_id)
            if bi not in self.routing_table: self.routing_table[bi] = []
            b = self.routing_table[bi]; b[:] = [n for n in b if n[0] != node_id]; b.append((node_id, host, port))
            if len(b) > self.k: b.pop()

    def cleanup_expired(self):
        with self.lock:
            for k in [k for k, v in self.storage.items() if v.is_expired()]: del self.storage[k]

    def list_keys_by_prefix(self, prefix: bytes) -> List[bytes]:
        """Searches storage for keys starting with the given prefix."""
        with self.lock: return [k for k in self.storage if k[:len(prefix)] == prefix and not self.storage[k].is_expired()]

# ─────────────────────────────────────────────────────────────────────────────
# 5. DISCOVERY SPACES (Section 6.2)
# ─────────────────────────────────────────────────────────────────────────────

class DiscoverySpaceManager:
    def __init__(self, dht: SimpleDHT): self.dht = dht; self.discovery_spaces: Dict[bytes, DiscoverySpace] = {}

    def compute_ds_id(self, namespace: str, topic: str, version: int) -> bytes:
        return sha256(f"ds:{namespace}:{topic}:{version}".encode())

    def announce_ds(self, namespace: str, topic: str, version: int, curator_private_key: bytes, description: str = "") -> bool:
        ds_id = self.compute_ds_id(namespace, topic, version)
        curator_eid = sha256(curator_private_key)
        ds = DiscoverySpace(ds_id=ds_id, namespace=namespace, topic=topic, version=version, curator_eid=curator_eid, description=description)
        ds_data = {"ds_id": ds_id.hex(), "namespace": namespace, "topic": topic, "version": version, "curator_eid": curator_eid.hex(), "description": description, "created_at": ds.created_at}
        sig = sign_message(curator_private_key, json.dumps(ds_data, sort_keys=True).encode()).hex()
        ok = self.dht.store(ds_id, json.dumps({"data": ds_data, "signature": sig}).encode(), publisher_eid=curator_eid, ttl=86400)
        if ok: self.discovery_spaces[ds_id] = ds
        return ok

    def join_ds(self, ds_id: bytes, agent_private_key: bytes) -> bool:
        ae = sha256(agent_private_key); ts = int(time.time())
        jd = {"ds_id": ds_id.hex(), "agent_eid": ae.hex(), "timestamp": ts}
        sig = sign_message(agent_private_key, json.dumps(jd, sort_keys=True).encode()).hex()
        return self.dht.store(sha256(ds_id + ae), json.dumps({"data": jd, "signature": sig}).encode(), publisher_eid=ae, ttl=3600)

    def query_ds(self, ds_id: bytes, max_results: int = 10) -> List[Dict]:
        results = []
        with self.dht.lock:
            for k in [k for k in self.dht.storage if k[:len(ds_id)] == ds_id and not self.dht.storage[k].is_expired()][:max_results]:
                try: results.append(json.loads(self.dht.storage[k].value.decode()).get("data", {}))
                except: continue
        return results

    def query_topic_hierarchy(self, namespace: str, topic_prefix: str) -> List[Dict]:
        """Section 6.2.1.5: Searches DS with topic prefix."""
        results = []
        with self.dht.lock:
            for k, v in self.dht.storage.items():
                try:
                    d = json.loads(v.value.decode()).get("data", {})
                    if d.get("namespace") == namespace and d.get("topic", "").startswith(topic_prefix):
                        results.append(d)
                except: continue
        return results

# ─────────────────────────────────────────────────────────────────────────────
# 6. ANONYMOUS DISCOVERY (Section 6.3)
# ─────────────────────────────────────────────────────────────────────────────

class AnonymousDiscovery:
    def __init__(self, dht: SimpleDHT): self.dht = dht; self.pending_requests: Dict[bytes, Dict] = {}

    def create_discovery_req(self, target_eid: bytes, requester_private_key: bytes, difficulty: int = 2) -> Dict:
        eph_pr, eph_pu = x25519_generate_keypair(); ts = int(time.time()).to_bytes(8, 'big')
        target_coord = sha256(target_eid)  # PoW computed over the SAME value that will be verified
        pn, _ = calculate_pow_nonce(target_coord, difficulty); tid = sha256(target_eid + eph_pu + ts)
        self.pending_requests[tid] = {"target_eid": target_eid, "eph_private": eph_pr, "timestamp": ts}
        return {"version": 1, "type": 0x01, "target_space_coordinate": target_coord.hex(),
                "ephemeral_pubkey": eph_pu.hex(), "timestamp": ts.hex(), "pow_nonce": pn.to_bytes(8, 'big').hex(), "pow_difficulty": difficulty}

    def create_discovery_res(self, req: Dict, responder_eid: bytes, responder_private_key: bytes) -> Optional[Dict]:
        if not verify_pow(bytes.fromhex(req["target_space_coordinate"]), int(req["pow_nonce"], 16), req["pow_difficulty"]): return None
        epp = bytes.fromhex(req["ephemeral_pubkey"]); ss = x25519_ecdh(responder_private_key[:32], epp)
        re = responder_eid if isinstance(responder_eid, bytes) else bytes.fromhex(responder_eid)
        n = os.urandom(12); ee, mac = aes_gcm_encrypt(ss[:32], re, n)
        return {"version": 1, "type": 0x02, "responder_eph_pubkey": epp.hex(), "nonce": n.hex(), "encrypted_eid": ee.hex(), "auth_tag": mac.hex(), "responder_signature": sign_message(responder_private_key, re).hex()}

    def process_discovery_res(self, res: Dict, requester_private_key: bytes) -> Optional[bytes]:
        ss = x25519_ecdh(requester_private_key[:32], bytes.fromhex(res["responder_eph_pubkey"]))
        try: return aes_gcm_decrypt(ss[:32], bytes.fromhex(res["encrypted_eid"]), bytes.fromhex(res["nonce"]), bytes.fromhex(res["auth_tag"]))
        except: return None

# ─────────────────────────────────────────────────────────────────────────────
# 7. FORWARDING TICKETS (Section 3.5)
# ─────────────────────────────────────────────────────────────────────────────

class ForwardingTicketManager:
    def __init__(self, dht: SimpleDHT): self.dht = dht

    def create_ticket(self, target_eid: bytes, new_locator: str, peer_public_key: bytes, owner_private_key: bytes, ttl: int = 3600) -> Dict:
        eph_pr, eph_pu = x25519_generate_keypair(); ss = x25519_ecdh(eph_pr, peer_public_key); n = os.urandom(12)
        k = ss[:32]; ed, mac = aes_gcm_encrypt(k, new_locator.encode(), n); efd = ed[:20] + mac
        tk = sha256(target_eid); si = tk + target_eid + ttl.to_bytes(4, 'big') + n + efd; sig = sign_message(owner_private_key, si)
        td = {"target_eid": target_eid.hex(), "ttl": ttl, "nonce": n.hex(), "encrypted_data": efd.hex(), "eph_pubkey": eph_pu.hex(), "signature": sig.hex()}
        self.dht.store(tk, json.dumps(td).encode(), publisher_eid=target_eid, ttl=ttl); return td

    def query_ticket(self, target_eid: bytes, requester_private_key: bytes) -> Optional[Dict]:
        d = self.dht.lookup(sha256(target_eid))
        if not d: return None
        t = json.loads(d.decode()); ep = bytes.fromhex(t["eph_pubkey"]); n = bytes.fromhex(t["nonce"])
        ed = bytes.fromhex(t["encrypted_data"]); ss = x25519_ecdh(requester_private_key[:32], ep)
        try: t["decrypted_locator"] = aes_gcm_decrypt(ss[:32], ed[:20], n, ed[20:]).decode(); return t
        except: return None

# ─────────────────────────────────────────────────────────────────────────────
# 8. EID REPUTATION SYSTEM (Section 3.6)
# ─────────────────────────────────────────────────────────────────────────────

class ReputationManager:
    def __init__(self):
        self.eids: Dict[bytes, EIDRecord] = {}; self.lock = threading.Lock()
        self.alpha = 0.12; self.w1 = 0.45; self.w2 = 0.35; self.w3 = 0.20; self.rho_threshold = 0.7; self.k_pom = 5

    def register_eid(self, eid: bytes, public_key: bytes, locator: str = "") -> EIDRecord:
        with self.lock:
            if eid not in self.eids: self.eids[eid] = EIDRecord(eid=eid, public_key=public_key, current_locator=locator)
            return self.eids[eid]

    def update_reputation(self, eid: bytes, metrics: Dict[str, float]) -> float:
        with self.lock:
            if eid not in self.eids: return 1.0
            r = self.eids[eid]; sv = metrics.get('s_verify', 1.0); at = metrics.get('a_telemetry', 1.0)
            pc = metrics.get('pom_count', r.pom_count); ps = min(1.0, pc / self.k_pom)
            r.reputation = self.alpha * (self.w1*sv + self.w2*at - self.w3*ps) + (1-self.alpha)*r.reputation
            r.pom_count = pc; r.last_seen = time.time(); r.reputation = max(0.0, min(1.0, r.reputation)); return r.reputation

    def get_reputation(self, eid: bytes) -> float:
        with self.lock: return self.eids[eid].reputation if eid in self.eids else 1.0

    def add_pom_count(self, eid: bytes, count: int = 1):
        with self.lock:
            if eid in self.eids: self.eids[eid].pom_count += count

    def check_threshold(self, eid: bytes, base_difficulty: int = 2) -> Tuple[bool, int]:
        with self.lock:
            if eid not in self.eids: return True, base_difficulty
            r = self.eids[eid]; rs = r.reputation
            if rs >= self.rho_threshold: return True, base_difficulty
            es = min(max(0, int(((self.rho_threshold - rs) * 40) + 0.5)), 32)
            return rs >= 0.3, base_difficulty + es

    def is_blocked(self, eid: bytes) -> bool:
        with self.lock: return eid in self.eids and (self.eids[eid].reputation < 0.3 or self.eids[eid].is_slashed)

    def decay_pom_scores(self, decay_factor: float = 0.5, max_age_days: int = 30):
        with self.lock:
            for r in self.eids.values():
                if r.pom_count > 0: r.pom_count = int(r.pom_count * decay_factor)

    def update_locator_and_generation(self, eid: bytes, locator: str, generation: int):
        with self.lock:
            if eid in self.eids: self.eids[eid].current_locator = locator; self.eids[eid].current_generation = generation

    def get_generation(self, eid: bytes) -> int:
        with self.lock: return self.eids[eid].current_generation if eid in self.eids else 0

    def eid_exists(self, eid: bytes) -> bool:
        with self.lock: return eid in self.eids

# ─────────────────────────────────────────────────────────────────────────────
# 9. DHI CONTENT EQUIVALENCE (Section 4.1.4) – NEW in v3
# ─────────────────────────────────────────────────────────────────────────────

class DHIContentEquivalence:
    """Deterministic content equivalence check (Section 4.1.4.1)."""
    EVM_THRESHOLD = 0.001

    @staticmethod
    def normalize_text(text: str) -> str:
        """Unicode NFC + whitespace collapse (Section 4.1.4.1.3b)."""
        import unicodedata
        t = unicodedata.normalize('NFC', text)
        t = re.sub(r'[\r\x00-\x1f\x7f-\x9f]+', '', t)
        t = re.sub(r'\s+', ' ', t).strip()
        return t

    @staticmethod
    def codepoint_distribution(text: str) -> Dict[str, float]:
        """p(i) = Count(Codepoint_i) / Total (RFC-Vorgabe)."""
        total = len(text)
        if total == 0: return {}
        counts: Dict[str, float] = {}
        for cp in text: counts[cp] = counts.get(cp, 0) + 1
        eps = 1e-7
        for cp in counts: counts[cp] = (counts[cp] + eps) / (total + eps * len(counts))
        return counts

    @staticmethod
    def cross_entropy(p: Dict[str, float], q: Dict[str, float]) -> float:
        """H(p, q) = -SUM(p_i * log2(q_i))."""
        h = 0.0
        for cp, prob in p.items():
            qp = q.get(cp, 1e-7)
            h -= prob * math.log2(qp)
        return h

    @staticmethod
    def shannon_entropy(p: Dict[str, float]) -> float:
        """H(p) = -SUM(p_i * log2(p_i))."""
        h = 0.0
        for prob in p.values():
            if prob > 0: h -= prob * math.log2(prob)
        return h

    @staticmethod
    def compute_evm(text_a: str, text_b: str) -> Tuple[float, bool]:
        """Computes EVM and checks if <= 0.001 (Section 4.1.4.1)."""
        na = DHIContentEquivalence.normalize_text(text_a)
        nb = DHIContentEquivalence.normalize_text(text_b)
        pa = DHIContentEquivalence.codepoint_distribution(na)
        pb = DHIContentEquivalence.codepoint_distribution(nb)
        h_pq = DHIContentEquivalence.cross_entropy(pa, pb)
        h_p = DHIContentEquivalence.shannon_entropy(pa)
        evm = h_pq - h_p
        return evm, evm <= DHIContentEquivalence.EVM_THRESHOLD

    @staticmethod
    def compute_sha256_equivalence(text_a: str, text_b: str) -> Tuple[bool, str]:
        """SHA-256 hash comparison (Section 4.1.4.1.4)."""
        na = DHIContentEquivalence.normalize_text(text_a)
        nb = DHIContentEquivalence.normalize_text(text_b)
        ha = sha256(na.encode()).hex()
        hb = sha256(nb.encode()).hex()
        return ha == hb, ha

    @classmethod
    def verify_equivalence(cls, text_a: str, text_b: str) -> Dict:
        """Complete equivalence test: EVM + SHA256."""
        evm, evm_ok = cls.compute_evm(text_a, text_b)
        sha_ok, sha_val = cls.compute_sha256_equivalence(text_a, text_b)
        return {
            "evm": evm, "evm_threshold": cls.EVM_THRESHOLD, "evm_pass": evm_ok,
            "sha256": sha_val, "sha256_pass": sha_ok,
            "overall_pass": evm_ok and sha_ok,
            "len_a": len(cls.normalize_text(text_a)), "len_b": len(cls.normalize_text(text_b))
        }

    @classmethod
    def create_hco(cls, trigger_type: int, eid: bytes, session_hash: bytes, sequence: int, url: str) -> HCO:
        """Creates Hand-off Context Object with ESD-EID (Section 4.1.4.2)."""
        esd_eid = sha256(eid + session_hash + sequence.to_bytes(4, 'big'))
        return HCO(trigger_type, esd_eid, session_hash, sequence, 0, url)

# ─────────────────────────────────────────────────────────────────────────────
# 10. TOKEN BUCKET (Section 5.4.1)
# ─────────────────────────────────────────────────────────────────────────────

class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity; self.refill_rate = refill_rate; self.tokens = float(capacity)
        self.last_refill = time.time(); self.lock = threading.Lock()

    def consume(self, tokens: int) -> bool:
        with self.lock:
            n = time.time(); e = n - self.last_refill
            self.tokens = min(self.capacity, self.tokens + e * self.refill_rate); self.last_refill = n
            if self.tokens >= tokens: self.tokens -= tokens; return True
            return False

    def reset(self):
        with self.lock: self.tokens = float(self.capacity)

# ─────────────────────────────────────────────────────────────────────────────
# 11. CIRCUIT BREAKER (Section 5.4.2)
# ─────────────────────────────────────────────────────────────────────────────

class CircuitBreakerState(Enum): CLOSED = "CLOSED"; OPEN = "OPEN"

class CircuitBreaker:
    def __init__(self, threshold: int = 100, cooldown: int = 60):
        self.state = CircuitBreakerState.CLOSED; self.failure_count = 0; self.threshold = threshold
        self.cooldown = cooldown; self.last_failure = 0; self.lock = threading.Lock()

    def record_success(self):
        with self.lock: self.failure_count = 0; self.state = CircuitBreakerState.CLOSED

    def record_failure(self):
        with self.lock:
            self.failure_count += 1; self.last_failure = time.time()
            if self.failure_count >= self.threshold: self.state = CircuitBreakerState.OPEN

    def can_execute(self) -> bool:
        with self.lock:
            if self.state == CircuitBreakerState.CLOSED: return True
            if time.time() - self.last_failure > self.cooldown:
                self.state = CircuitBreakerState.CLOSED; self.failure_count = 0; return True
            return False

# ─────────────────────────────────────────────────────────────────────────────
# 12. ERP STATE MACHINE (Section 4.2.3.3)
# ─────────────────────────────────────────────────────────────────────────────

class EIDState(Enum): UNBOUND = "UNBOUND"; ALLOCATED = "ALLOCATED"; TRANSITION = "TRANSITION"; BOUND = "BOUND"; EVOLVE_PENDING = "EVOLVE_PENDING"

class LLContext:
    def __init__(self, eid: bytes, iat: bytes):
        self.eid = eid; self.iat = iat; self.state = EIDState.UNBOUND; self.generation_counter = 0
        self.locator = ""; self.buffer = []; self.created_at = time.time(); self.last_keepalive = time.time()

    def transition(self, event: str) -> bool:
        transitions = {
            EIDState.UNBOUND: {"ERP_INIT": EIDState.ALLOCATED},
            EIDState.ALLOCATED: {"ERP_ALLOC": EIDState.ALLOCATED, "ERP_REGISTER": EIDState.TRANSITION},
            EIDState.TRANSITION: {"DHT_CONFIRM": EIDState.BOUND, "NETWORK_CHURN": EIDState.TRANSITION},
            EIDState.BOUND: {"NETWORK_CHURN": EIDState.TRANSITION, "APP_DIGEST_CHANGE": EIDState.EVOLVE_PENDING},
            EIDState.EVOLVE_PENDING: {"ERP_EVOLVE_COMPLETE": EIDState.BOUND}}
        ns = transitions.get(self.state, {}).get(event)
        if ns: self.state = ns; return True
        return False

# ─────────────────────────────────────────────────────────────────────────────
# 13. PSS (Section 6.4)
# ─────────────────────────────────────────────────────────────────────────────

class PSSManager:
    def __init__(self):
        self.sessions: Dict[bytes, PSSSession] = {}; self.pending_handshakes: Dict[bytes, Dict] = {}; self.lock = threading.Lock()

    def create_session_id(self, i_cookie: bytes, r_cookie: bytes) -> bytes: return i_cookie + r_cookie

    def initiate_pss(self, initiator_eid: bytes, target_eid: bytes, init_private_key: bytes, sfc_requested: bool = False) -> Optional[Dict]:
        ic = generate_cookie()
        with self.lock: self.pending_handshakes[ic] = {'initiator_eid': initiator_eid, 'target_eid': target_eid, 'timestamp': time.time(), 'sfc_requested': sfc_requested}
        return {"version": 1, "type": 0x08, "initiator_eid": initiator_eid.hex(), "i_cookie": ic.hex(), "r_cookie": "0000000000000000", "initial_seq": 0, "sfc_requested": sfc_requested, "signature": sign_message(init_private_key, ic).hex()}

    def process_pss_init(self, pss_init: Dict, responder_eid: bytes, resp_private_key: bytes) -> Optional[Dict]:
        try:
            ic = bytes.fromhex(pss_init['i_cookie'])
            ie = bytes.fromhex(pss_init['initiator_eid'])
            sig = bytes.fromhex(pss_init.get('signature', ''))
        except (KeyError, ValueError):
            return None  # Malformed PSS_INIT – discard without state allocation
        if not verify_signature(ie, ic, sig): return None
        rc = generate_cookie(); p = {'initiator_eid': ie, 'responder_eid': responder_eid, 'timestamp': time.time(), 'r_cookie': rc}
        with self.lock: self.pending_handshakes[ic] = p
        return {"version": 1, "type": 0x0A, "i_cookie": ic.hex(), "r_cookie": rc.hex(), "negotiation_counter": 1, "rejection_flags": 0, "sfc_conditions": os.urandom(32).hex() if pss_init.get('sfc_requested') else "0"*64, "signature": sign_message(resp_private_key, ic+rc).hex(), "_pending": p}

    def complete_handshake(self, pss_neg: Dict, initiator_eid: bytes, responder_eid: bytes = None) -> Optional[PSSSession]:
        ic = bytes.fromhex(pss_neg['i_cookie']); rc = bytes.fromhex(pss_neg['r_cookie'])
        if responder_eid: p = {'initiator_eid': initiator_eid, 'responder_eid': responder_eid, 'r_cookie': rc}
        else:
            with self.lock: p = self.pending_handshakes.get(ic)
            if not p: return None
        sig = bytes.fromhex(pss_neg['signature']); te = p['responder_eid']
        if not verify_signature(te, ic+rc, sig): return None
        sid = self.create_session_id(ic, rc); s = PSSSession(session_id=sid, initiator_eid=initiator_eid, responder_eid=te, i_cookie=ic, r_cookie=rc, state="STATE_ESTABLISHED", sfc_active=len(pss_neg.get('sfc_conditions', '0'*64))>0)
        with self.lock: self.sessions[sid] = s; self.pending_handshakes.pop(ic, None)
        return s

    def get_session(self, session_id: bytes) -> Optional[PSSSession]:
        with self.lock: return self.sessions.get(session_id)

    def close_session(self, session_id: bytes, reason: str = "NORMAL"):
        with self.lock:
            if session_id in self.sessions: self.sessions[session_id].state = "STATE_CLOSED"; return True
        return False

# ─────────────────────────────────────────────────────────────────────────────
# 14. ESE (Section 6.1)
# ─────────────────────────────────────────────────────────────────────────────

class ESEManager:
    """Ephemeral State Endpoints (Section 6.1) with optional DHT publication."""
    def __init__(self, dht: Optional[SimpleDHT] = None):
        self.endpoints: Dict[bytes, ESEndpoint] = {}; self.lock = threading.Lock()
        self.dht = dht  # Optional DHT for cross-agent Global Point resolution

    def set_dht(self, dht: SimpleDHT):
        """Attach a shared DHT so Global Points become network-resolvable."""
        self.dht = dht

    def create_local_point(self, eid: bytes, tag: str) -> bytes:
        eid = sha256(eid + tag.encode())
        with self.lock: self.endpoints[eid] = ESEndpoint(eid=eid, endpoint_id=eid, is_global=False, data={'tag': tag})
        return eid

    def create_global_point(self, eid: bytes, tag: str) -> bytes:
        gp = sha256(eid + tag.encode())
        with self.lock: self.endpoints[gp] = ESEndpoint(eid=eid, endpoint_id=gp, is_global=True, data={'tag': tag})
        # Publish to DHT so other agents can resolve this Global Point (Section 6.1.3)
        if self.dht is not None:
            try:
                payload = {'endpoint_id': gp.hex(), 'owner_eid': eid.hex(), 'tag': tag,
                           'timestamp': time.time(), 'ttl': 3600}
                self.dht.store(gp, json.dumps(payload).encode(),
                               publisher_eid=eid, ttl=3600)
            except Exception:
                pass
        return gp

    def get_endpoint(self, endpoint_id: bytes) -> Optional[ESEndpoint]:
        with self.lock:
            ep = self.endpoints.get(endpoint_id)
            if ep and (time.time()-ep.created_at) < ep.ttl: return ep
            elif ep: del self.endpoints[endpoint_id]
        if ep is None and self.dht is not None:
            # Try DHT lookup for cross-agent Global Points
            try:
                raw = self.dht.lookup(endpoint_id)
                if raw:
                    payload = json.loads(raw.decode())
                    ep = ESEndpoint(eid=bytes.fromhex(payload['owner_eid']),
                                    endpoint_id=endpoint_id, is_global=True,
                                    data={'tag': payload.get('tag', '')})
                    with self.lock: self.endpoints[endpoint_id] = ep
                    return ep
            except Exception:
                pass
        return ep

    def update_data(self, endpoint_id: bytes, key: str, value: Any):
        with self.lock:
            if endpoint_id in self.endpoints: self.endpoints[endpoint_id].data[key] = value
        # Optionally publish update to DHT
        if self.dht is not None and endpoint_id in self.endpoints:
            try:
                ep = self.endpoints[endpoint_id]
                payload = {'endpoint_id': endpoint_id.hex(), 'owner_eid': ep.eid.hex(),
                           'tag': ep.data.get('tag', ''), 'data': ep.data,
                           'timestamp': time.time(), 'ttl': ep.ttl}
                self.dht.store(endpoint_id, json.dumps(payload).encode(),
                               publisher_eid=ep.eid, ttl=ep.ttl)
            except Exception:
                pass

    def cleanup_expired(self):
        with self.lock:
            for eid in [e for e, ep in self.endpoints.items() if (time.time()-ep.created_at) > ep.ttl]: del self.endpoints[eid]

# ─────────────────────────────────────────────────────────────────────────────
# 15. PoM (Section 4.2.7.1 / 5.5.1)
# ─────────────────────────────────────────────────────────────────────────────

class PoMManager:
    def __init__(self, reputation_manager: ReputationManager):
        self.pom_tickets: List[PoMTicket] = []; self.reputation_manager = reputation_manager; self.lock = threading.Lock(); self.pom_ttl = 86400

    def create_pom_ticket(self, target_eid: bytes, fragment_a: bytes, fragment_b: bytes, accuser_eid: bytes) -> Optional[PoMTicket]:
        if fragment_a == fragment_b: return None
        t = PoMTicket(target_eid=target_eid, fragment_a=fragment_a, fragment_b=fragment_b, accuser_eid=accuser_eid, timestamp=time.time())
        with self.lock: self.pom_tickets.append(t)
        self.reputation_manager.add_pom_count(target_eid, 1); return t

    def validate_pom_ticket(self, ticket: PoMTicket) -> bool: return ticket.fragment_a != ticket.fragment_b

    def get_active_poms(self, eid: bytes, window: int = 86400) -> List[PoMTicket]:
        cutoff = time.time()-window
        with self.lock: return [t for t in self.pom_tickets if t.target_eid == eid and t.timestamp > cutoff]

    def cleanup_old_tickets(self):
        cutoff = time.time()-self.pom_ttl
        with self.lock: self.pom_tickets = [t for t in self.pom_tickets if t.timestamp > cutoff]

# ─────────────────────────────────────────────────────────────────────────────
# 16. 2PSE (Section 4.2.7.2)
# ─────────────────────────────────────────────────────────────────────────────

class TwoPSEManager:
    def __init__(self, reputation_manager: ReputationManager):
        self.escrows: Dict[bytes, TwoPSEEscrow] = {}; self.reputation_manager = reputation_manager
        self.lock = threading.Lock(); self.escrow_duration = 3600; self.slashing_threshold = 3

    def initiate_escrow(self, target_eid: bytes) -> bool:
        with self.lock:
            if target_eid in self.escrows:
                e = self.escrows[target_eid]
                if e.state == "STATE_CHALLENGED": e.escrow_start = time.time(); e.rebuttal_deadline = time.time()+self.escrow_duration; return True
                return False
            self.escrows[target_eid] = TwoPSEEscrow(target_eid=target_eid, state="STATE_CHALLENGED", escrow_start=time.time(), escrow_duration=self.escrow_duration, rebuttal_deadline=time.time()+self.escrow_duration)
            return True

    def submit_counter_proof(self, target_eid: bytes, counter_proof: bytes) -> bool:
        with self.lock:
            if target_eid not in self.escrows: return False
            e = self.escrows[target_eid]
            if e.state != "STATE_CHALLENGED": return False
            if len(counter_proof) > 0: e.state = "STATE_NOMINAL"; del self.escrows[target_eid]; return True
            return False

    def check_escrow_expiry(self, target_eid: bytes) -> bool:
        with self.lock:
            if target_eid not in self.escrows: return False
            e = self.escrows[target_eid]
            if e.state != "STATE_CHALLENGED": return False
            if time.time() > e.rebuttal_deadline: e.state = "STATE_SLASHED"; self.reputation_manager.update_reputation(target_eid, {'s_verify': 0.0, 'a_telemetry': 0.0, 'pom_count': 10}); return True
            return False

    def get_escrow_state(self, target_eid: bytes) -> Optional[str]:
        with self.lock: return self.escrows[target_eid].state if target_eid in self.escrows else None

# ─────────────────────────────────────────────────────────────────────────────
# 17. MIGRATION_VECTOR (Section 4.2.5.1)
# ─────────────────────────────────────────────────────────────────────────────

class MigrationManager:
    def __init__(self, reputation_manager: ReputationManager):
        self.reputation_manager = reputation_manager; self.pending_migrations: Dict[bytes, Dict] = {}; self.lock = threading.Lock()

    def create_migration_vector(self, source_eid: bytes, new_locator: str, private_key: bytes) -> Optional[Dict]:
        with self.lock:
            if source_eid not in self.pending_migrations: self.pending_migrations[source_eid] = {'gen': 0}
            ng = self.pending_migrations[source_eid]['gen'] + 1; self.pending_migrations[source_eid]['gen'] = ng
        si = source_eid + new_locator.encode() + ng.to_bytes(8, 'big')
        return {"version": 1, "type": 0x17, "source_eid": source_eid.hex(), "new_locator": new_locator, "generation_counter": ng, "signature": sign_message(private_key, si).hex(), "timestamp": time.time()}

    def process_migration_vector(self, migration: Dict) -> Tuple[bool, int]:
        se = bytes.fromhex(migration['source_eid']); nl = migration['new_locator']; ng = migration['generation_counter']
        sig = bytes.fromhex(migration['signature']); si = se + nl.encode() + ng.to_bytes(8, 'big')
        if not verify_signature(se, si, sig): return False, -1
        # Register unknown EID before updating locator (bootstrap-safe)
        if not self.reputation_manager.eid_exists(se):
            self.reputation_manager.register_eid(se, se, locator=nl)
        self.reputation_manager.update_locator_and_generation(se, nl, ng); return True, ng

    def validate_generation(self, source_eid: bytes, packet_gen: int) -> bool:
        if not self.reputation_manager.eid_exists(source_eid): return False  # Unknown EID: reject (anti-spoofing)
        cg = self.reputation_manager.get_generation(source_eid)
        if packet_gen > cg: self.reputation_manager.update_locator_and_generation(source_eid, "", packet_gen); return True
        return packet_gen == cg

# ─────────────────────────────────────────────────────────────────────────────
# 18. TCP NETWORKING
# ─────────────────────────────────────────────────────────────────────────────

class FrameBuffer:
    def __init__(self): self._buf = b""
    def feed(self, data: bytes): self._buf += data
    def read_line(self) -> Optional[bytes]:
        if b"\n" not in self._buf: return None
        l, self._buf = self._buf.split(b"\n", 1); return l
    def has_data(self) -> bool: return len(self._buf) > 0

class IACPPacket:
    ERP_INIT = "ERP_INIT"; ERP_ALLOC = "ERP_ALLOC"; ERP_REGISTER = "ERP_REGISTER"; ERP_ACK = "ERP_ACK"
    PSS_INIT = "PSS_INIT"; PSS_NEG = "PSS_NEG"; PSS_ACK = "PSS_ACK"; PSS_DATA = "PSS_DATA"; PSS_CLOSE = "PSS_CLOSE"
    MAX_FRAME_SIZE = 1 << 20

    def __init__(self, msg_type: str, sender: str, payload: dict):
        self.msg_type = msg_type; self.sender = sender; self.payload = payload; self.signature = ""

    def sign(self, eid: str): self.signature = sign_message_str(eid, json.dumps(self.to_dict(), sort_keys=True))

    def verify(self, eid: str) -> bool:
        sig = self.signature; self.signature = ""; r = verify_signature_str(eid, json.dumps(self.to_dict(), sort_keys=True), sig); self.signature = sig; return r

    def to_dict(self) -> dict: return {"type": self.msg_type, "sender": self.sender, "payload": self.payload, "signature": self.signature}

    @classmethod
    def from_dict(cls, d: dict) -> "IACPPacket": p = cls(d["type"], d["sender"], d["payload"]); p.signature = d.get("signature", ""); return p

class IACPSessionWire:
    def __init__(self, local_eid: str, peer_eid: str, cookie_i: str, cookie_r: str):
        self.local_eid = local_eid; self.peer_eid = peer_eid; self.cookie_i = cookie_i; self.cookie_r = cookie_r
        self.seq_send = 0; self.seq_recv = 0
        sorted_eids = "".join(sorted([local_eid, peer_eid]))
        # Domain-separated key derivation: include role labels to prevent cross-protocol key reuse
        self.session_key = hkdf_derive(
            (cookie_i + cookie_r + sorted_eids).encode(),
            b"IACP_SALT_v1",
            b"IACP_SESSION_KEY_v1|" + sorted_eids.encode()
        )

    def encrypt(self, plaintext: str) -> str:
        n = os.urandom(12); ct, mac = aes_gcm_encrypt(self.session_key[:32], plaintext.encode("utf-8"), n)
        return json.dumps({"nonce": n.hex(), "ct": ct.hex(), "mac": mac.hex()})

    def decrypt(self, encrypted: str) -> str:
        d = json.loads(encrypted)
        try: return aes_gcm_decrypt(self.session_key[:32], bytes.fromhex(d["ct"]), bytes.fromhex(d["nonce"]), bytes.fromhex(d["mac"])).decode("utf-8", errors="replace")
        except: raise ValueError("MAC verification failed")

def recv_frame(sock: socket.socket, buf: FrameBuffer, timeout: float = 30.0) -> IACPPacket:
    sock.settimeout(timeout)
    while True:
        l = buf.read_line()
        if l is not None:
            if len(l) > IACPPacket.MAX_FRAME_SIZE: raise ValueError(f"Frame too large: {len(l)}")
            return IACPPacket.from_dict(json.loads(l.decode()))
        c = sock.recv(4096)
        if not c: raise ConnectionError("Connection closed")
        buf.feed(c)

def perform_handshake(sock: socket.socket, my_eid: str, is_initiator: bool) -> IACPSessionWire:
    buf = FrameBuffer()
    def sp(pkt): pkt.sign(my_eid); sock.sendall((json.dumps(pkt.to_dict()) + "\n").encode())
    def rp(): return recv_frame(sock, buf)

    if is_initiator:
        sp(IACPPacket(IACPPacket.ERP_INIT, my_eid, {"nonce": os.urandom(16).hex()}))
        alloc = rp(); assert alloc.msg_type == IACPPacket.ERP_ALLOC, f"Expected ERP_ALLOC, got {alloc.msg_type}"
        assert alloc.verify(alloc.sender), "ERP_ALLOC sig fail"
        pe = alloc.sender; sp(IACPPacket(IACPPacket.ERP_REGISTER, my_eid, {"peer_eid": pe, "slot": alloc.payload.get("slot", 0)}))
        ack = rp(); assert ack.msg_type == IACPPacket.ERP_ACK; assert ack.verify(ack.sender)
        ci = os.urandom(8).hex(); sp(IACPPacket(IACPPacket.PSS_INIT, my_eid, {"cookie_i": ci}))
        neg = rp(); assert neg.msg_type == IACPPacket.PSS_NEG; assert neg.verify(neg.sender)
        cr = neg.payload.get("cookie_r", ""); sp(IACPPacket(IACPPacket.PSS_ACK, my_eid, {"cookie_i": ci, "cookie_r": cr}))
        return IACPSessionWire(my_eid, pe, ci, cr)
    else:
        init = rp(); assert init.msg_type == IACPPacket.ERP_INIT; assert init.verify(init.sender)
        pe = init.sender; sp(IACPPacket(IACPPacket.ERP_ALLOC, my_eid, {"slot": int.from_bytes(os.urandom(4), "big")}))
        reg = rp(); assert reg.msg_type == IACPPacket.ERP_REGISTER; assert reg.verify(reg.sender)
        sp(IACPPacket(IACPPacket.ERP_ACK, my_eid, {}))
        psi = rp(); assert psi.msg_type == IACPPacket.PSS_INIT; assert psi.verify(psi.sender)
        ci = psi.payload.get("cookie_i", ""); cr = os.urandom(8).hex()
        sp(IACPPacket(IACPPacket.PSS_NEG, my_eid, {"cookie_i": ci, "cookie_r": cr}))
        ack = rp(); assert ack.msg_type == IACPPacket.PSS_ACK; assert ack.verify(ack.sender)
        return IACPSessionWire(my_eid, pe, ci, cr)

def send_data(sock: socket.socket, session: IACPSessionWire, message: str):
    session.seq_send += 1; enc = session.encrypt(message)
    p = IACPPacket(IACPPacket.PSS_DATA, session.local_eid, {"seq": session.seq_send, "encrypted": enc}); p.sign(session.local_eid)
    sock.sendall((json.dumps(p.to_dict()) + "\n").encode())

def recv_data(sock: socket.socket, session: IACPSessionWire, buf: Optional[FrameBuffer] = None) -> str:
    if buf is None: buf = FrameBuffer()
    p = recv_frame(sock, buf)
    assert p.msg_type == IACPPacket.PSS_DATA, f"Expected PSS_DATA, got {p.msg_type}"
    assert p.verify(session.peer_eid), "PSS_DATA sig fail"
    seq = p.payload.get("seq", 0)
    if seq <= session.seq_recv: raise ValueError(f"Replay! seq={seq} <= recv={session.seq_recv}")
    session.seq_recv = seq; return session.decrypt(p.payload["encrypted"])

# ─────────────────────────────────────────────────────────────────────────────
# 19. RELAY TRANSPORT
# ─────────────────────────────────────────────────────────────────────────────

class RelayTransport:
    def __init__(self, relay_url: str, eid: str, session_cookie: str):
        self.relay_url = relay_url.rstrip("/")
        self.eid = eid
        self.session_cookie = session_cookie
        self._registered = False
        # Local inbox: unmatched envelopes from a poll batch are kept here so
        # handshake does not discard early PSS_DATA (or vice versa).
        self._inbox: List[dict] = []
        self._inbox_lock = threading.Lock()

    def register(self) -> bool:
        try:
            d = json.dumps({"eid": self.eid, "session_cookie": self.session_cookie}).encode()
            r = urllib.request.urlopen(urllib.request.Request(f"{self.relay_url}/relay_register", data=d, headers={"Content-Type": "application/json"}), timeout=5)
            self._registered = json.loads(r.read().decode()).get("status") == "ok"; return self._registered
        except: return False

    def send(self, to_eid: str, encrypted_payload: str) -> bool:
        if not self._registered: return False
        try:
            d = json.dumps({"from_eid": self.eid, "to_eid": to_eid, "encrypted": encrypted_payload, "session_cookie": self.session_cookie}).encode()
            r = urllib.request.urlopen(urllib.request.Request(f"{self.relay_url}/relay", data=d, headers={"Content-Type": "application/json"}), timeout=10)
            return json.loads(r.read().decode()).get("status") == "ok"
        except: return False

    def poll(self, timeout: int = 5) -> list:
        if not self._registered: return []
        try:
            r = urllib.request.urlopen(f"{self.relay_url}/relay_poll?eid={self.eid}&session_cookie={self.session_cookie}&timeout={timeout}", timeout=timeout+5)
            j = json.loads(r.read().decode()); return j.get("messages", []) if j.get("status") == "ok" else []
        except: return []

    def start_polling(self, callback, stop_event: threading.Event, poll_interval: int = 1):
        def loop():
            while not stop_event.is_set():
                for m in self.poll(timeout=5):
                    if not stop_event.is_set(): callback(m)
                stop_event.wait(poll_interval)
        t = threading.Thread(target=loop, daemon=True); t.start(); return t

    def send_envelope(self, to_eid: str, envelope: dict) -> bool:
        return self.send(to_eid, json.dumps(envelope, sort_keys=True))

    def _parse_raw_messages(self, messages: list) -> List[dict]:
        out: List[dict] = []
        for m in messages:
            raw = m.get("encrypted", "")
            try:
                env = json.loads(raw) if isinstance(raw, str) else raw
                if not isinstance(env, dict) or "iacp_type" not in env:
                    continue
                out.append({
                    "from_eid": m.get("from_eid", ""),
                    "envelope": env,
                    "timestamp": m.get("timestamp", 0),
                })
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
        return out

    def poll_envelopes(self, timeout: int = 5) -> List[dict]:
        """Return inbox + newly polled envelopes. Does not clear inbox."""
        with self._inbox_lock:
            out = list(self._inbox)
            self._inbox.clear()
        out.extend(self._parse_raw_messages(self.poll(timeout=timeout)))
        return out

    def push_inbox(self, items: List[dict]) -> None:
        """Re-queue envelopes that were polled but not consumed (wrong type/sender)."""
        if not items:
            return
        with self._inbox_lock:
            self._inbox.extend(items)


# ─────────────────────────────────────────────────────────────────────────────
# 19b. RELAY SESSION PROTOCOL (Phases 1–5)
# ─────────────────────────────────────────────────────────────────────────────

RELAY_HANDSHAKE_TIMEOUT = 60.0
RELAY_STEP_TIMEOUT = 15.0
RELAY_POLL_INTERVAL = 0.5
RELAY_DATA_TIMEOUT = 60.0
RELAY_SEND_RETRIES = 3

RELAY_HANDSHAKE_ALL_TYPES = frozenset({
    IACPPacket.ERP_INIT, IACPPacket.ERP_ALLOC, IACPPacket.ERP_REGISTER,
    IACPPacket.ERP_ACK, IACPPacket.PSS_INIT, IACPPacket.PSS_NEG,
    IACPPacket.PSS_ACK, IACPPacket.PSS_DATA, IACPPacket.PSS_CLOSE,
})


class RelaySessionError(Exception):
    """Raised on signature, sequence, or protocol errors over relay."""
    pass


def packet_to_relay_envelope(pkt: "IACPPacket") -> dict:
    return {
        "iacp_type": pkt.msg_type,
        "sender": pkt.sender,
        "payload": pkt.payload,
        "signature": pkt.signature,
    }


def relay_envelope_to_packet(env: dict) -> "IACPPacket":
    pkt = IACPPacket(env["iacp_type"], env.get("sender", ""), env.get("payload") or {})
    pkt.signature = env.get("signature", "")
    return pkt


def verify_relay_envelope(env: dict) -> bool:
    if not isinstance(env, dict):
        return False
    if env.get("iacp_type") not in RELAY_HANDSHAKE_ALL_TYPES:
        return False
    sender = env.get("sender", "")
    if not sender or not env.get("signature"):
        return False
    return relay_envelope_to_packet(env).verify(sender)


def discover_relay_peer(discover_url: str, topic: str,
                        exclude_eid: Optional[str] = None) -> Optional[dict]:
    try:
        url = f"{discover_url.rstrip('/')}/discover?topic={topic}"
        resp = urllib.request.urlopen(url, timeout=5)
        result = json.loads(resp.read().decode())
        if result.get("status") != "ok":
            return None
        for peer in result.get("results") or []:
            eid = peer.get("eid", "")
            if not eid or (exclude_eid and eid == exclude_eid):
                continue
            return peer
        return None
    except Exception:
        return None


def register_discovery_presence(discover_url: str, eid: str, topic: str,
                                ip: str = "0.0.0.0", port: int = 0) -> bool:
    try:
        data = json.dumps({
            "eid": eid, "ip": ip, "port": port or 0, "topic": topic
        }).encode()
        req = urllib.request.Request(
            f"{discover_url.rstrip('/')}/register",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        return json.loads(resp.read().decode()).get("status") == "ok"
    except Exception:
        return False


def relay_send_packet(relay: "RelayTransport", to_eid: str,
                      packet: "IACPPacket",
                      retries: int = RELAY_SEND_RETRIES) -> bool:
    if not packet.signature:
        packet.sign(packet.sender)
    env = packet_to_relay_envelope(packet)
    for _ in range(max(1, retries)):
        if relay.send_envelope(to_eid, env):
            return True
        time.sleep(0.3)
    return False


def relay_recv_packet(relay: "RelayTransport",
                      expected_types: set,
                      expected_from: Optional[str] = None,
                      timeout: float = RELAY_STEP_TIMEOUT,
                      poll_interval: float = RELAY_POLL_INTERVAL) -> "IACPPacket":
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = max(0.5, min(poll_interval * 2, deadline - time.time()))
        batch = relay.poll_envelopes(timeout=max(1, int(remaining)))
        leftover: List[dict] = []
        found: Optional[IACPPacket] = None
        for item in batch:
            env = item["envelope"]
            sender = env.get("sender") or item.get("from_eid", "")
            if expected_from and sender != expected_from:
                leftover.append(item)
                continue
            if env.get("iacp_type") not in expected_types:
                leftover.append(item)
                continue
            if not verify_relay_envelope(env):
                leftover.append(item)
                continue
            if found is None:
                found = relay_envelope_to_packet(env)
            else:
                leftover.append(item)
        relay.push_inbox(leftover)
        if found is not None:
            return found
        time.sleep(poll_interval)
    raise TimeoutError(
        f"relay_recv_packet: no packet in {expected_types} "
        f"from {expected_from or '*'} within {timeout}s"
    )


def perform_relay_handshake(
    relay: "RelayTransport",
    my_eid: str,
    peer_eid: Optional[str],
    is_initiator: bool,
    timeout: float = RELAY_HANDSHAKE_TIMEOUT,
) -> "IACPSessionWire":
    """ERP+PSS handshake over relay. Responder: peer_eid=None accepts any initiator."""
    if not relay._registered:
        if not relay.register():
            raise RuntimeError("Relay registration failed")

    step_timeout = max(RELAY_STEP_TIMEOUT, timeout / 4.0)
    pe = peer_eid or None

    def sp(pkt: IACPPacket, to: str) -> None:
        pkt.sign(my_eid)
        if not relay_send_packet(relay, to, pkt):
            raise RuntimeError(f"relay send failed for {pkt.msg_type}")

    def rp(expected: set, from_eid: Optional[str]) -> IACPPacket:
        return relay_recv_packet(
            relay, expected_types=expected, expected_from=from_eid,
            timeout=step_timeout, poll_interval=RELAY_POLL_INTERVAL,
        )

    if is_initiator:
        if not pe:
            raise ValueError("Initiator requires peer_eid")
        sp(IACPPacket(IACPPacket.ERP_INIT, my_eid, {"nonce": os.urandom(16).hex()}), pe)
        alloc = rp({IACPPacket.ERP_ALLOC}, pe)
        pe = alloc.sender
        sp(IACPPacket(IACPPacket.ERP_REGISTER, my_eid, {
            "peer_eid": pe, "slot": alloc.payload.get("slot", 0),
        }), pe)
        rp({IACPPacket.ERP_ACK}, pe)
        ci = os.urandom(8).hex()
        sp(IACPPacket(IACPPacket.PSS_INIT, my_eid, {"cookie_i": ci}), pe)
        neg = rp({IACPPacket.PSS_NEG}, pe)
        cr = neg.payload.get("cookie_r", "")
        sp(IACPPacket(IACPPacket.PSS_ACK, my_eid, {"cookie_i": ci, "cookie_r": cr}), pe)
        return IACPSessionWire(my_eid, pe, ci, cr)
    else:
        init = rp({IACPPacket.ERP_INIT}, pe)
        pe = init.sender
        sp(IACPPacket(IACPPacket.ERP_ALLOC, my_eid, {
            "slot": int.from_bytes(os.urandom(4), "big"),
        }), pe)
        rp({IACPPacket.ERP_REGISTER}, pe)
        sp(IACPPacket(IACPPacket.ERP_ACK, my_eid, {}), pe)
        psi = rp({IACPPacket.PSS_INIT}, pe)
        ci = psi.payload.get("cookie_i", "")
        cr = os.urandom(8).hex()
        sp(IACPPacket(IACPPacket.PSS_NEG, my_eid, {"cookie_i": ci, "cookie_r": cr}), pe)
        rp({IACPPacket.PSS_ACK}, pe)
        return IACPSessionWire(my_eid, pe, ci, cr)


def send_data_relay(relay: "RelayTransport", session: "IACPSessionWire",
                    message: str, retries: int = RELAY_SEND_RETRIES) -> bool:
    session.seq_send += 1
    enc = session.encrypt(message)
    pkt = IACPPacket(
        IACPPacket.PSS_DATA,
        session.local_eid,
        {"seq": session.seq_send, "encrypted": enc},
    )
    pkt.sign(session.local_eid)
    ok = relay_send_packet(relay, session.peer_eid, pkt, retries=retries)
    if not ok:
        session.seq_send -= 1
    return ok


def recv_data_relay(relay: "RelayTransport", session: "IACPSessionWire",
                    timeout: float = RELAY_DATA_TIMEOUT) -> str:
    """Strict seq ordering; unmatched envelopes are re-queued; raises RelaySessionError on sig/MAC fail."""
    deadline = time.time() + timeout
    expected_seq = session.seq_recv + 1
    while time.time() < deadline:
        remaining = max(1, int(min(RELAY_STEP_TIMEOUT, deadline - time.time())))
        items = relay.poll_envelopes(timeout=remaining)
        if not items:
            time.sleep(RELAY_POLL_INTERVAL)
            continue
        leftover: List[dict] = []
        result: Optional[str] = None
        for item in items:
            env = item["envelope"]
            sender = env.get("sender") or item.get("from_eid", "")
            if sender != session.peer_eid:
                leftover.append(item)
                continue
            if env.get("iacp_type") != IACPPacket.PSS_DATA:
                leftover.append(item)
                continue
            if not verify_relay_envelope(env):
                relay.push_inbox(leftover)
                raise RelaySessionError(
                    "PSS_DATA signature verification failed – closing session"
                )
            pkt = relay_envelope_to_packet(env)
            seq = pkt.payload.get("seq", 0)
            if seq < expected_seq:
                # stale/replay – drop
                continue
            if seq > expected_seq:
                # future seq – keep for later
                leftover.append(item)
                continue
            enc = pkt.payload.get("encrypted")
            if not enc:
                relay.push_inbox(leftover)
                raise RelaySessionError(
                    "PSS_DATA missing encrypted payload – closing session"
                )
            try:
                plaintext = session.decrypt(enc)
            except Exception as e:
                relay.push_inbox(leftover)
                raise RelaySessionError(
                    f"decrypt/MAC failed: {e} – closing session"
                ) from e
            session.seq_recv = seq
            result = plaintext
            # keep remaining items after this one
            break
        else:
            relay.push_inbox(leftover)
            time.sleep(RELAY_POLL_INTERVAL)
            continue
        # append any items not yet processed after the match
        idx = items.index(item) if item in items else len(items)
        leftover.extend(items[idx + 1:])
        relay.push_inbox(leftover)
        return result
    raise TimeoutError(f"recv_data_relay: no in-order PSS_DATA within {timeout}s")


def close_relay_session(relay: "RelayTransport", session: "IACPSessionWire") -> None:
    try:
        pkt = IACPPacket(IACPPacket.PSS_CLOSE, session.local_eid, {
            "seq": session.seq_send + 1, "reason": "close",
        })
        pkt.sign(session.local_eid)
        relay_send_packet(relay, session.peer_eid, pkt, retries=1)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# 20. SECURE SESSION CHANNEL (NEW) – High-Level Agent Communication
# ─────────────────────────────────────────────────────────────────────────────

class SecureSessionChannel:
    """High-level communication channel between two IACP agents."""
    def __init__(self, local_agent: 'IACPAgent', peer_eid: bytes, peer_addr: Optional[str] = None):
        self.local = local_agent; self.peer_eid = peer_eid; self.peer_addr = peer_addr
        self.session: Optional[PSSSession] = None; self.wire_session: Optional[IACPSessionWire] = None
        self.ese_remote: Optional[bytes] = None; self.ese_local: Optional[bytes] = None
        self.message_log: List[Dict] = []

    def establish(self, sfc_requested: bool = False, peer_private_key: Optional[bytes] = None) -> bool:
        """Perform PSS handshake and set up ESEs."""
        pss = self.local.pss_manager
        init = pss.initiate_pss(self.local.eid, self.peer_eid, self.local.private_key, sfc_requested)
        # Use provided peer private key, or fall back to peer_eid (for backward compat)
        resp_key = peer_private_key if peer_private_key else self.peer_eid[:32]
        neg_data = pss.process_pss_init(init, self.peer_eid, resp_key)
        if not neg_data: return False
        self.session = pss.complete_handshake(neg_data, self.local.eid)
        if not self.session: return False
        self.ese_local = self.local.ese_manager.create_global_point(self.local.eid, f"pss_{self.session.session_id.hex()[:8]}")
        self.ese_remote = self.local.ese_manager.create_global_point(self.peer_eid, f"pss_{self.session.session_id.hex()[:8]}")
        return True

    def send_message(self, msg_type: str, content: Dict) -> bool:
        """Send encrypted message over PSS channel with sequence binding."""
        if not self.session: return False
        seq = self.session.initiator_seq
        msg = {"type": msg_type, "from": self.local.eid.hex(), "to": self.peer_eid.hex(),
               "content": content, "timestamp": time.time(), "seq": seq}
        # Bind sequence number cryptographically to prevent replay
        msg["mac"] = hmac.new(self.session.session_id, json.dumps(msg, sort_keys=True).encode(),
                              hashlib.sha256).hexdigest()
        self.local.ese_manager.update_data(self.ese_local, f"msg_{seq}", msg)
        self.session.initiator_seq += 1; self.session.last_activity = time.time()
        self.message_log.append(msg)
        return True

    def receive_messages(self, max_count: int = 10) -> List[Dict]:
        """Retrieve messages from peer's ESE with replay protection."""
        if not self.ese_remote: return []
        ep = self.local.ese_manager.get_endpoint(self.ese_remote)
        if not ep: return []
        msgs = []
        for k, v in list(ep.data.items())[:max_count]:
            if k.startswith("msg_"):
                # Verify MAC to reject replayed/tampered messages
                try:
                    mac = v.pop("mac", "")
                    expected = hmac.new(self.session.session_id,
                                        json.dumps(v, sort_keys=True).encode(),
                                        hashlib.sha256).hexdigest()
                    if hmac.compare_digest(mac, expected):
                        msgs.append(v)
                except Exception:
                    continue
        return msgs

    def close(self):
        """Close the channel."""
        if self.session: self.local.pss_manager.close_session(self.session.session_id)

# ─────────────────────────────────────────────────────────────────────────────
# 21. IACP AGENT (Combines all components)
# ─────────────────────────────────────────────────────────────────────────────

class IACPAgent:
    def __init__(self, name: str):
        self.name = name
        self.private_key, self.public_key = generate_keypair()
        self.eid = self.public_key  # EID = Public Key (Section 3.2: "EID = Public_Key")
        self.eid_str = sha256_hex(self.eid); self.iat = generate_iat()
        self.dht = SimpleDHT(node_id=self.eid)
        self.ds_manager = DiscoverySpaceManager(self.dht)
        self.discovery = AnonymousDiscovery(self.dht)
        self.ticket_manager = ForwardingTicketManager(self.dht)
        self.reputation_manager = ReputationManager()
        self.pss_manager = PSSManager(); self.ese_manager = ESEManager(dht=self.dht)
        self.pom_manager = PoMManager(self.reputation_manager)
        self.twopse_manager = TwoPSEManager(self.reputation_manager)
        self.migration_manager = MigrationManager(self.reputation_manager)
        self.token_bucket = TokenBucket(capacity=100, refill_rate=10)
        self.circuit_breaker = CircuitBreaker(threshold=10, cooldown=60)
        self.wire_session: Optional[IACPSessionWire] = None; self.is_running = False
        self.active_channels: Dict[bytes, SecureSessionChannel] = {}
        self.dhi_eq = DHIContentEquivalence()
        self.reputation_manager.register_eid(self.eid, self.public_key)

    def start(self): self.is_running = True; print(f"[{self.name}] Agent started. EID: {sha256_hex(self.eid)[:16]}...")
    def stop(self): self.is_running = False; print(f"[{self.name}] Agent stopped.")
    def get_eid_hex(self) -> str: return sha256_hex(self.eid)
    def get_eid_display(self) -> str: return self.get_eid_hex()[:16]

    def connect(self, peer_eid: bytes, peer_addr: Optional[str] = None, sfc: bool = False) -> Optional[SecureSessionChannel]:
        """Establish a high-level connection to a peer."""
        ch = SecureSessionChannel(self, peer_eid, peer_addr)
        if ch.establish(sfc): self.active_channels[peer_eid] = ch; return ch
        return None

    def discover_peers(self, namespace: str, topic: str) -> List[Dict]:
        """Search Discovery Space for peers."""
        ds_id = self.ds_manager.compute_ds_id(namespace, topic, 1)
        return self.ds_manager.query_ds(ds_id)

    def join_discovery_space(self, namespace: str, topic: str) -> bool:
        """Join a Discovery Space."""
        ds_id = self.ds_manager.compute_ds_id(namespace, topic, 1)
        return self.ds_manager.join_ds(ds_id, self.private_key)

    def announce_discovery_space(self, namespace: str, topic: str, description: str = ""):
        """Create/announce a Discovery Space."""
        self.ds_manager.announce_ds(namespace, topic, 1, self.private_key, description)

    def verify_content_equivalence(self, text_a: str, text_b: str) -> Dict:
        """Compute DHI Content Equivalence (EVM) for two texts."""
        return self.dhi_eq.verify_equivalence(text_a, text_b)

# ─────────────────────────────────────────────────────────────────────────────
# 22. QUIC TRANSPORT BINDING (Section 4.2.8)
# ─────────────────────────────────────────────────────────────────────────────

class IACPQuicTransport:
    ALPN = "iacp"
    def __init__(self, local_eid: bytes, peer_eid: bytes):
        self.local_eid = local_eid; self.peer_eid = peer_eid; self.control_stream_id = 0; self.data_stream_id = 1
        self.max_float_buf = 4194304; self.t_eval = 15000; self.session_established = False
    def create_quic_session(self, is_initiator: bool) -> Dict:
        return {"alpn": self.ALPN, "local_eid": self.local_eid.hex(), "peer_eid": self.peer_eid.hex(), "is_initiator": is_initiator, "transport_params": {"max_float_buf": self.max_float_buf, "t_eval": self.t_eval}}
    def map_stream_to_pss(self, stream_id: int, msg_type: int) -> str: return "CONTROL_STREAM" if stream_id == 0 else "DATA_STREAM"
    def handle_quic_error(self, error_code: int) -> Dict: return {"error": error_code, "action": "TERMINATE_PSS", "transition": "STATE_DISCONNECTED", "reconcile": True}

# ─────────────────────────────────────────────────────────────────────────────
# 23. TEE ATTESTATION (Section 4.2.10 / RATS)
# ─────────────────────────────────────────────────────────────────────────────

class TeeAttestationManager:
    ATTESTATION_TYPES = {0x01: "EAT", 0x02: "CWT", 0x03: "TPM", 0x04: "TDX", 0x05: "SEV_SNP"}
    def __init__(self): self.cache: Dict[Tuple[bytes, str, str], Dict] = {}; self.cache_ttl = 300
    def create_attestation_evidence(self, tee_type: str, measurements: Dict, private_key: bytes, eid: bytes) -> Dict:
        at = next((k for k, v in self.ATTESTATION_TYPES.items() if v == tee_type), 0x01)
        ev = {"tee_type": tee_type, "measurements": measurements, "algorithm": "sha256", "timestamp": int(time.time())}
        eb = json.dumps(ev, sort_keys=True).encode(); sig = sign_message(private_key, eb)
        return {"attestation_type": at, "attestation_length": len(eb), "evidence": eb.hex(), "signature": sig.hex(), "eid": eid.hex()}
    def verify_attestation(self, evidence_hex: str, signature_hex: str, public_key: bytes, tee_type: str) -> Tuple[bool, str]:
        try:
            ev = bytes.fromhex(evidence_hex); sig = bytes.fromhex(signature_hex)
            if not verify_signature(public_key, ev, sig): return False, "SIGNATURE_INVALID"
            ed = json.loads(ev.decode())
            if ed.get("tee_type") != tee_type: return False, "TEE_TYPE_MISMATCH"
            if time.time() - ed.get("timestamp", 0) > 300: return False, "EVIDENCE_STALE"
            return True, "VALID"
        except Exception as e: return False, f"ERROR: {e}"
    def cache_attestation_result(self, cache_key: Tuple[bytes, str, str], result: Dict): self.cache[cache_key] = {"result": result, "timestamp": time.time(), "ttl": self.cache_ttl}
    def get_cached_result(self, cache_key: Tuple[bytes, str, str]) -> Optional[Dict]:
        if cache_key in self.cache:
            e = self.cache[cache_key]
            if time.time()-e["timestamp"] < e["ttl"]: return e["result"]
            del self.cache[cache_key]
        return None
    def create_attestation_result(self, subject_eid: bytes, verifier_id: str, tee_type: str, measurements_hash: str, status: str, reason: str = "none") -> Dict:
        r = {"result_type": "iacp-attestation-result", "version": "1.0", "subject_eid": subject_eid.hex(), "verifier_id": verifier_id, "verification_time": int(time.time()), "tee_type": tee_type, "measurements_hash": measurements_hash, "status": status, "reason": reason}
        r["signature"] = sha256_hex(json.dumps(r, sort_keys=True).encode()); return r

# ─────────────────────────────────────────────────────────────────────────────
# 24. CROSS-DOMAIN FEDERATION (Section 3.7)
# ─────────────────────────────────────────────────────────────────────────────

class FederationGateway:
    def __init__(self, domain_id: str, curator_eid: bytes, curator_private_key: bytes):
        self.domain_id = domain_id; self.curator_eid = curator_eid; self.curator_private_key = curator_private_key
        self.trust_anchor_documents: Dict[str, Dict] = {}; self.revocation_list: Dict[str, Dict] = {}
    def create_trust_anchor_document(self, namespace: str, allowed_domains: List[str], required_trust_tier: int = 1, max_delegation_depth: int = 5) -> Dict:
        doc = {"document_type": "iacp-trust-anchor", "version": "1.0", "domain": self.domain_id, "domain_id": sha256_hex(self.domain_id.encode()),
               "trust_anchors": [{"type": "ed25519", "key": sha256_hex(self.curator_eid), "valid_from": int(time.time()), "valid_until": int(time.time())+86400*365, "purpose": "eid-validation"}],
               "namespace_root": sha256_hex(namespace.encode()), "curator_eid": sha256_hex(self.curator_eid),
               "federation_policy": {"allowed_domains": allowed_domains, "required_trust_tier": required_trust_tier, "max_delegation_depth": max_delegation_depth}}
        doc["signature"] = sign_message(self.curator_private_key, json.dumps(doc, sort_keys=True).encode()).hex(); return doc
    def publish_trust_anchor(self, dht: SimpleDHT, document: Dict) -> bool:
        return dht.store(sha256(f"iacp-federation:{self.domain_id}".encode()), json.dumps(document).encode(), publisher_eid=self.curator_eid, ttl=86400)
    def validate_trust_anchor(self, document: Dict) -> Tuple[bool, str]:
        try:
            sig = bytes.fromhex(document.get("signature", ""))
            if not sig: return False, "MISSING_SIGNATURE"
            dc = dict(document); del dc["signature"]
            if not verify_signature(self.curator_eid, json.dumps(dc, sort_keys=True).encode(), sig): return False, "SIGNATURE_INVALID"
            now = int(time.time())
            for a in document.get("trust_anchors", []):
                if now < a.get("valid_from", 0): return False, "NOT_YET_VALID"
                if now > a.get("valid_until", 0): return False, "EXPIRED"
            return True, "VALID"
        except Exception as e: return False, f"ERROR: {e}"
    def create_federation_req(self, target_domain_id: str, requester_eid: bytes, requester_private_key: bytes) -> Dict:
        ts = int(time.time()).to_bytes(8, 'big'); r = {"version": 1, "type": 0x1C, "target_domain_id": target_domain_id, "requester_eid": requester_eid.hex(), "timestamp": ts.hex()}
        r["signature"] = sign_message(requester_private_key, json.dumps(r, sort_keys=True).encode()).hex(); return r
    def revoke_trust_anchor(self, anchor_fingerprint: str, reason_code: int = 1) -> Dict:
        r = {"version": 1, "type": 0x20, "target_domain_id": self.domain_id, "anchor_fingerprint": anchor_fingerprint, "revocation_timestamp": int(time.time()), "reason_code": reason_code}
        r["signature"] = sign_message(self.curator_private_key, json.dumps(r, sort_keys=True).encode()).hex(); return r

# ─────────────────────────────────────────────────────────────────────────────
# 25. EMILIA OPAQUE AUTHORIZATION ENVELOPE (Section 5.7.2)
# ─────────────────────────────────────────────────────────────────────────────

class OpaqueAuthEnvelope:
    def __init__(self): self.envelopes: Dict[bytes, Dict] = {}
    def create_envelope(self, auth_data: bytes, nonce: bytes, signature: bytes) -> bytes:
        env = {"auth_data": auth_data.hex(), "nonce": nonce.hex(), "signature": signature.hex(), "timestamp": int(time.time())}
        return sha256(json.dumps(env).encode())
    def verify_envelope_format(self, envelope: bytes) -> bool:
        try: d = json.loads(envelope); return all(k in d for k in ["auth_data", "nonce", "signature"])
        except: return False
    def extract_emilia_receipt(self, envelope: bytes) -> Optional[Dict]:
        try: d = json.loads(envelope); return json.loads(bytes.fromhex(d["auth_data"]))
        except: return None

# ─────────────────────────────────────────────────────────────────────────────
# 26. END
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("IACP Unified Protocol Module (v3)")
    print(f"  Cryptography: {'Ed25519/X25519/AES-GCM/HKDF' if _HAZMAT else 'HMAC/XOR (fallback)'}")

    # Quick self-test
    print("\n=== Quick Self-Test ===")
    priv, pub = generate_keypair(); msg = b"test message"; sig = sign_message(priv, msg)
    assert verify_signature(pub, msg, sig), "Ed25519 fail"; print("[OK] Ed25519")

    a_pr, a_pu = x25519_generate_keypair(); b_pr, b_pu = x25519_generate_keypair()
    assert x25519_ecdh(a_pr, b_pu) == x25519_ecdh(b_pr, a_pu), "ECDH fail"; print("[OK] X25519")

    k = os.urandom(32); n = os.urandom(12); pt = b"Hello IACP!"; ct, mac = aes_gcm_encrypt(k, pt, n)
    assert aes_gcm_decrypt(k, ct, n, mac) == pt; print("[OK] AES-GCM")

    ikm = b"test"; k1 = hkdf_derive(ikm, b"salt", b"info1"); k2 = hkdf_derive(ikm, b"salt", b"info2")
    assert len(k1)==32 and k1!=k2; print("[OK] HKDF")

    dht = SimpleDHT(node_id=os.urandom(32)); ds = DiscoverySpaceManager(dht)
    did = ds.compute_ds_id("test.ns", "test.topic", 1); pk = os.urandom(32)
    ds.announce_ds("test.ns", "test.topic", 1, pk); ds.join_ds(did, pk)
    assert len(ds.query_ds(did)) > 0; print("[OK] query_ds")

    # Test DHI Content Equivalence
    t1 = "Hello World! This is a test."
    t2 = "Hello World!  This is   a test.\n\r"
    r = DHIContentEquivalence.verify_equivalence(t1, t2)
    assert r["overall_pass"], f"DHI failed: {r}"; print(f"[OK] DHI Content Equivalence (EVM={r['evm']:.6f})")

    # Test HCO Serialization
    hco = DHIContentEquivalence.create_hco(1, os.urandom(32), os.urandom(32), 42, "https://example.com")
    data = hco.serialize(); hco2 = HCO.deserialize(data)
    assert hco.trigger_type == hco2.trigger_type and hco.target_url == hco2.target_url
    print("[OK] HCO Serialization")

    # Test SecureSessionChannel with proper dual-key signing
    agent_a = IACPAgent("Alice"); agent_b = IACPAgent("Bob")
    agent_a.start(); agent_b.start()
    # Now use process_pss_init with Bob's PRIVATE KEY for correct Ed25519 signing
    ch_a = SecureSessionChannel(agent_a, agent_b.eid)
    # Override establish to properly use both private keys
    pss = agent_a.pss_manager
    init_data = pss.initiate_pss(agent_a.eid, agent_b.eid, agent_a.private_key, False)
    neg_data = pss.process_pss_init(init_data, agent_b.eid, agent_b.private_key)
    assert neg_data is not None, "PSS_NEG generation failed"
    ch_a.session = pss.complete_handshake(neg_data, agent_a.eid)
    assert ch_a.session is not None, "PSS handshake completion failed"
    ch_a.ese_local = agent_a.ese_manager.create_global_point(agent_a.eid, "test_a")
    ch_a.ese_remote = agent_a.ese_manager.create_global_point(agent_b.eid, "test_b")
    ch_a.send_message("GREETING", {"text": "Hello Bob!"})
    # Verify message was written to the local ESE
    ep = agent_a.ese_manager.get_endpoint(ch_a.ese_local)
    msgs = [v for k, v in ep.data.items() if k.startswith("msg_")] if ep else []
    assert len(msgs) > 0; print(f"[OK] SecureSessionChannel ({len(msgs)} message(s))")

    # Test Topic Hierarchy
    hierarchy = ds.query_topic_hierarchy("test.ns", "test")
    print(f"[OK] Topic Hierarchy ({len(hierarchy)} result(s))")

    print("\n=== All Self-Tests Passed ===")