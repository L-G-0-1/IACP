"""
IACP Core Protocol - ERP, PSS, ESE, Reputation, PoM, Anti-Abuse
==================================================================

Basiert auf IACP Draft Sections 3.6, 4.2, 5.3, 5.4, 5.5, 6.1, 6.4

Erweiterte Implementierung von iacp-demo-04:
- EID Reputation System (Section 3.6)
- Persistent State Sessions PSS mit Dual-Cookie Handshake (Section 6.4)
- Ephemeral State Endpoints ESE (Section 6.1)
- Anti-Abuse: Token-Bucket + Circuit Breaker (Section 5.4)
- Proof of Malfeasance PoM (Section 4.2.7 / 5.5)
- Two-Phase Slashing Escrow 2PSE (Section 4.2.7.2)
- Dynamic PoW Difficulty (Section 5.3.1)
- MIGRATION_VECTOR (Section 4.2.5.1)
- ERP State Machine (Section 4.2.3.3)
"""

import socket
import json
import hashlib
import hmac
import os
import time
import threading
import struct
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import secrets


# ---------------------------------------------------------------------------
# Cryptographic Helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """SHA-256 Hash."""
    return hashlib.sha256(data).digest()

def sha256_hex(data: bytes) -> str:
    """SHA-256 Hash als Hex-String."""
    return hashlib.sha256(data).hexdigest()

def generate_eid() -> bytes:
    """Generiere ein 32-byte EID (zufällig für Demo)."""
    return os.urandom(32)

def generate_iat() -> bytes:
    """Generiere Instance Authentication Token (256-bit)."""
    return os.urandom(32)

def generate_cookie() -> bytes:
    """Generiere 8-byte Cookie."""
    return os.urandom(8)

def sign_message(private_key: bytes, message: bytes) -> bytes:
    """Simulierte Ed25519 Signatur (HMAC-SHA256 für Demo)."""
    return hmac.new(private_key, message, hashlib.sha256).digest()[:64]

def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verifiziere Signatur."""
    expected = sign_message(public_key, message)
    return hmac.compare_digest(expected, signature)

def generate_keypair() -> Tuple[bytes, bytes]:
    """Generiere Ed25519 Keypair (simuliert)."""
    private_key = os.urandom(32)
    public_key = sha256(private_key)
    return private_key, public_key

def x25519_generate_keypair() -> Tuple[bytes, bytes]:
    """Generiere X25519 Keypair (simuliert)."""
    private_key = os.urandom(32)
    public_key = sha256(private_key)
    return private_key, public_key

def x25519_ecdh(private_key: bytes, public_key: bytes) -> bytes:
    """X25519 ECDH Key Agreement (simuliert)."""
    return sha256(private_key + public_key)

def aes_gcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
    """AES-GCM-256 Verschlüsselung (simuliert)."""
    ciphertext = bytes([plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext))])
    mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    return ciphertext, mac

def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, mac: bytes) -> bytes:
    """AES-GCM-256 Entschlüsselung mit MAC-Verifikation."""
    expected_mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(expected_mac, mac):
        raise ValueError("MAC verification failed")
    plaintext = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
    return plaintext


# ---------------------------------------------------------------------------
# PoW (Proof-of-Work) - Hashcash-Style mit dynamischer Difficulty
# ---------------------------------------------------------------------------

def calculate_pow_nonce(target_key: bytes, difficulty: int = 2) -> Tuple[int, bytes]:
    """Finde PoW Nonce mit trailing zeros."""
    nonce = 0
    while True:
        hash_input = target_key + nonce.to_bytes(8, 'big')
        hash_result = sha256(hash_input)
        
        trailing_zeros = 0
        for byte in reversed(hash_result):
            if byte == 0:
                trailing_zeros += 8
            else:
                trailing_zeros += (byte & -byte).bit_length() - 1
                break
        
        if trailing_zeros >= difficulty:
            return nonce, hash_result
        
        nonce += 1
        if nonce > 100000:
            raise ValueError(f"PoW failed after {nonce} attempts")

def verify_pow(target_key: bytes, nonce: int, difficulty: int = 2) -> bool:
    """Verifiziere PoW Nonce."""
    hash_input = target_key + nonce.to_bytes(8, 'big')
    hash_result = sha256(hash_input)
    
    trailing_zeros = 0
    for byte in reversed(hash_result):
        if byte == 0:
            trailing_zeros += 8
        else:
            trailing_zeros += (byte & -byte).bit_length() - 1
            break
    
    return trailing_zeros >= difficulty


# ---------------------------------------------------------------------------
# Datenstrukturen
# ---------------------------------------------------------------------------

@dataclass
class EIDRecord:
    """EID Record mit Reputation und Metadaten."""
    eid: bytes
    public_key: bytes
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    reputation: float = 1.0  # R_State(t)
    pow_count: int = 0  # PoM_Count für Reputation
    is_slashed: bool = False
    slash_timestamp: Optional[float] = None
    current_generation: int = 0
    current_locator: str = ""
    
@dataclass
class PSSSession:
    """Persistent State Session mit Dual-Cookie Handshake."""
    session_id: bytes  # I-Cookie || R-Cookie
    initiator_eid: bytes
    responder_eid: bytes
    i_cookie: bytes  # 8 bytes
    r_cookie: bytes  # 8 bytes
    state: str = "STATE_HEARING"  # STATE_HEARING, STATE_ESTABLISHED, STATE_DISCONNECTED
    initiator_seq: int = 0
    responder_seq: int = 0
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    sfc_active: bool = False
    sfc_conditions: Optional[bytes] = None
    
@dataclass
class ESEndpoint:
    """Ephemeral State Endpoint."""
    eid: bytes  # Parent EID
    endpoint_id: bytes  # GP_Coordinate = SHA-256(EID || Tag) oder LP
    is_global: bool = True
    data: Dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    ttl: int = 3600
    
@dataclass
class PoMTicket:
    """Proof of Malfeasance Ticket."""
    target_eid: bytes
    fragment_a: bytes  # IP_Vector_A || Gen_Counter_A || Signature_A
    fragment_b: bytes  # IP_Vector_B || Gen_Counter_B || Signature_B
    timestamp: float = field(default_factory=time.time)
    accuser_eid: Optional[bytes] = None
    signature: Optional[bytes] = None

@dataclass
class TwoPSEEscrow:
    """Two-Phase Slashing Escrow State."""
    target_eid: bytes
    state: str = "STATE_CHALLENGED"  # STATE_CHALLENGED, STATE_SLASHED, STATE_NOMINAL
    escrow_start: float = field(default_factory=time.time)
    escrow_duration: int = 3600  # 1 hour
    rebuttal_deadline: float = field(default_factory=lambda: time.time() + 3600)
    confirmation_count: int = 0
    required_confirmations: int = 7


# ---------------------------------------------------------------------------
# EID Reputation System (Section 3.6)
# ---------------------------------------------------------------------------

class ReputationManager:
    """Verwalte EID Reputation mit EMA und Threshold Enforcement."""
    
    def __init__(self):
        self.eids: Dict[bytes, EIDRecord] = {}
        self.lock = threading.Lock()
        
        # Reputation Parameter
        self.alpha = 0.12  # EMA smoothing factor
        self.w1 = 0.45  # S_Verify (signature validity)
        self.w2 = 0.35  # A_Telemetry (availability)
        self.w3 = 0.20  # PoM_Score (misbehavior)
        self.rho_threshold = 0.7  # R_Threshold
        self.k_pom = 5  # Normalization factor for PoM
        
    def register_eid(self, eid: bytes, public_key: bytes, locator: str = "") -> EIDRecord:
        """Registriere neue EID mit initial Reputation 1.0."""
        with self.lock:
            if eid not in self.eids:
                record = EIDRecord(eid=eid, public_key=public_key, current_locator=locator)
                self.eids[eid] = record
            return self.eids[eid]
    
    def update_reputation(self, eid: bytes, metrics: Dict[str, float]) -> float:
        """Aktualisiere Reputation basierend auf Metrics.
        
        R_State(t) = a * M(t) + (1 - a) * R_State(t-1)
        M(t) = w1*S_Verify + w2*A_Telemetry - w3*PoM_Score
        """
        with self.lock:
            if eid not in self.eids:
                return 1.0
            
            record = self.eids[eid]
            
            # Extract metrics
            s_verify = metrics.get('s_verify', 1.0)  # Ratio of valid signatures
            a_telemetry = metrics.get('a_telemetry', 1.0)  # Availability
            pom_count = metrics.get('pom_count', record.pow_count)
            
            # PoM_Score = min(1.0, PoM_Count / k)
            pom_score = min(1.0, pom_count / self.k_pom)
            
            # M(t) = w1*S_Verify + w2*A_Telemetry - w3*PoM_Score
            m_t = self.w1 * s_verify + self.w2 * a_telemetry - self.w3 * pom_score
            
            # EMA: R_State(t) = a * M(t) + (1 - a) * R_State(t-1)
            record.reputation = self.alpha * m_t + (1 - self.alpha) * record.reputation
            record.pom_count = pom_count
            record.last_seen = time.time()
            
            # Clamp to [0.0, 1.0]
            record.reputation = max(0.0, min(1.0, record.reputation))
            
            return record.reputation
    
    def get_reputation(self, eid: bytes) -> float:
        """Hole aktuelle Reputation."""
        with self.lock:
            if eid not in self.eids:
                return 1.0
            return self.eids[eid].reputation
    
    def add_pom_count(self, eid: bytes, count: int = 1):
        """Erhöhe PoM Count."""
        with self.lock:
            if eid in self.eids:
                self.eids[eid].pow_count += count
    
    def check_threshold(self, eid: bytes, base_difficulty: int = 2) -> Tuple[bool, int]:
        """Prüfe Reputation Threshold und berechne escalierte PoW Difficulty.
        
        D_escalated = D_base + max(0, ceil((R_Threshold - R_State) * 40))
        Max escalation: +32 bits
        """
        with self.lock:
            if eid not in self.eids:
                return True, base_difficulty
            
            record = self.eids[eid]
            r_state = record.reputation
            
            if r_state >= self.rho_threshold:
                return True, base_difficulty
            
            # Escalate difficulty
            deficit = self.rho_threshold - r_state
            escalation = max(0, int((deficit * 40) + 0.5))
            escalation = min(escalation, 32)  # Cap at +32 bits
            
            return r_state >= 0.3, base_difficulty + escalation
    
    def is_blocked(self, eid: bytes) -> bool:
        """Prüfe ob EID blockiert ist (R_State < 0.3)."""
        with self.lock:
            if eid not in self.eids:
                return False
            return self.eids[eid].reputation < 0.3 or self.eids[eid].is_slashed
    
    def decay_pom_scores(self, decay_factor: float = 0.5, max_age_days: int = 30):
        """Decay alte PoM Tickets (Section 5.5.4)."""
        cutoff = time.time() - (max_age_days * 86400)
        with self.lock:
            for record in self.eids.values():
                # Simplified: In production, track PoM timestamps
                if record.pom_count > 0:
                    record.pow_count = int(record.pow_count * decay_factor)


# ---------------------------------------------------------------------------
# Token Bucket Rate Limiter (Section 5.4.1)
# ---------------------------------------------------------------------------

class TokenBucket:
    """Token-Bucket Rate Limiter."""
    
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens: int) -> bool:
        """Consumiere Token. Gibt True zurück bei Erfolg."""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def reset(self):
        """Reset Bucket."""
        with self.lock:
            self.tokens = float(self.capacity)


# ---------------------------------------------------------------------------
# Circuit Breaker (Section 5.4.2)
# ---------------------------------------------------------------------------

class CircuitBreakerState(Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"

class CircuitBreaker:
    """Autonomer Circuit Breaker für DHT Nodes."""
    
    def __init__(self, threshold: int = 100, cooldown: int = 60):
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.threshold = threshold
        self.cooldown = cooldown
        self.last_failure = 0
        self.lock = threading.Lock()
    
    def record_success(self):
        """Record successful request."""
        with self.lock:
            self.failure_count = 0
            self.state = CircuitBreakerState.CLOSED
    
    def record_failure(self):
        """Record failed request."""
        with self.lock:
            self.failure_count += 1
            self.last_failure = time.time()
            if self.failure_count >= self.threshold:
                self.state = CircuitBreakerState.OPEN
    
    def can_execute(self) -> bool:
        """Prüfe ob Request ausgeführt werden darf."""
        with self.lock:
            if self.state == CircuitBreakerState.CLOSED:
                return True
            
            # Check cooldown
            if time.time() - self.last_failure > self.cooldown:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                return True
            
            return False


# ---------------------------------------------------------------------------
# EID State Machine (Section 4.2.3.3)
# ---------------------------------------------------------------------------

class EIDState(Enum):
    UNBOUND = "UNBOUND"
    ALLOCATED = "ALLOCATED"
    TRANSITION = "TRANSITION"
    BOUND = "BOUND"
    EVOLVE_PENDING = "EVOLVE_PENDING"

class LLContext:
    """Local Loopback Context für einen AAI."""
    
    def __init__(self, eid: bytes, iat: bytes):
        self.eid = eid
        self.iat = iat
        self.state = EIDState.UNBOUND
        self.generation_counter = 0
        self.locator = ""
        self.buffer = []  # FIFO buffer for TRANSITION state
        self.created_at = time.time()
        self.last_keepalive = time.time()
        
    def transition(self, event: str) -> bool:
        """State Machine Transition."""
        transitions = {
            EIDState.UNBOUND: {
                "ERP_INIT": EIDState.ALLOCATED,
            },
            EIDState.ALLOCATED: {
                "ERP_ALLOC": EIDState.ALLOCATED,
                "ERP_REGISTER": EIDState.TRANSITION,
            },
            EIDState.TRANSITION: {
                "DHT_CONFIRM": EIDState.BOUND,
                "NETWORK_CHURN": EIDState.TRANSITION,
            },
            EIDState.BOUND: {
                "NETWORK_CHURN": EIDState.TRANSITION,
                "APP_DIGEST_CHANGE": EIDState.EVOLVE_PENDING,
            },
            EIDState.EVOLVE_PENDING: {
                "ERP_EVOLVE_COMPLETE": EIDState.BOUND,
            }
        }
        
        current_transitions = transitions.get(self.state, {})
        next_state = current_transitions.get(event)
        
        if next_state:
            print(f"[LL-Context] State transition: {self.state.value} -> {next_state.value} (event: {event})")
            self.state = next_state
            return True
        return False


# ---------------------------------------------------------------------------
# Persistent State Sessions (Section 6.4)
# ---------------------------------------------------------------------------

class PSSManager:
    """Verwalte Persistent State Sessions mit Dual-Cookie Handshake."""
    
    def __init__(self):
        self.sessions: Dict[bytes, PSSSession] = {}  # session_id -> session
        self.pending_handshakes: Dict[bytes, Dict] = {}  # i_cookie -> pending
        self.lock = threading.Lock()
        
    def create_session_id(self, i_cookie: bytes, r_cookie: bytes) -> bytes:
        """Erstelle Session ID: I-Cookie || R-Cookie."""
        return i_cookie + r_cookie
    
    def initiate_pss(self, initiator_eid: bytes, target_eid: bytes, sfc_requested: bool = False) -> Optional[Dict]:
        """PSS_INIT: Starte Dual-Cookie Handshake."""
        i_cookie = generate_cookie()
        
        # Create pending handshake
        with self.lock:
            self.pending_handshakes[i_cookie] = {
                'initiator_eid': initiator_eid,
                'target_eid': target_eid,
                'timestamp': time.time(),
                'sfc_requested': sfc_requested
            }
        
        # PSS_INIT Wire Format (Type 0x08)
        pss_init = {
            "version": 1,
            "type": 0x08,
            "initiator_eid": initiator_eid.hex(),
            "i_cookie": i_cookie.hex(),
            "r_cookie": "0000000000000000",  # Zero-filled initially
            "initial_seq": 0,
            "sfc_requested": sfc_requested,
            "signature": sign_message(initiator_eid[:32], i_cookie).hex()
        }
        
        return pss_init
    
    def process_pss_init(self, pss_init: Dict, responder_eid: bytes) -> Optional[Dict]:
        """Verarbeite PSS_INIT und erstelle PSS_NEG."""
        i_cookie = bytes.fromhex(pss_init['i_cookie'])
        initiator_eid = bytes.fromhex(pss_init['initiator_eid'])
        
        # Verify signature
        signature = bytes.fromhex(pss_init['signature'])
        if not verify_signature(initiator_eid[:32], i_cookie, signature):
            return None
        
        # Create PSS_NEG
        r_cookie = generate_cookie()
        
        # Store pending
        with self.lock:
            self.pending_handshakes[i_cookie] = {
                'initiator_eid': initiator_eid,
                'responder_eid': responder_eid,
                'timestamp': time.time(),
                'r_cookie': r_cookie
            }
        
        # PSS_NEG Wire Format (Type 0x0A)
        pss_neg = {
            "version": 1,
            "type": 0x0A,
            "i_cookie": i_cookie.hex(),
            "r_cookie": r_cookie.hex(),
            "negotiation_counter": 1,
            "rejection_flags": 0,
            "sfc_conditions": os.urandom(32).hex() if pss_init.get('sfc_requested') else "0" * 64,
            "signature": sign_message(responder_eid[:32], i_cookie + r_cookie).hex()
        }
        
        return pss_neg
    
    def complete_handshake(self, pss_neg: Dict, initiator_eid: bytes) -> Optional[PSSSession]:
        """PSS_ACK: Vervollständige Handshake."""
        i_cookie = bytes.fromhex(pss_neg['i_cookie'])
        r_cookie = bytes.fromhex(pss_neg['r_cookie'])
        
        # Verify I-Cookie matches pending
        with self.lock:
            pending = self.pending_handshakes.get(i_cookie)
            if not pending:
                return None
            
            # Verify signature
            signature = bytes.fromhex(pss_neg['signature'])
            if not verify_signature(pending['responder_eid'][:32], i_cookie + r_cookie, signature):
                return None
            
            # Create session
            session_id = self.create_session_id(i_cookie, r_cookie)
            session = PSSSession(
                session_id=session_id,
                initiator_eid=initiator_eid,
                responder_eid=pending['responder_eid'],
                i_cookie=i_cookie,
                r_cookie=r_cookie,
                state="STATE_ESTABLISHED",
                sfc_active=len(pss_neg.get('sfc_conditions', '0' * 64)) > 0
            )
            
            self.sessions[session_id] = session
            del self.pending_handshakes[i_cookie]
            
            return session
    
    def get_session(self, session_id: bytes) -> Optional[PSSSession]:
        """Hole Session by ID."""
        with self.lock:
            return self.sessions.get(session_id)
    
    def close_session(self, session_id: bytes, reason: str = "NORMAL"):
        """Schließe Session (PSS_TEARDOWN)."""
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                session.state = "STATE_CLOSED"
                # In production: Send PSS_TEARDOWN to peer
                return True
        return False


# ---------------------------------------------------------------------------
# Ephemeral State Endpoints (Section 6.1)
# ---------------------------------------------------------------------------

class ESEManager:
    """Verwalte Ephemeral State Endpoints."""
    
    def __init__(self):
        self.endpoints: Dict[bytes, ESEndpoint] = {}  # endpoint_id -> ESE
        self.lock = threading.Lock()
    
    def create_local_point(self, eid: bytes, tag: str) -> bytes:
        """Erstelle Local Point (nur lokal zugänglich)."""
        endpoint_id = sha256(eid + tag.encode())
        with self.lock:
            self.endpoints[endpoint_id] = ESEndpoint(
                eid=eid,
                endpoint_id=endpoint_id,
                is_global=False,
                data={'tag': tag}
            )
        return endpoint_id
    
    def create_global_point(self, eid: bytes, tag: str) -> bytes:
        """Erstelle Global Point (GP_Coordinate = SHA-256(EID || Tag))."""
        gp_coordinate = sha256(eid + tag.encode())
        with self.lock:
            self.endpoints[gp_coordinate] = ESEndpoint(
                eid=eid,
                endpoint_id=gp_coordinate,
                is_global=True,
                data={'tag': tag}
            )
        return gp_coordinate
    
    def get_endpoint(self, endpoint_id: bytes) -> Optional[ESEndpoint]:
        """Hole Endpoint."""
        with self.lock:
            ep = self.endpoints.get(endpoint_id)
            if ep and (time.time() - ep.created_at) < ep.ttl:
                return ep
            elif ep:
                del self.endpoints[endpoint_id]
        return None
    
    def update_data(self, endpoint_id: bytes, key: str, value: Any):
        """Aktualisiere Endpoint Data."""
        with self.lock:
            if endpoint_id in self.endpoints:
                self.endpoints[endpoint_id].data[key] = value
    
    def cleanup_expired(self):
        """Entferne abgelaufene Endpoints."""
        with self.lock:
            now = time.time()
            expired = [eid for eid, ep in self.endpoints.items() 
                      if (now - ep.created_at) > ep.ttl]
            for eid in expired:
                del self.endpoints[eid]


# ---------------------------------------------------------------------------
# Proof of Malfeasance (PoM) (Section 4.2.7.1 / 5.5.1)
# ---------------------------------------------------------------------------

class PoMManager:
    """Verwalte Proof of Malfeasance Tickets."""
    
    def __init__(self, reputation_manager: ReputationManager):
        self.pom_tickets: List[PoMTicket] = []
        self.reputation_manager = reputation_manager
        self.lock = threading.Lock()
        self.pom_ttl = 86400  # 24 hours
        
    def create_pom_ticket(self, target_eid: bytes, fragment_a: bytes, 
                         fragment_b: bytes, accuser_eid: bytes) -> Optional[PoMTicket]:
        """Erstelle PoM Ticket bei gültigen Beweisen."""
        # Verify fragments are structurally non-identical
        if fragment_a == fragment_b:
            return None
        
        # Verify both signatures against same EID (simplified)
        # In production: Full Ed25519 verification
        ticket = PoMTicket(
            target_eid=target_eid,
            fragment_a=fragment_a,
            fragment_b=fragment_b,
            accuser_eid=accuser_eid,
            timestamp=time.time()
        )
        
        with self.lock:
            self.pom_tickets.append(ticket)
            
        # Update reputation
        self.reputation_manager.add_pom_count(target_eid, 1)
        
        return ticket
    
    def validate_pom_ticket(self, ticket: PoMTicket) -> bool:
        """Validiere PoM Ticket (simuliert)."""
        # In production: Verify both signatures against Target_EID
        # Check structural non-identity
        return ticket.fragment_a != ticket.fragment_b
    
    def get_active_poms(self, eid: bytes, window: int = 86400) -> List[PoMTicket]:
        """Hole aktive PoM Tickets für EID."""
        cutoff = time.time() - window
        with self.lock:
            return [t for t in self.pom_tickets 
                    if t.target_eid == eid and t.timestamp > cutoff]
    
    def cleanup_old_tickets(self):
        """Entferne abgelaufene Tickets."""
        cutoff = time.time() - self.pom_ttl
        with self.lock:
            self.pom_tickets = [t for t in self.pom_tickets if t.timestamp > cutoff]


# ---------------------------------------------------------------------------
# Two-Phase Slashing Escrow 2PSE (Section 4.2.7.2)
# ---------------------------------------------------------------------------

class TwoPSEManager:
    """Verwalte Two-Phase Slashing Escrow."""
    
    def __init__(self, reputation_manager: ReputationManager):
        self.escrows: Dict[bytes, TwoPSEEscrow] = {}
        self.reputation_manager = reputation_manager
        self.lock = threading.Lock()
        self.escrow_duration = 3600  # 1 hour
        self.slashing_threshold = 3  # PoM_Count >= 3 in 24h window
        
    def initiate_escrow(self, target_eid: bytes) -> bool:
        """Starte 2PSE Escrow für Target EID."""
        with self.lock:
            if target_eid in self.escrows:
                escrow = self.escrows[target_eid]
                if escrow.state == "STATE_CHALLENGED":
                    # Reset timer
                    escrow.escrow_start = time.time()
                    escrow.rebuttal_deadline = time.time() + self.escrow_duration
                    return True
                return False
            
            escrow = TwoPSEEscrow(
                target_eid=target_eid,
                state="STATE_CHALLENGED",
                escrow_start=time.time(),
                escrow_duration=self.escrow_duration,
                rebuttal_deadline=time.time() + self.escrow_duration
            )
            self.escrows[target_eid] = escrow
            return True
    
    def submit_counter_proof(self, target_eid: bytes, counter_proof: bytes) -> bool:
        """Submitting Counter-Proof während Escrow Window."""
        with self.lock:
            if target_eid not in self.escrows:
                return False
            
            escrow = self.escrows[target_eid]
            if escrow.state != "STATE_CHALLENGED":
                return False
            
            # Verify counter-proof (simplified)
            # In production: Full cryptographic verification
            if len(counter_proof) > 0:
                escrow.state = "STATE_NOMINAL"
                del self.escrows[target_eid]
                return True
            
            return False
    
    def check_escrow_expiry(self, target_eid: bytes) -> bool:
        """Prüfe ob Escrow abgelaufen ist und slash falls nötig."""
        with self.lock:
            if target_eid not in self.escrows:
                return False
            
            escrow = self.escrows[target_eid]
            if escrow.state != "STATE_CHALLENGED":
                return False
            
            if time.time() > escrow.rebuttal_deadline:
                # Escrow expired without counter-proof -> SLASH
                escrow.state = "STATE_SLASHED"
                self.reputation_manager.update_reputation(target_eid, {
                    's_verify': 0.0,
                    'a_telemetry': 0.0,
                    'pom_count': 10  # High PoM count
                })
                return True
            
            return False
    
    def get_escrow_state(self, target_eid: bytes) -> Optional[str]:
        """Hole aktuellen Escrow State."""
        with self.lock:
            if target_eid in self.escrows:
                return self.escrows[target_eid].state
        return None


# ---------------------------------------------------------------------------
# MIGRATION_VECTOR (Section 4.2.5.1)
# ---------------------------------------------------------------------------

class MigrationManager:
    """Verwalte MIGRATION_VECTOR für Locator Updates."""
    
    def __init__(self, reputation_manager: ReputationManager):
        self.reputation_manager = reputation_manager
        self.pending_migrations: Dict[bytes, Dict] = {}
        self.lock = threading.Lock()
        
    def create_migration_vector(self, source_eid: bytes, new_locator: str, 
                               private_key: bytes) -> Optional[Dict]:
        """Erstelle MIGRATION_VECTOR (Type 0x17)."""
        # Increment generation counter
        with self.lock:
            if source_eid not in self.pending_migrations:
                self.pending_migrations[source_eid] = {'gen': 0}
            
            old_gen = self.pending_migrations[source_eid]['gen']
            new_gen = old_gen + 1
            self.pending_migrations[source_eid]['gen'] = new_gen
        
        # Create signature: Sign_Ed25519(Private_Key, Source_EID || New_IP || Gen_Counter_New)
        signature_input = source_eid + new_locator.encode() + new_gen.to_bytes(8, 'big')
        signature = sign_message(private_key, signature_input)
        
        # MIGRATION_VECTOR Wire Format
        migration = {
            "version": 1,
            "type": 0x17,
            "source_eid": source_eid.hex(),
            "new_locator": new_locator,
            "generation_counter": new_gen,
            "signature": signature.hex(),
            "timestamp": time.time()
        }
        
        return migration
    
    def process_migration_vector(self, migration: Dict) -> Tuple[bool, int]:
        """Verarbeite MIGRATION_VECTOR und aktualisiere Cache."""
        source_eid = bytes.fromhex(migration['source_eid'])
        new_locator = migration['new_locator']
        new_gen = migration['generation_counter']
        signature = bytes.fromhex(migration['signature'])
        
        # Verify signature (simplified)
        # In production: Full Ed25519 verification
        signature_input = source_eid + new_locator.encode() + new_gen.to_bytes(8, 'big')
        if not verify_signature(source_eid[:32], signature_input, signature):
            return False, -1
        
        # Update reputation manager
        self.reputation_manager.eids[source_eid].current_locator = new_locator
        self.reputation_manager.eids[source_eid].current_generation = new_gen
        
        return True, new_gen
    
    def validate_generation(self, source_eid: bytes, packet_gen: int) -> bool:
        """Generation Counting Validation (Section 4.2.5.2)."""
        with self.lock:
            if source_eid not in self.reputation_manager.eids:
                return True  # Unknown EID, accept
            
            record = self.reputation_manager.eids[source_eid]
            cache_gen = record.current_generation
            
            if packet_gen > cache_gen:
                # Update cache
                record.current_generation = packet_gen
                return True
            elif packet_gen == cache_gen:
                return True  # In-sequence
            else:
                # Stale frame
                return False


# ---------------------------------------------------------------------------
# IACP Entity (Combines all components)
# ---------------------------------------------------------------------------

class IACPAgent:
    """Main IACP Agent combining all protocols."""
    
    def __init__(self, name: str):
        self.name = name
        self.eid = generate_eid()
        self.public_key, self.private_key = generate_keypair()
        self.iat = generate_iat()
        
        # Core components
        self.reputation_manager = ReputationManager()
        self.pss_manager = PSSManager()
        self.ese_manager = ESEManager()
        self.pom_manager = PoMManager(self.reputation_manager)
        self.twopse_manager = TwoPSEManager(self.reputation_manager)
        self.migration_manager = MigrationManager(self.reputation_manager)
        
        # Anti-abuse
        self.token_bucket = TokenBucket(capacity=100, refill_rate=10)  # 100 tokens, 10/s
        self.circuit_breaker = CircuitBreaker(threshold=10, cooldown=60)
        
        # State
        self.is_running = False
        
        # Register self
        self.reputation_manager.register_eid(self.eid, self.public_key)
        
    def start(self):
        """Start Agent."""
        self.is_running = True
        print(f"[{self.name}] Agent started. EID: {sha256_hex(self.eid)[:16]}...")
    
    def stop(self):
        """Stop Agent."""
        self.is_running = False
        print(f"[{self.name}] Agent stopped.")
    
    def get_eid_hex(self) -> str:
        """EID als Hex-String."""
        return sha256_hex(self.eid)


# ---------------------------------------------------------------------------
# Demo / Test Code
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("IACP Core Protocol Module")
    print("Features: ERP, PSS, ESE, Reputation, PoM, Anti-Abuse, Migration")
    print("See demo_core.py for usage example.")