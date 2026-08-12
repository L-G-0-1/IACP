"""
IACP Full Demo Visualizer – Graphical Protocol Walkthrough
============================================================
Shows all 43 stations of the IACP Agent Lifecycle in 9 phases
with animated Canvas visualizations, step log and live metrics.

Usage:
    from iacp_demo_visualizer import DemoVisualizer
    viz = DemoVisualizer(parent_widget)
    viz.run()
"""

import tkinter as tk
from tkinter import ttk
import math
import time
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Tuple
import random


# ─────────────────────────────────────────────────────────────────────────────
# Color palette – 9 phases
# ─────────────────────────────────────────────────────────────────────────────

PHASE_COLORS = {
    1:  {"bg": "#E3F2FD", "fg": "#1565C0", "accent": "#2196F3", "name": "Identity & Registration"},
    2:  {"bg": "#F3E5F5", "fg": "#7B1FA2", "accent": "#9C27B0", "name": "Discovery & Peer Finding"},
    3:  {"bg": "#E8F5E9", "fg": "#2E7D32", "accent": "#4CAF50", "name": "Session Establishment (PSS)"},
    4:  {"bg": "#E0F7FA", "fg": "#00838F", "accent": "#00BCD4", "name": "Communication & State"},
    5:  {"bg": "#FFF3E0", "fg": "#E65100", "accent": "#FF9800", "name": "Mobility & Fault Tolerance"},
    6:  {"bg": "#FFEBEE", "fg": "#C62828", "accent": "#F44336", "name": "Governance & Slashing"},
    7:  {"bg": "#EDE7F6", "fg": "#4527A0", "accent": "#3F51B5", "name": "Cross-Domain & Attestation"},
    8:  {"bg": "#ECEFF1", "fg": "#37474F", "accent": "#607D8B", "name": "Session Termination"},
    9:  {"bg": "#FFFDE7", "fg": "#F9A825", "accent": "#FFC107", "name": "DHI Content Processing"},
}

CATEGORY_ICONS = {
    "crypto":      "\U0001f510",
    "network":     "\U0001f310",
    "state":       "\u2699\ufe0f",
    "formula":     "\U0001f4ca",
    "dht":         "\U0001f5c4\ufe0f",
    "governance":  "\u2696\ufe0f",
    "session":     "\U0001f517",
    "discovery":   "\U0001f50d",
    "mobility":    "\U0001f4e1",
    "termination": "\U0001f6aa",
    "content":     "\U0001f4c4",
    "identity":    "\U0001f194",
}


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DemoStep:
    """A single step in the demo."""
    phase: int
    step_id: int
    title: str
    description: str
    category: str
    duration: float = 3.0
    detail_lines: List[str] = field(default_factory=list)
    icon: str = ""

    def __post_init__(self):
        if not self.icon:
            self.icon = CATEGORY_ICONS.get(self.category, "\u25cf")
        if not self.detail_lines:
            self.detail_lines = [self.description]


@dataclass
class Phase:
    """A phase with multiple steps."""
    number: int
    name: str
    color: Dict[str, str]
    steps: List[DemoStep] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Animation Engine
# ─────────────────────────────────────────────────────────────────────────────

class AnimationEngine:
    """Controls the timed sequence of demo steps."""

    def __init__(self, callback_next_step: Callable):
        self.callback = callback_next_step
        self._running = False
        self._paused = False
        self._speed = 1.0
        self._current_step = 0
        self._total_steps = 0
        self._timer_id = None
        self._root = None

    def set_root(self, root: tk.Misc):
        self._root = root

    def set_total_steps(self, n: int):
        self._total_steps = n

    @property
    def current_step(self) -> int:
        return self._current_step

    @current_step.setter
    def current_step(self, v: int):
        self._current_step = max(0, min(v, self._total_steps - 1))

    @property
    def speed(self) -> float:
        return self._speed

    @speed.setter
    def speed(self, v: float):
        self._speed = max(0.1, min(4.0, v))

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_paused(self) -> bool:
        return self._paused

    def start(self):
        self._running = True
        self._paused = False
        self._schedule_next(0.5)

    def pause(self):
        self._paused = True
        if self._timer_id and self._root:
            self._root.after_cancel(self._timer_id)
            self._timer_id = None

    def resume(self):
        if self._paused:
            self._paused = False
            self._schedule_next(0.3)

    def stop(self):
        self._running = False
        self._paused = False
        if self._timer_id and self._root:
            self._root.after_cancel(self._timer_id)
            self._timer_id = None

    def go_to_step(self, step: int):
        self._current_step = max(0, min(step, self._total_steps - 1))
        self.callback(self._current_step)

    def _schedule_next(self, delay: float):
        if not self._running or self._paused or not self._root:
            return
        adjusted = delay / self._speed
        self._timer_id = self._root.after(int(adjusted * 1000), self._on_timer)

    def _on_timer(self):
        if not self._running or self._paused:
            return
        self._current_step += 1
        if self._current_step >= self._total_steps:
            self._running = False
            self.callback(self._current_step - 1, finished=True)
            return
        self.callback(self._current_step)
        self._schedule_next(0.3)


# ─────────────────────────────────────────────────────────────────────────────
# Canvas Drawing Methods
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolCanvas(tk.Canvas):
    """Enhanced Canvas class with IACP-specific drawing methods."""

    def __init__(self, master, **kwargs):
        super().__init__(master, bg="#FAFAFA", highlightthickness=0, **kwargs)
        self._anim_objects: List[int] = []
        self._text_objects: List[int] = []

    def clear_all(self):
        """Deletes all drawn objects."""
        self.delete("all")
        self._anim_objects.clear()
        self._text_objects.clear()

    def draw_agent(self, x: int, y: int, label: str, color: str = "#2196F3",
                   size: int = 40, eid_short: str = "") -> List[int]:
        """Draws an agent as a circle with label."""
        tags = []
        # Kreis
        o = self.create_oval(x - size, y - size, x + size, y + size,
                             fill=color, outline="#333", width=2, tags=("agent",))
        tags.append(o)
        # EID Text
        if eid_short:
            t = self.create_text(x, y, text=eid_short, fill="white",
                                 font=("Consolas", 7, "bold"), tags=("agent",))
            tags.append(t)
        # Label
        lbl = self.create_text(x, y + size + 15, text=label, fill="#333",
                               font=("Segoe UI", 9, "bold"), tags=("agent",))
        tags.append(lbl)
        return tags

    def draw_packet(self, x1: int, y1: int, x2: int, y2: int,
                    label: str = "", color: str = "#FF9800",
                    packet_type: str = "") -> int:
        """Draws an animated packet between two points."""
        mx, my = (x1 + x2) // 2, (y1 + y2) // 2
        # Rechteck für Paket
        r = self.create_rectangle(mx - 30, my - 12, mx + 30, my + 12,
                                  fill=color, outline="#333", width=1,
                                  tags=("packet",))
        # Typ-Label
        if packet_type:
            self.create_text(mx, my - 1, text=packet_type, fill="white",
                             font=("Consolas", 7, "bold"), tags=("packet",))
        # Beschriftung
        if label:
            self.create_text(mx, my + 20, text=label, fill="#555",
                             font=("Segoe UI", 7), tags=("packet",))
        return r

    def draw_arrow(self, x1: int, y1: int, x2: int, y2: int,
                   color: str = "#999", width: int = 2, dashed: bool = False,
                   label: str = "") -> List[int]:
        """Draws an arrow between two points."""
        tags = []
        style = (4, 4) if dashed else ()
        a = self.create_line(x1, y1, x2, y2, fill=color, width=width,
                             dash=style, arrow=tk.LAST, tags=("arrow",))
        tags.append(a)
        if label:
            mx, my = (x1 + x2) // 2, (y1 + y2) // 2
            l = self.create_text(mx, my - 12, text=label, fill=color,
                                 font=("Segoe UI", 7, "italic"), tags=("arrow",))
            tags.append(l)
        return tags

    def draw_state_machine(self, states: List[Tuple[str, str, int, int]],
                           current_state: str, phase_color: str) -> List[int]:
        """Draws a state machine with current state highlighted."""
        tags = []
        for name, color, x, y in states:
            is_current = (name == current_state)
            fill = phase_color if is_current else "#E0E0E0"
            outline = "#333" if is_current else "#999"
            w = 3 if is_current else 1
            r = self.create_rectangle(x - 55, y - 18, x + 55, y + 18,
                                      fill=fill, outline=outline, width=w,
                                      tags=("state",))
            tags.append(r)
            fg = "white" if is_current else "#666"
            t = self.create_text(x, y, text=name, fill=fg,
                                 font=("Consolas", 8, "bold"), tags=("state",))
            tags.append(t)
        return tags

    def draw_formula(self, x: int, y: int, formula: str, result: str = "",
                     color: str = "#333") -> List[int]:
        """Draws a mathematical formula."""
        tags = []
        t = self.create_text(x, y, text=formula, fill=color,
                             font=("Consolas", 11, "bold"), anchor="w",
                             tags=("formula",))
        tags.append(t)
        if result:
            r = self.create_text(x, y + 25, text=result, fill="#666",
                                 font=("Consolas", 9), anchor="w",
                                 tags=("formula",))
            tags.append(r)
        return tags

    def draw_quorum(self, cx: int, cy: int, radius: int, count: int = 7,
                    confirmed: int = 0, failed: int = 0) -> List[int]:
        """Draws a DHT quorum as a circle of nodes."""
        tags = []
        for i in range(count):
            angle = 2 * math.pi * i / count - math.pi / 2
            x = cx + int(radius * math.cos(angle))
            y = cy + int(radius * math.sin(angle))
            if i < confirmed:
                fill = "#4CAF50"
            elif i < confirmed + failed:
                fill = "#F44336"
            else:
                fill = "#BDBDBD"
            o = self.create_oval(x - 12, y - 12, x + 12, y + 12,
                                 fill=fill, outline="#333", width=1,
                                 tags=("quorum",))
            tags.append(o)
            n = self.create_text(x, y, text=str(i + 1), fill="white",
                                 font=("Consolas", 7, "bold"), tags=("quorum",))
            tags.append(n)
        return tags

    def draw_key_value(self, x: int, y: int, key: str, value: str,
                       color: str = "#E3F2FD") -> List[int]:
        """Draws a key-value pair as a card."""
        tags = []
        r = self.create_rectangle(x, y, x + 200, y + 40,
                                  fill=color, outline="#90CAF9", width=1,
                                  tags=("kv",))
        tags.append(r)
        k = self.create_text(x + 10, y + 10, text=key, fill="#1565C0",
                             font=("Consolas", 8, "bold"), anchor="nw",
                             tags=("kv",))
        tags.append(k)
        v = self.create_text(x + 10, y + 24, text=value, fill="#333",
                             font=("Consolas", 8), anchor="nw",
                             tags=("kv",))
        tags.append(v)
        return tags

    def draw_byte_visualization(self, x: int, y: int, data: str,
                                label: str = "", color: str = "#2196F3") -> List[int]:
        """Draws a byte representation (Hex)."""
        tags = []
        if label:
            l = self.create_text(x, y - 5, text=label, fill="#333",
                                 font=("Segoe UI", 8, "bold"), anchor="w",
                                 tags=("bytes",))
            tags.append(l)
        # Hex-Bytes als kleine Kästchen
        hex_str = data[:32]
        bx = x
        for i in range(0, len(hex_str), 2):
            if i >= 32:
                break
            byte_val = hex_str[i:i+2]
            r = self.create_rectangle(bx, y + 5, bx + 16, y + 22,
                                      fill=color, outline="#333", width=1,
                                      tags=("bytes",))
            tags.append(r)
            t = self.create_text(bx + 8, y + 13, text=byte_val, fill="white",
                                 font=("Consolas", 6, "bold"), tags=("bytes",))
            tags.append(t)
            bx += 18
        return tags

    def draw_chart_bar(self, x: int, y: int, width: int, height: int,
                       value: float, max_val: float = 1.0,
                       color: str = "#4CAF50", label: str = "") -> List[int]:
        """Draws a bar for metrics."""
        tags = []
        bar_h = int((value / max_val) * height)
        r = self.create_rectangle(x, y - bar_h, x + width, y,
                                  fill=color, outline="#333", width=1,
                                  tags=("chart",))
        tags.append(r)
        if label:
            l = self.create_text(x + width // 2, y + 10, text=label,
                                 fill="#333", font=("Segoe UI", 7),
                                 tags=("chart",))
            tags.append(l)
        return tags

    def draw_phase_transition(self, phase_num: int, phase_name: str,
                              color: Dict[str, str]):
        """Draws a phase transition screen."""
        self.clear_all()
        w = self.winfo_width() or 600
        h = self.winfo_height() or 400
        # Hintergrund
        self.create_rectangle(0, 0, w, h, fill=color["bg"], outline="")
        # Phase Nummer
        self.create_text(w // 2, h // 2 - 60, text=f"Phase {phase_num}",
                         fill=color["fg"], font=("Segoe UI", 28, "bold"))
        # Phase Name
        self.create_text(w // 2, h // 2, text=phase_name,
                         fill=color["accent"], font=("Segoe UI", 18))
        # Dekorative Linie
        self.create_line(w // 2 - 100, h // 2 + 30, w // 2 + 100, h // 2 + 30,
                         fill=color["accent"], width=2)
        # Continue hint
        self.create_text(w // 2, h // 2 + 60, text="\u25b6 Starting demo...",
                         fill=color["fg"], font=("Segoe UI", 12))

    def draw_completion(self, total_steps: int):
        """Draws the completion screen."""
        self.clear_all()
        w = self.winfo_width() or 600
        h = self.winfo_height() or 400
        # Hintergrund
        self.create_rectangle(0, 0, w, h, fill="#E8F5E9", outline="")
        # Checkmark
        self.create_text(w // 2, h // 2 - 60, text="\u2714",
                         fill="#4CAF50", font=("Segoe UI", 48))
        # Titel
        self.create_text(w // 2, h // 2, text="IACP Full Demo completed!",
                         fill="#2E7D32", font=("Segoe UI", 18, "bold"))
        # Statistik
        self.create_text(w // 2, h // 2 + 40,
                         text=f"{total_steps} Steps in 9 Phasen",
                         fill="#666", font=("Segoe UI", 12))
        self.create_text(w // 2, h // 2 + 65,
                         text="All IACP protocol stations successfully traversed.",
                         fill="#888", font=("Segoe UI", 10))


# ─────────────────────────────────────────────────────────────────────────────
# Demo-Steps-Definition (alle 49 Steps in 9 Phasen)
# ─────────────────────────────────────────────────────────────────────────────

def build_all_phases() -> List[Phase]:
    """Creates all 9 phases with a total of 43 demo steps."""

    phases = []

    # ── Phase 1: Identity & Registration (6 Steps) ──
    p1 = Phase(1, "Identity & Registration", PHASE_COLORS[1], [])
    p1.steps = [
        DemoStep(1, 1, "Generate EID Keypair",
                 "The agent generates an Ed25519 cryptographic keypair (32-byte Private Key, 32-byte Public Key).",
                 "crypto", 3.5, [
                     "Ed25519: 128-bit security level",
                     "Private Key: 32 bytes (CSPRNG)",
                     "Public Key: 32 bytes (EID = Public Key)",
                 ]),
        DemoStep(1, 2, "EID = Public Key",
                 "The Ephemeral Agent Identity (EID) is identical to the Ed25519 Public Key – a self-certifying identifier.",
                 "identity", 3.0, [
                     "EID = Public_Key (32 bytes)",
                     "Self-certifying: signature verification without certificate",
                     "No routing metadata in the EID",
                 ]),
        DemoStep(1, 3, "IAT Generation (Instance Authentication Token)",
                 "The LL-Entity generates a 32-byte random token für die lokale AAI-Isolation auf dem Host.",
                 "crypto", 3.0, [
                     "IAT = CSPRNG(256 bit)",
                     "Prevents session hijacking between AAIs",
                     "Included in every local frame",
                 ]),
        DemoStep(1, 4, "ERP_INIT – Local Initialization",
                 "The AAI sends an ERP_INIT frame with a 32-byte initialization nonce to the LL-Entity.",
                 "network", 3.5, [
                     "Frame: ERP_INIT (Type 0x11)",
                     "Nonce N_init: 32 bytes CSPRNG",
                     "Local loopback channel (Unix Socket / Shared Memory)",
                 ]),
        DemoStep(1, 5, "ERP_ALLOC – EID Assignment",
                 "The LL-Entity responds with ERP_ALLOC: confirms the nonce, sends the assigned EID and Local_IAT.",
                 "network", 3.5, [
                     "Frame: ERP_ALLOC (Type 0x14)",
                     "Contains: N_init, Source_EID, Local_IAT",
                     "AAI verifies nonce match",
                 ]),
        DemoStep(1, 6, "ERP_REGISTER – Global Registration",
                 "The LL-Entity registers the EID in the DHT overlay: signed mapping EID → IP address + Generation Counter.",
                 "network", 4.0, [
                     "Frame: ERP_REGISTER (Type 0x15)",
                     "Signature: Ed25519 over EID || IP || Gen_Counter",
                     "DHT Quorum (7 nodes) validates the registration",
                     "State: UNBOUND → ALLOCATED → TRANSITION → BOUND",
                 ]),
    ]
    phases.append(p1)

    # ── Phase 2: Discovery & Peer Finding (6 Steps) ──
    p2 = Phase(2, "Discovery & Peer Finding", PHASE_COLORS[2], [])
    p2.steps = [
        DemoStep(2, 1, "Create Discovery Space (DS_ANNOUNCE)",
                 "A curator creates a Discovery Space with namespace, topic and version – stored in the DHT.",
                 "discovery", 3.5, [
                     "DS_ID = SHA-256('ds:' || Namespace || Topic || Version)",
                     "Curator signs DS_ANNOUNCE with Ed25519",
                     "TTL: 24 hours in DHT",
                 ]),
        DemoStep(2, 2, "Join Discovery Space (DS_JOIN)",
                 "An agent registers in the Discovery Space by publishing a DS_JOIN record.",
                 "discovery", 3.0, [
                     "DS_JOIN: EID + Timestamp + Ed25519 signature",
                     "TTL: 1 hour (must be refreshed)",
                     "Curator can prune stale entries",
                 ]),
        DemoStep(2, 3, "Anonymous Discovery – PoW Calculation",
                 "The searching agent computes a Hashcash Proof-of-Work (leading zero bits) für die DISCOVERY_REQ.",
                 "crypto", 4.0, [
                     "Hashcash: SHA-256 with nonce variation",
                     "Difficulty: D_req = D_base + floor(gamma * Queue_Current / Queue_Max)",
                     "Default D_base = 16 bits, Maximum 32 bits",
                 ]),
        DemoStep(2, 4, "Send DISCOVERY_REQ",
                 "The agent sends an anonymous discovery request with ephemeral X25519 Public Key and PoW token.",
                 "network", 3.5, [
                     "Frame: DISCOVERY_REQ (Type 0x01)",
                     "Contains: Ephemeral Public Key, PoW Nonce, Timestamp",
                     "No own EID revealed",
                 ]),
        DemoStep(2, 5, "DISCOVERY_RES – Encrypted Response",
                 "The responder validates the PoW, computes an X25519 shared secret and encrypts its EID with AES-GCM.",
                 "network", 4.0, [
                     "Frame: DISCOVERY_RES (Type 0x02)",
                     "ECDH: X25519(Responder_Private, Ephemeral_Public)",
                     "AES-GCM-256: EID encrypted + Auth Tag",
                 ]),
        DemoStep(2, 6, "EID Decryption & Identification",
                 "The initiator decrypts the peer EID using its ephemeral private key and now knows the identity.",
                 "crypto", 3.0, [
                     "ECDH: X25519(Ephemeral_Private, Responder_Public)",
                     "AES-GCM-256: decryption + MAC verification",
                     "Both sides now know each other EIDs",
                 ]),
    ]
    phases.append(p2)

    # ── Phase 3: Session Establishment (6 Steps) ──
    p3 = Phase(3, "Session Establishment (PSS)", PHASE_COLORS[3], [])
    p3.steps = [
        DemoStep(3, 1, "Reputation Check Before Session",
                 "The initiator checks the target EID reputation: R_State(t) = 0.12*M(t) + 0.88*R_State(t-1).",
                 "formula", 3.5, [
                     "R_Threshold = 0.7 (default)",
                     "M(t) = 0.45*S_Verify + 0.35*A_Telemetry - 0.20*PoM_Score",
                     "If R_State < 0.3: session is rejected",
                 ]),
        DemoStep(3, 2, "PSS_INIT with I-Cookie",
                 "The initiator sends PSS_INIT with an 8-byte random cookie (I-Cookie) and Ed25519 signature.",
                 "session", 3.5, [
                     "Frame: PSS_INIT (Type 0x08)",
                     "I-Cookie: 8 bytes CSPRNG",
                     "R-Cookie: 0x0000000000000000 (not yet set)",
                     "Signed with initiator private key",
                 ]),
        DemoStep(3, 3, "PSS_NEG with R-Cookie",
                 "The responder verifies the signature, generates its own 8-byte cookie (R-Cookie) and sends PSS_NEG.",
                 "session", 3.5, [
                     "Frame: PSS_NEG (Type 0x0A)",
                     "Contains: I-Cookie + R-Cookie",
                     "Optional: Proposed SFC Conditions Block (32 bytes)",
                     "Signed with responder private key",
                 ]),
        DemoStep(3, 4, "PSS_ACK – Session Ratification",
                 "The initiator confirms the handshake with PSS_ACK. The session enters STATE_ESTABLISHED.",
                 "session", 3.0, [
                     "Frame: PSS_ACK (Type 0x09)",
                     "Contains: I-Cookie + R-Cookie (invariant)",
                     "State: STATE_HEARING → STATE_ESTABLISHED",
                     "All subsequent packets carry [I-Cookie || R-Cookie]",
                 ]),
        DemoStep(3, 5, "SFC Negotiation (Session Federation Contract)",
                 "Optional: Both sides negotiate resource limits, permission scopes and execution boundaries.",
                 "session", 3.5, [
                     "SFC bit in PSS_INIT Capabilities Flags (bit 0)",
                     "PSS_NEG: Proposed SFC Conditions Block (32 Byte)",
                     "PSS_ACK: Ratification with Agreed Capabilities",
                 ]),
        DemoStep(3, 6, "Session Key Derivation",
                 "The AES-GCM-256 session key is derived from I-Cookie, R-Cookie and both EIDs (HKDF-SHA256).",
                 "crypto", 3.0, [
                     "HKDF-SHA256(I-Cookie || R-Cookie || Sorted_EIDs)",
                     "Salt: 'IACP_SALT_v1'",
                     "Info: 'IACP_SESSION_KEY'",
                     "Output: 32-byte AES-GCM-256 key",
                 ]),
    ]
    phases.append(p3)

    # ── Phase 4: Kommunikation & State (4 Steps) ──
    p4 = Phase(4, "Communication & State", PHASE_COLORS[4], [])
    p4.steps = [
        DemoStep(4, 1, "PSS_DATA_STREAM – Encrypted Communication",
                 "Payload data is sent as PSS_DATA_STREAM frames encrypted with AES-GCM-256 and a sequence number.",
                 "session", 3.5, [
                     "Frame: PSS_DATA_STREAM (Type 0x0B)",
                     "AES-GCM-256: Nonce (12 bytes) + Ciphertext + Auth Tag",
                     "Sequence Number: monotonically increasing (8 bytes)",
                     "Rolling State Reconciliation Hash (32 bytes)",
                 ]),
        DemoStep(4, 2, "Create ESE Global Point",
                 "A Global Point (GP) is computed as SHA-256(EID || Tag) and is WAN-routable.",
                 "state", 3.0, [
                     "GP_Coordinate = SHA-256(Parent_EID || Endpoint_Tag)",
                     "Global Points sind über das Internet erreichbar",
                     "ESE data is ephemeral (TTL: 1 hour)",
                 ]),
        DemoStep(4, 3, "Create ESE Local Point",
                 "A Local Point (LP) is only visible on the local network and not discoverable over WAN.",
                 "state", 2.5, [
                     "Local Points: only visible on LAN",
                     "No DHT registration for LPs",
                     "Isolation by default",
                 ]),
        DemoStep(4, 4, "Sequence Vector Reconciliation",
                 "Both sides reconcile sequence states: each frame has a monotonically increasing ID + cryptographic hash.",
                 "formula", 3.5, [
                     "Sequence Vector: (Initiator_Seq, Responder_Seq)",
                     "Reconciliation on connection recovery",
                     "Detects packet loss and replay attacks",
                 ]),
    ]
    phases.append(p4)

    # ── Phase 5: Mobilität & Fehlertoleranz (6 Steps) ──
    p5 = Phase(5, "Mobility & Fault Tolerance", PHASE_COLORS[5], [])
    p5.steps = [
        DemoStep(5, 1, "Detect Network Change",
                 "The LL-Entity detects an interface change (e.g. WiFi → Mobile) and briefly locks the outbound queue.",
                 "mobility", 3.0, [
                     "Interface migration detected",
                     "Outbound queue briefly locked",
                     "Generation counter is incremented",
                 ]),
        DemoStep(5, 2, "Create MIGRATION_VECTOR",
                 "The LL-Entity creates a signed MIGRATION_VECTOR with new IP, new port and incremented Generation Counter.",
                 "mobility", 3.5, [
                     "Frame: MIGRATION_VECTOR (Type 0x17)",
                     "Gen_Counter_New = Gen_Counter_Old + 1",
                     "Signatur: Ed25519(EID || New_IP || Gen_Counter_New)",
                 ]),
        DemoStep(5, 3, "Distribute MIGRATION_VECTOR",
                 "Der MIGRATION_VECTOR wird an das DHT-Quorum und an alle activeen Peers im Session-Table gesendet.",
                 "network", 3.5, [
                     "Multicast to DHT quorum (7 nodes)",
                     "Asynchronous mirroring to all PSS peers",
                     "Cache invalidation at receivers",
                 ]),
        DemoStep(5, 4, "Generation Counting – Cache Invalidation",
                 "Receiving nodes check: Packet_Gen > Cache_Gen → Update. Packet_Gen < Cache_Gen → Drop (Stale).",
                 "formula", 3.5, [
                     "Packet_Gen > Cache_Gen: update mapping",
                     "Packet_Gen == Cache_Gen: process normally",
                     "Packet_Gen < Cache_Gen: silent drop",
                 ]),
        DemoStep(5, 5, "Create Forwarding Ticket (DHT_TICKET_STORE)",
                 "Before going offline, an encrypted forwarding ticket is stored in the DHT: AES-GCM with ECDH key.",
                 "dht", 4.0, [
                     "Frame: DHT_TICKET_STORE (Type 0x05)",
                     "ECDH: X25519(Ephemeral_Private, Peer_Public)",
                     "AES-GCM-256: Locator (20 bytes) encrypted",
                     "KEY = SHA-256(EID_Agent) in DHT",
                 ]),
        DemoStep(5, 6, "Retrieve Forwarding Ticket (DHT_TICKET_QUERY)",
                 "A peer retrieves the forwarding ticket after the agent returns and decrypts the new locator.",
                 "dht", 3.5, [
                     "Frame: DHT_TICKET_QUERY (Type 0x06)",
                     "Response: DHT_TICKET_RESP (Type 0x07)",
                     "Decryption with ECDH shared secret",
                     "State synchronization via sequence vectors",
                 ]),
    ]
    phases.append(p5)

    # ── Phase 6: Governance & Slashing (5 Steps) ──
    p6 = Phase(6, "Governance & Slashing", PHASE_COLORS[6], [])
    p6.steps = [
        DemoStep(6, 1, "Proof of Malfeasance – Double-Signing erkennen",
                 "An observer sees two different signed mappings with the same Generation Counter from the same EID.",
                 "governance", 4.0, [
                     "Fragment A: IP=10.0.0.1, Gen=5, Sig=0xABC",
                     "Fragment B: IP=10.0.0.2, Gen=5, Sig=0xDEF",
                     "Same EID, same Gen_Counter, different IPs",
                     "→ Equivocation (double signing)",
                 ]),
        DemoStep(6, 2, "Create & Submit PoM Ticket",
                 "The observer creates a PoM ticket with both fragments and submits it to the DHT quorum.",
                 "governance", 3.5, [
                     "PoM_Ticket = {Target_EID, Fragment_A, Fragment_B, Timestamp}",
                     "Quorum checks: both signatures valid against Target_EID?",
                     "Quorum checks: fragments not identical?",
                     "Consensus: m = 4 out of 7 nodes required",
                 ]),
        DemoStep(6, 3, "2PSE – STATE_CHALLENGED (Escrow Window)",
                 "The quorum sets the target to STATE_CHALLENGED. An escrow window of 1 hour begins.",
                 "governance", 3.5, [
                     "State: STATE_NOMINAL → STATE_CHALLENGED",
                     "Escrow Window: T_escrow = 1 Stunde",
                     "Node can submit a counter-proof",
                     "Multi-path routing is enforced",
                 ]),
        DemoStep(6, 4, "Counter-Proof oder Slashing",
                 "If the accused node submits a valid counter-proof, the escrow is lifted. Otherwise: STATE_SLASHED.",
                 "governance", 3.5, [
                     "Counter-Proof: PSS_REVOCATION_REBUTTAL (Type 0x13)",
                     "On success: STATE_NOMINAL restored",
                     "On expiry: STATE_SLASHED irrevocable",
                     "EID is added to revocation bloom filter",
                 ]),
        DemoStep(6, 5, "Reputation Penalties & Rehabilitation",
                 "After slashing, reputation drops drastically. Old PoM tickets decay with 50% weight after 30 days.",
                 "formula", 3.5, [
                     "PoM_Score(t) = min(1.0, PoM_Count(t) / 5)",
                     "Decay: 50% weight after 30 days",
                     "Rehabilitation: 7 days without new PoM → Reset",
                     "R_State < 0.3: session block + max PoW",
                 ]),
    ]
    phases.append(p6)

    # ── Phase 7: Cross-Domain & Attestation (3 Steps) ──
    p7 = Phase(7, "Cross-Domain & Attestation", PHASE_COLORS[7], [])
    p7.steps = [
        DemoStep(7, 1, "Retrieve Trust Anchor Document",
                 "Agent A fragt das Trust Anchor Document von Domain B aus dem DHT an: KEY = SHA-256('iacp-federation:' || Domain_ID).",
                 "dht", 3.5, [
                     "Frame: FED_TRUST_ANCHOR_REQ (Type 0x1C)",
                     "Response: FED_TRUST_ANCHOR_RES (Type 0x1D)",
                     "Trust Anchor: Ed25519-signiertes JSON-Dokument",
                     "Enthält: Trust Anchors, Namespace Root, Federation Policy",
                 ]),
        DemoStep(7, 2, "Federation Gateway – Cross-Domain Trust",
                 "A Federation Gateway mediates between two trust domains when direct exchange is not possible.",
                 "network", 3.5, [
                     "Gateway validates both trust anchors",
                     "Forwards Trust Anchor B to Domain A",
                     "PSS wird mit Cross-Domain-Flag etabliert",
                     "Trust Anchor Fingerprint im PSS_INIT",
                 ]),
        DemoStep(7, 3, "TEE Remote Attestation (RATS/EAT)",
                 "The agent proves its execution environment: Intel TDX/AMD SEV-SNP/Intel SGX evidence is verified.",
                 "crypto", 4.0, [
                     "Frame: PSS_ATTEST (Type 0x23)",
                     "Evidence: EAT/CWT/TPM Quote/TDX Report/SEV-SNP Report",
                     "Verifier checks: signature, freshness (300s), measurements",
                     "Attestation Result: Caching mit 300s TTL",
                 ]),
    ]
    phases.append(p7)

    # ── Phase 8: Session Termination (3 Steps) ──
    p8 = Phase(8, "Session Termination", PHASE_COLORS[8], [])
    p8.steps = [
        DemoStep(8, 1, "Graceful Teardown (PSS_TEARDOWN)",
                 "The initiator flushes all outbound pipelines, sends a terminal data checksum and the PSS_TEARDOWN frame.",
                 "termination", 3.5, [
                     "Frame: PSS_TEARDOWN (Type 0x0C)",
                     "Final data checksum is committed",
                     "Waits for reciprocal verification ACK",
                     "State: STATE_ESTABLISHED → STATE_CLOSED",
                 ]),
        DemoStep(8, 2, "PSS_REVOCATION_PUBLISH (Forced Teardown)",
                 "On protocol violation, PSS_REVOCATION_PUBLISH is sent immediately – inklusive PoM-Ticket fürs Directory.",
                 "termination", 3.5, [
                     "Frame: PSS_REVOCATION_PUBLISH (Type 0x0D)",
                     "Local session is immediately destroyed",
                     "PoM-Ticket wird an globales Directory gepusht",
                     "Automatic blacklisting + slashing routine",
                 ]),
        DemoStep(8, 3, "EID Revocation & Hot-Docking",
                 "On compromise, a Revocation Certificate is sent to the quorum. State is migrated to backup host.",
                 "mobility", 4.0, [
                     "Revocation Certificate: Ed25519-signiert",
                     "DHT-Eintrag: SHA-256('revocation:' || EID)",
                     "TTL: 30 days, then EID can be reused",
                     "Hot-Docking: CBOR state → zlib → AES-GCM → Backup",
                 ]),
    ]
    phases.append(p8)

    # ── Phase 9: DHI Content Processing (4 Steps) ──
    p9 = Phase(9, "DHI Content Processing", PHASE_COLORS[9], [])
    p9.steps = [
        DemoStep(9, 1, "ANML Discovery Pipeline",
                 "The DHI traverses the ingestion pipeline: DNS SRV → /.well-known/anml → HTTP Link Header.",
                 "content", 3.5, [
                     "1. DNS SRV: _anml._tcp.{domain}",
                     "2. Well-Known: /.well-known/anml",
                     "3. HTTP Link Header: rel='alternate' type='application/anml+xml'",
                 ]),
        DemoStep(9, 2, "HRP-Berechnung (Heuristic Relevancy Probability)",
                 "Each candidate URI gets a probability: HRP(n) = 0.45*S + 0.35*R + 0.20*C.",
                 "formula", 3.5, [
                     "S: Semantic Similarity (Jaro-Winkler + BM25)",
                     "R: Reputation Weight (DHT curator verification)",
                     "C: Contextual History (past successes)",
                     "Default: w1=0.45, w2=0.35, w3=0.20",
                 ]),
        DemoStep(9, 3, "APE Threshold Filter (Automated Pipeline Extraction)",
                 "The APE engine filters: HRP(n) < Θ=0.60 → pruning. HRP(n) >= 0.85 -> Fast Path. Otherwise -> Async Queue.",
                 "content", 3.5, [
                     "Θ = 0.60 (Default Threshold)",
                     "HRP ≥ 0.85: Dedizierte TCP/IACP-Verbindung",
                     "Θ ≤ HRP < 0.85: Priorisierte Async-Queue",
                     "DAG Path Optimization: O(e log v)",
                 ]),
        DemoStep(9, 4, "EVM Content Equivalence (EVM ≤ 0.001)",
                 "The DHI checks mathematical equivalence between ANML and HTML: Cross-Entropy + SHA-256 hash comparison.",
                 "formula", 4.0, [
                     "EVM = H(p,q) - H(p) ≤ 0.001",
                     "Unicode NFC normalization + whitespace collapse",
                     "SHA-256: Depth-First, Left-to-Right Text-Extraktion",
                     "If EVM > 0.001: Legacy Path Fallback (HCO)",
                 ]),
    ]
    phases.append(p9)

    return phases


# ─────────────────────────────────────────────────────────────────────────────
# Main Class: DemoVisualizer
# ─────────────────────────────────────────────────────────────────────────────

class DemoVisualizer:
    """Vollständige grafische IACP-Demo mit Canvas-Animationen."""

    def __init__(self, parent: tk.Tk):
        self.parent = parent
        self.phases = build_all_phases()
        self.total_steps = sum(len(p.steps) for p in self.phases)
        self._current_phase = 0
        self._current_step_in_phase = 0
        self._global_step = 0
        self._anim_phase = "idle"  # idle | phase_transition | step | completion

        # Engine
        self.engine = AnimationEngine(self._on_step_change)
        self.engine.set_total_steps(self.total_steps)

        # Window
        self.window: Optional[tk.Toplevel] = None
        self.canvas: Optional[ProtocolCanvas] = None
        self._build_ui()

    def _build_ui(self):
        """Erstellt das Demo-Fenster."""
        self.window = tk.Toplevel(self.parent)
        self.window.title("IACP Full Demo – Graphical Protocol Walkthrough")
        self.window.geometry("1300x850")
        self.window.minsize(1000, 700)

        # Haupt-Container
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill="both", expand=True)

        # ── Top: Header ──
        header = ttk.Frame(main_frame)
        header.pack(fill="x", padx=10, pady=(10, 5))

        self.header_title = tk.StringVar(value="IACP Full Demo")
        ttk.Label(header, textvariable=self.header_title,
                  font=("Segoe UI", 16, "bold")).pack(side="left")

        self.header_progress = tk.StringVar(value="Step 0 / 0")
        ttk.Label(header, textvariable=self.header_progress,
                  font=("Segoe UI", 10), foreground="#666").pack(side="right")

        # ── Main Content: Phase Nav + Canvas + Log ──
        content = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        content.pack(fill="both", expand=True, padx=10, pady=5)

        # ── Left: Phase Navigation ──
        nav_frame = ttk.LabelFrame(content, text=" Phases ", width=180)
        content.add(nav_frame, weight=0)

        self.phase_buttons: List[ttk.Button] = []
        self.phase_labels: List[tk.StringVar] = []
        nav_canvas = tk.Canvas(nav_frame, width=170, highlightthickness=0)
        nav_scroll = ttk.Scrollbar(nav_frame, orient="vertical", command=nav_canvas.yview)
        nav_inner = ttk.Frame(nav_canvas)

        nav_canvas.create_window((0, 0), window=nav_inner, anchor="nw")
        nav_canvas.configure(yscrollcommand=nav_scroll.set)

        for i, phase in enumerate(self.phases):
            color = phase.color
            frame = tk.Frame(nav_inner, bg=color["bg"], bd=1, relief="solid")
            frame.pack(fill="x", padx=5, pady=3)

            # Phase-Header
            hdr = tk.Frame(frame, bg=color["bg"])
            hdr.pack(fill="x", padx=5, pady=(5, 2))
            tk.Label(hdr, text=f"Phase {phase.number}", bg=color["bg"],
                     fg=color["fg"], font=("Segoe UI", 8, "bold")).pack(side="left")
            tk.Label(hdr, text=f"{len(phase.steps)} Steps", bg=color["bg"],
                     fg=color["fg"], font=("Segoe UI", 7)).pack(side="right")

            tk.Label(frame, text=phase.name, bg=color["bg"], fg=color["fg"],
                     font=("Segoe UI", 8), wraplength=150).pack(fill="x", padx=5, pady=(0, 5))

            # Step-Liste
            step_var = tk.StringVar(value="")
            tk.Label(frame, textvariable=step_var, bg=color["bg"], fg="#666",
                     font=("Consolas", 7)).pack(fill="x", padx=5, pady=(0, 5))
            self.phase_labels.append(step_var)

        nav_canvas.pack(side="left", fill="both", expand=True)
        nav_scroll.pack(side="right", fill="y")

        # ── Center: Canvas + Detail ──
        center_frame = ttk.Frame(content)
        content.add(center_frame, weight=3)

        # Canvas
        canvas_frame = ttk.LabelFrame(center_frame, text=" Visualization ")
        canvas_frame.pack(fill="both", expand=True)

        self.canvas = ProtocolCanvas(canvas_frame, height=400)
        self.canvas.pack(fill="both", expand=True, padx=5, pady=5)

        # Step-Titel + Beschreibung
        detail_frame = ttk.Frame(center_frame)
        detail_frame.pack(fill="x", pady=(5, 0))

        self.step_title_var = tk.StringVar(value="Ready")
        ttk.Label(detail_frame, textvariable=self.step_title_var,
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")

        self.step_desc_var = tk.StringVar(value="Click 'Start' to begin the demo.")
        ttk.Label(detail_frame, textvariable=self.step_desc_var,
                  font=("Segoe UI", 9), foreground="#555", wraplength=600,
                  justify="left").pack(anchor="w", pady=(2, 5))

        # ── Right: Log + Metriken ──
        right_frame = ttk.Frame(content)
        content.add(right_frame, weight=1)

        # Log
        log_frame = ttk.LabelFrame(right_frame, text=" Step-Log ")
        log_frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(log_frame, font=("Consolas", 8), height=12,
                                width=40, state="disabled", bg="#FAFAFA")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        log_scroll.pack(side="right", fill="y", pady=5)

        # Tags für Log
        self.log_text.tag_configure("phase", foreground="#1565C0", font=("Consolas", 8, "bold"))
        self.log_text.tag_configure("step", foreground="#333")
        self.log_text.tag_configure("detail", foreground="#888")
        self.log_text.tag_configure("highlight", foreground="#4CAF50", font=("Consolas", 8, "bold"))

        # Metriken
        metrics_frame = ttk.LabelFrame(right_frame, text=" Live Metrics ")
        metrics_frame.pack(fill="x", pady=(5, 0))

        self.metrics_vars: Dict[str, tk.StringVar] = {}
        metrics = [
            ("phase", "Phase:"),
            ("step", "Step:"),
            ("progress", "Progress:"),
            ("speed", "Speed:"),
            ("status", "Status:"),
        ]
        for key, label in metrics:
            row = ttk.Frame(metrics_frame)
            row.pack(fill="x", padx=5, pady=2)
            ttk.Label(row, text=label, width=12, anchor="e",
                      font=("Segoe UI", 8)).pack(side="left")
            var = tk.StringVar(value="-")
            ttk.Label(row, textvariable=var, font=("Consolas", 8)).pack(side="left", padx=5)
            self.metrics_vars[key] = var

        # ── Bottom: Controls ──
        ctrl_frame = ttk.Frame(main_frame)
        ctrl_frame.pack(fill="x", padx=10, pady=(5, 10))

        # Buttons
        self.btn_start = ttk.Button(ctrl_frame, text="▶ Start", command=self._on_start)
        self.btn_start.pack(side="left", padx=2)

        self.btn_pause = ttk.Button(ctrl_frame, text="⏸ Pause", command=self._on_pause,
                                    state="disabled")
        self.btn_pause.pack(side="left", padx=2)

        self.btn_stop = ttk.Button(ctrl_frame, text="⏹ Stop", command=self._on_stop,
                                   state="disabled")
        self.btn_stop.pack(side="left", padx=2)

        self.btn_reset = ttk.Button(ctrl_frame, text="↺ Reset", command=self._on_reset)
        self.btn_reset.pack(side="left", padx=2)

        # Speed
        ttk.Label(ctrl_frame, text="Speed:").pack(side="left", padx=(20, 5))
        self.speed_var = tk.DoubleVar(value=1.0)
        speed_scale = ttk.Scale(ctrl_frame, from_=0.25, to=4.0, variable=self.speed_var,
                                orient=tk.HORIZONTAL, length=120,
                                command=self._on_speed_change)
        speed_scale.pack(side="left")
        self.speed_label = tk.StringVar(value="1.0x")
        ttk.Label(ctrl_frame, textvariable=self.speed_label, width=5).pack(side="left", padx=2)

        # Step Navigation
        ttk.Label(ctrl_frame, text="Step:").pack(side="left", padx=(20, 5))
        self.step_nav_var = tk.IntVar(value=0)
        step_nav = ttk.Spinbox(ctrl_frame, from_=0, to=self.total_steps - 1,
                               textvariable=self.step_nav_var, width=5,
                               command=self._on_step_nav)
        step_nav.pack(side="left")
        ttk.Button(ctrl_frame, text="Go to", command=self._on_step_nav).pack(side="left", padx=2)

        # Progress Bar
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var,
                                             maximum=self.total_steps)
        self.progress_bar.pack(fill="x", padx=10, pady=(0, 5))

        # Status
        self.status_var = tk.StringVar(value="Ready. Press 'Start' for the full demo.")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var,
                               relief="sunken", anchor="w", padding=(5, 2))
        status_bar.pack(fill="x")

        # Engine-Root setzen
        self.engine.set_root(self.window)

    # ─────────────────────────────────────────────────────────────────────────
    # Controls
    # ─────────────────────────────────────────────────────────────────────────

    def _on_start(self):
        """Starts the demo."""
        self._reset_state()
        self.engine.start()
        self.btn_start.config(state="disabled")
        self.btn_pause.config(state="normal")
        self.btn_stop.config(state="normal")
        self.status_var.set("Demo running...")

    def _on_pause(self):
        """Pauses/Resumes the demo."""
        if self.engine.is_paused:
            self.engine.resume()
            self.btn_pause.config(text="⏸ Pause")
            self.status_var.set("Demo running...")
        else:
            self.engine.pause()
            self.btn_pause.config(text="▶ Weiter")
            self.status_var.set("Paused")

    def _on_stop(self):
        """Stops the demo."""
        self.engine.stop()
        self._set_controls_idle()
        self.status_var.set("Demo stopped.")

    def _on_reset(self):
        """Resets the demo."""
        self.engine.stop()
        self._reset_state()
        self._set_controls_idle()
        self.canvas.clear_all()
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state="disabled")
        self.step_title_var.set("Ready")
        self.step_desc_var.set("Click 'Start' to begin the demo.")
        self.header_progress.set("Step 0 / 0")
        self.progress_var.set(0)
        self.status_var.set("Reset. Press 'Start'.")

    def _on_speed_change(self, val):
        """Changes the speed."""
        speed = float(val)
        self.engine.speed = speed
        self.speed_label.set(f"{speed:.1f}x")

    def _on_step_nav(self):
        """Navigates to a specific step."""
        step = self.step_nav_var.get()
        if 0 <= step < self.total_steps:
            self.engine.stop()
            self._global_step = step
            self._render_step(step)
            self._update_ui_for_step(step)
            self.status_var.set(f"Bei Step {step + 1}/{self.total_steps}")

    def _set_controls_idle(self):
        """Sets controls to idle state."""
        self.btn_start.config(state="normal")
        self.btn_pause.config(state="disabled", text="⏸ Pause")
        self.btn_stop.config(state="disabled")

    def _reset_state(self):
        """Resets internal state."""
        self._current_phase = 0
        self._current_step_in_phase = 0
        self._global_step = 0
        self._anim_phase = "idle"
        self.canvas.clear_all()
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state="disabled")

    # ─────────────────────────────────────────────────────────────────────────
    # Step-Rendering
    # ─────────────────────────────────────────────────────────────────────────

    def _on_step_change(self, step_idx: int, finished: bool = False):
        """Callback from AnimationEngine on step change."""
        if finished:
            self._render_completion()
            self._set_controls_idle()
            self.status_var.set("Demo completed!")
            return
        self._global_step = step_idx
        self._render_step(step_idx)
        self._update_ui_for_step(step_idx)

    def _render_step(self, step_idx: int):
        """Renders a specific step on the canvas."""
        # Finde Phase und Step
        cum = 0
        for pi, phase in enumerate(self.phases):
            if step_idx < cum + len(phase.steps):
                si = step_idx - cum
                step = phase.steps[si]
                self._current_phase = pi
                self._current_step_in_phase = si
                break
            cum += len(phase.steps)
        else:
            return

        # Prüfe ob Phasen-Übergang nötig
        if self._anim_phase != "phase_transition" and self._current_step_in_phase == 0:
            self._render_phase_transition(self.phases[self._current_phase])
            self._anim_phase = "phase_transition"
            # Nach 2 Sekunden den eigentlichen Step rendern
            self.window.after(2000, lambda: self._render_step_content(step))
            return

        self._render_step_content(step)

    def _render_phase_transition(self, phase: Phase):
        """Draws the phase transition screen."""
        self.canvas.draw_phase_transition(phase.number, phase.name, phase.color)
        self._log(f"── Phase {phase.number}: {phase.name} ──", "phase")

    def _render_step_content(self, step: DemoStep):
        """Draws the content of a step."""
        self.canvas.clear_all()
        self._anim_phase = "step"

        phase = self.phases[self._current_phase]
        color = phase.color

        # Hintergrund
        w = self.canvas.winfo_width() or 600
        h = self.canvas.winfo_height() or 400
        self.canvas.create_rectangle(0, 0, w, h, fill="#FAFAFA", outline="")

        # Step-Titel oben
        self.canvas.create_text(20, 20, text=f"{step.icon}  {step.title}",
                                fill="#333", font=("Segoe UI", 14, "bold"), anchor="nw")

        # Kategorie-Badge
        badge_colors = {
            "crypto": "#E3F2FD", "network": "#FFF3E0", "state": "#E8F5E9",
            "formula": "#F3E5F5", "dht": "#E0F7FA", "governance": "#FFEBEE",
            "session": "#E8F5E9", "discovery": "#F3E5F5", "mobility": "#FFF3E0",
            "termination": "#ECEFF1", "content": "#FFFDE7", "identity": "#E3F2FD",
        }
        badge_fg = {
            "crypto": "#1565C0", "network": "#E65100", "state": "#2E7D32",
            "formula": "#7B1FA2", "dht": "#00838F", "governance": "#C62828",
            "session": "#2E7D32", "discovery": "#7B1FA2", "mobility": "#E65100",
            "termination": "#37474F", "content": "#F9A825", "identity": "#1565C0",
        }
        bc = badge_colors.get(step.category, "#E0E0E0")
        bf = badge_fg.get(step.category, "#333")
        self.canvas.create_rectangle(w - 120, 15, w - 15, 35,
                                     fill=bc, outline=bf, width=1)
        self.canvas.create_text(w - 67, 25, text=step.category.upper(),
                                fill=bf, font=("Consolas", 8, "bold"))

        # Detail-Box
        detail_y = 50
        self.canvas.create_rectangle(20, detail_y, w - 20, detail_y + 30 + 18 * len(step.detail_lines),
                                     fill="#F5F5F5", outline="#E0E0E0", width=1)
        for i, line in enumerate(step.detail_lines):
            self.canvas.create_text(30, detail_y + 10 + 18 * i, text=f"• {line}",
                                    fill="#555", font=("Segoe UI", 9), anchor="nw")

        # Phasen-spezifische Visualisierung
        viz_y = detail_y + 40 + 18 * len(step.detail_lines)
        self._render_category_visualization(step, w, h, viz_y, color)

        # Log
        self._log(f"{step.icon} {step.title}", "step")
        for line in step.detail_lines:
            self._log(f"  • {line}", "detail")

    def _render_category_visualization(self, step: DemoStep, w: int, h: int,
                                        y_start: int, color: Dict[str, str]):
        """Draws category-specific visualizations."""
        cx = w // 2

        if step.category == "crypto":
            # Key visualization
            self.canvas.create_text(cx - 100, y_start, text="Private Key",
                                    fill="#E65100", font=("Segoe UI", 9, "bold"))
            self.canvas.create_rectangle(cx - 120, y_start + 15, cx - 20, y_start + 45,
                                         fill="#FFF3E0", outline="#FF9800", width=2)
            self.canvas.create_text(cx - 70, y_start + 30, text="[32 bytes CSPRNG]",
                                    fill="#E65100", font=("Consolas", 7))

            self.canvas.create_text(cx + 20, y_start, text="Public Key = EID",
                                    fill="#1565C0", font=("Segoe UI", 9, "bold"))
            self.canvas.create_rectangle(cx, y_start + 15, cx + 100, y_start + 45,
                                         fill="#E3F2FD", outline="#2196F3", width=2)
            self.canvas.create_text(cx + 50, y_start + 30, text="[32 bytes Ed25519]",
                                    fill="#1565C0", font=("Consolas", 7))

            # Pfeil
            self.canvas.create_line(cx - 20, y_start + 30, cx, y_start + 30,
                                    fill="#999", width=2, arrow=tk.LAST)

            # Signatur
            self.canvas.create_text(cx, y_start + 60, text="Sign(Private, Message) → 64 byte Ed25519 signature",
                                    fill="#333", font=("Consolas", 9))

        elif step.category == "network":
            # Two agents with packet
            self.canvas.draw_agent(150, y_start + 60, "Initiator (AAI)", "#2196F3", 35, "EID_A")
            self.canvas.draw_agent(w - 150, y_start + 60, "Responder (LL-Entity)", "#4CAF50", 35, "EID_B")

            # Paket-Animation
            pkt_type = step.title.split("(")[-1].split(")")[0] if "(" in step.title else "FRAME"
            self.canvas.draw_packet(185, y_start + 60, w - 185, y_start + 60,
                                    color="#FF9800", packet_type=pkt_type)

            # Pfeil
            self.canvas.draw_arrow(185, y_start + 60, w - 185, y_start + 60,
                                   color="#FF9800", width=2, label="TCP/IP")

        elif step.category == "state":
            # State machine
            states = [
                ("UNBOUND", "#E0E0E0", 100, y_start + 50),
                ("ALLOCATED", "#E0E0E0", 250, y_start + 50),
                ("TRANSITION", "#E0E0E0", 400, y_start + 50),
                ("BOUND", "#E0E0E0", 550, y_start + 50),
            ]
            # Bestimme aktuellen State aus dem Step-Titel
            current = "BOUND"
            for s_name in ["UNBOUND", "ALLOCATED", "TRANSITION", "BOUND"]:
                if s_name in step.title.upper():
                    current = s_name
                    break
            self.canvas.draw_state_machine(states, current, color["accent"])

            # Pfeile zwischen States
            self.canvas.draw_arrow(155, y_start + 50, 195, y_start + 50, "#999", 1, label="ERP_INIT")
            self.canvas.draw_arrow(305, y_start + 50, 345, y_start + 50, "#999", 1, label="ERP_REGISTER")
            self.canvas.draw_arrow(455, y_start + 50, 495, y_start + 50, "#999", 1, label="DHT_CONFIRM")

        elif step.category == "formula":
            # Formula visualization
            formulas = {
                "HRP": "HRP(n) = 0.45·S(A,Tn) + 0.35·R(En) + 0.20·C(Hn)",
                "EVM": "EVM = H(p,q) - H(p) ≤ 0.001",
                "Reputation": "R_State(t) = 0.12·M(t) + 0.88·R_State(t-1)",
                "Generation": "Packet_Gen > Cache_Gen → Update | Packet_Gen < Cache_Gen → Drop",
                "PoM": "PoM_Score(t) = min(1.0, PoM_Count(t) / 5)",
                "Sequence": "Seq_Vector = (Initiator_Seq, Responder_Seq)",
            }
            formula_text = "IACP Formula"
            for key, val in formulas.items():
                if key.lower() in step.title.lower():
                    formula_text = val
                    break
            self.canvas.draw_formula(50, y_start, formula_text, color=color["fg"])

            # Zusätzlich: Visualisierung
            if "Reputation" in step.title:
                # Balkendiagramm
                for i, val in enumerate([0.9, 0.85, 0.7, 0.5, 0.3]):
                    bx = 100 + i * 80
                    self.canvas.draw_chart_bar(bx, y_start + 120, 40, 80, val, 1.0,
                                                "#4CAF50" if val >= 0.7 else "#F44336",
                                                f"t={i+1}")

        elif step.category == "dht":
            # DHT Quorum visualization
            self.canvas.draw_quorum(cx, y_start + 70, 80, 7, 4, 0)
            self.canvas.create_text(cx, y_start + 10, text="DHT Global Directory Quorum",
                                    fill="#333", font=("Segoe UI", 10, "bold"))
            self.canvas.create_text(cx, y_start + 160, text="7 Nodes | 4 Consensus | Kademlia XOR",
                                    fill="#666", font=("Consolas", 8))

        elif step.category == "governance":
            # PoM/2PSE visualization
            # Zwei konfliktierende Fragmente
            self.canvas.create_text(cx - 150, y_start, text="Fragment A",
                                    fill="#C62828", font=("Segoe UI", 9, "bold"))
            self.canvas.create_rectangle(cx - 200, y_start + 15, cx - 50, y_start + 55,
                                         fill="#FFEBEE", outline="#F44336", width=2)
            self.canvas.create_text(cx - 125, y_start + 35, text="IP=10.0.0.1 | Gen=5",
                                    fill="#C62828", font=("Consolas", 8))

            self.canvas.create_text(cx + 50, y_start, text="Fragment B",
                                    fill="#C62828", font=("Segoe UI", 9, "bold"))
            self.canvas.create_rectangle(cx, y_start + 15, cx + 150, y_start + 55,
                                         fill="#FFEBEE", outline="#F44336", width=2)
            self.canvas.create_text(cx + 75, y_start + 35, text="IP=10.0.0.2 | Gen=5",
                                    fill="#C62828", font=("Consolas", 8))

            # X zwischen Fragmenten
            self.canvas.create_text(cx, y_start + 35, text="✗",
                                    fill="#F44336", font=("Segoe UI", 18, "bold"))

            # Status
            if "CHALLENGED" in step.title.upper():
                self.canvas.create_text(cx, y_start + 75, text="STATE: CHALLENGED (Escrow Window 1h)",
                                        fill="#FF9800", font=("Consolas", 10, "bold"))
            elif "SLASHING" in step.title.upper() or "Slash" in step.title:
                self.canvas.create_text(cx, y_start + 75, text="STATE: SLASHED (Stake burned!)",
                                        fill="#F44336", font=("Consolas", 10, "bold"))

        elif step.category == "session":
            # Dual-Cookie Handshake visualization
            self.canvas.draw_agent(120, y_start + 50, "Initiator", "#2196F3", 30, "EID_A")
            self.canvas.draw_agent(w - 120, y_start + 50, "Responder", "#4CAF50", 30, "EID_B")

            # Drei Nachrichten
            y_pos = y_start + 50
            msgs = [
                ("PSS_INIT", "I-Cookie: 8B random", 170, y_pos - 40, w - 170, y_pos - 40),
                ("PSS_NEG", "R-Cookie: 8B random", w - 170, y_pos, 170, y_pos),
                ("PSS_ACK", "Session Established!", 170, y_pos + 40, w - 170, y_pos + 40),
            ]
            for msg_type, desc, x1, y1, x2, y2 in msgs:
                self.canvas.draw_packet(x1, y1, x2, y2, desc, "#4CAF50", msg_type)

        elif step.category == "mobility":
            # Migration visualization
            self.canvas.draw_agent(150, y_start + 50, "Agent (mobile)", "#FF9800", 30, "EID")

            # Zwei Netzwerke
            self.canvas.create_rectangle(300, y_start - 10, 500, y_start + 30,
                                         fill="#E3F2FD", outline="#2196F3", width=2)
            self.canvas.create_text(400, y_start + 10, text="WiFi (10.0.0.1)",
                                    fill="#1565C0", font=("Consolas", 8))

            self.canvas.create_rectangle(300, y_start + 70, 500, y_start + 110,
                                         fill="#FFF3E0", outline="#FF9800", width=2)
            self.canvas.create_text(400, y_start + 90, text="Mobile (10.0.0.2)",
                                    fill="#E65100", font=("Consolas", 8))

            # Pfeil nach unten
            self.canvas.create_line(400, y_start + 30, 400, y_start + 70,
                                    fill="#FF9800", width=3, arrow=tk.LAST)
            self.canvas.create_text(420, y_start + 50, text="Gen+1",
                                    fill="#FF9800", font=("Consolas", 8, "bold"))

        elif step.category == "discovery":
            # Discovery visualization
            self.canvas.draw_agent(120, y_start + 50, "Searcher", "#9C27B0", 30, "EID_A")
            self.canvas.draw_agent(w - 120, y_start + 50, "Responder", "#7B1FA2", 30, "EID_B")

            # DS im DHT
            self.canvas.create_rectangle(cx - 60, y_start - 10, cx + 60, y_start + 30,
                                         fill="#F3E5F5", outline="#9C27B0", width=2)
            self.canvas.create_text(cx, y_start + 10, text="Discovery Space",
                                    fill="#7B1FA2", font=("Consolas", 8, "bold"))

            # Pfeile
            self.canvas.draw_arrow(150, y_start + 30, cx - 60, y_start + 10,
                                   "#9C27B0", 1, label="DS_JOIN")
            self.canvas.draw_arrow(cx + 60, y_start + 10, w - 150, y_start + 30,
                                   "#9C27B0", 1, label="DISCOVERY_REQ")

        elif step.category == "content":
            # DHI Pipeline visualization
            stages = ["DNS SRV", ".well-known", "Link Header", "HRP/APE", "EVM"]
            for i, stage in enumerate(stages):
                sx = 60 + i * 110
                self.canvas.create_rectangle(sx, y_start + 20, sx + 80, y_start + 50,
                                             fill="#FFFDE7", outline="#F9A825", width=2)
                self.canvas.create_text(sx + 40, y_start + 35, text=stage,
                                        fill="#F57F17", font=("Consolas", 8, "bold"))
                if i < len(stages) - 1:
                    self.canvas.create_line(sx + 80, y_start + 35, sx + 110, y_start + 35,
                                            fill="#F9A825", width=2, arrow=tk.LAST)

        elif step.category == "termination":
            # Teardown visualization
            self.canvas.draw_agent(150, y_start + 50, "Initiator", "#607D8B", 30, "EID_A")
            self.canvas.draw_agent(w - 150, y_start + 50, "Responder", "#607D8B", 30, "EID_B")

            # Teardown-Nachricht
            self.canvas.draw_packet(185, y_start + 50, w - 185, y_start + 50,
                                    "Final Checksum", "#607D8B", "PSS_TEARDOWN")

            # Status
            self.canvas.create_text(cx, y_start + 90, text="STATE: CLOSED",
                                    fill="#607D8B", font=("Consolas", 10, "bold"))

        elif step.category == "identity":
            # EID visualization
            self.canvas.create_text(cx, y_start, text="Ephemeral Agent Identity (EID)",
                                    fill="#1565C0", font=("Segoe UI", 12, "bold"))
            # EID als Hex
            eid_hex = "a1b2 c3d4 e5f6 7890 a1b2 c3d4 e5f6 7890 a1b2 c3d4 e5f6 7890 a1b2 c3d4 e5f6 7890"
            self.canvas.create_rectangle(cx - 180, y_start + 30, cx + 180, y_start + 60,
                                         fill="#E3F2FD", outline="#2196F3", width=2)
            self.canvas.create_text(cx, y_start + 45, text=eid_hex,
                                    fill="#1565C0", font=("Consolas", 9, "bold"))
            self.canvas.create_text(cx, y_start + 80, text="32 bytes | Ed25519 Public Key | Self-certifying",
                                    fill="#666", font=("Consolas", 8))

    def _render_completion(self):
        """Draws the completion screen."""
        self.canvas.draw_completion(self.total_steps)
        self._log("✓ Demo completed successfully!", "highlight")
        self._log(f"  {self.total_steps} Steps in 9 Phasen", "highlight")
        self.header_title.set("IACP Full Demo – Completed ✓")
        self.status_var.set("Demo completed successfully!")

    def _update_ui_for_step(self, step_idx: int):
        """Updates the UI elements for the current step."""
        # Finde Phase und Step
        cum = 0
        current_phase = 0
        current_step_in_phase = 0
        for pi, phase in enumerate(self.phases):
            if step_idx < cum + len(phase.steps):
                current_phase = pi
                current_step_in_phase = step_idx - cum
                break
            cum += len(phase.steps)

        phase = self.phases[current_phase]
        step = phase.steps[current_step_in_phase]

        # Header
        self.header_title.set(f"Phase {phase.number}: {phase.name}")
        self.header_progress.set(f"Step {step_idx + 1} / {self.total_steps}")

        # Step-Titel und Beschreibung
        self.step_title_var.set(f"{step.icon}  {step.title}")
        self.step_desc_var.set(step.description)

        # Progress
        self.progress_var.set(step_idx + 1)
        self.step_nav_var.set(step_idx)

        # Metriken
        self.metrics_vars["phase"].set(f"{phase.number}/9 – {phase.name}")
        self.metrics_vars["step"].set(f"{step_idx + 1}/{self.total_steps}")
        self.metrics_vars["progress"].set(f"{int((step_idx + 1) / self.total_steps * 100)}%")
        self.metrics_vars["speed"].set(f"{self.engine.speed:.1f}x")
        self.metrics_vars["status"].set("Running" if self.engine.is_running else "Paused")

        # Phase-Navigation aktualisieren
        for i, var in enumerate(self.phase_labels):
            if i == current_phase:
                var.set(f"▶ {step.title[:30]}")
            elif i < current_phase:
                var.set("✓ Completed")
            else:
                var.set("")

    def _log(self, message: str, tag: str = "step"):
        """Adds a message to the step log."""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def run(self):
        """Shows the demo window."""
        self.window.deiconify()
        self.window.lift()