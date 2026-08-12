"""
IACP Desktop App - Complete Agent Management Console
=====================================================
A full-featured graphical application for the Internet Agent Communication Protocol.

Features:
- EID Management with auto-generation
- Three connection modes: Direct, Discovery, Relay
- Live conversation view with LLM agents (phi3:mini)
- Reputation tracking dashboard
- Protocol metrics and stats
- Session management
- Log export
- Built-in discovery server with start/stop

Usage:
  python iacp_app.py
  python iacp_app.py --discover localhost:8888
"""

import socket
import sys
import os
import argparse
import threading
import time
import json
import urllib.request
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iacp_demo_visualizer import DemoVisualizer
from iacp_protocol import (
    generate_eid_str, generate_cookie_str,
    perform_handshake, send_data, recv_data,
    RelayTransport, FrameBuffer, IACPSessionWire,
    ReputationManager, SimpleDHT, PSSManager, ESEManager,
    TokenBucket, CircuitBreaker
)


# =========================================================================
# LLM Agent Integration
# =========================================================================

PROMPT_INITIATOR = (
    "You are a curious, creative AI researcher. You are having a "
    "free discussion with another AI. You ask questions, share "
    "ideas, challenge assumptions, and respond to what your "
    "conversation partner says. Answer in English, 2-4 sentences. "
    "Be lively and engaged."
)

PROMPT_RESPONDER = (
    "You are a thoughtful AI knowledge expert. You are having a free "
    "discussion with another AI. You answer questions, ask follow-up "
    "questions, and bring new perspectives. You build on what your "
    "conversation partner has said. Answer in English, 2-4 sentences."
)

def ask_llm(model: str, prompt: str, context: str) -> str:
    """Ask the local LLM and return the response."""
    try:
        from ollama import chat
        response = chat(model=model, messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": context},
        ], options={"temperature": 0.7, "num_predict": 256})
        return response["message"]["content"].strip()
    except ImportError:
        return "[LLM not available - run: pip install ollama]"
    except Exception as e:
        return f"[LLM Error: {e}]"


# =========================================================================
# Background Agent Thread
# =========================================================================

def agent_thread(app, mode, peer_addr, bind_addr, discover_url,
                 topic, use_relay, relay_url, llm_model):
    """Run an IACP agent in a background thread and update the app UI."""
    try:
        my_eid = generate_eid_str()
        session_cookie = generate_cookie_str()
        app.update_eid_display(my_eid)
        app.log(f"Agent started. EID: {my_eid[:16]}...", "system")

        # Reputation tracking
        rep_manager = ReputationManager()
        estats = app.stats
        estats['reputation'] = rep_manager

        # Token bucket for rate limiting display
        token_bucket = TokenBucket(capacity=100, refill_rate=10)
        estats['token_bucket'] = token_bucket
        estats['packets_sent'] = 0
        estats['packets_recv'] = 0

        app.log("Reputation system initialized", "system")

        if use_relay and relay_url:
            relay = RelayTransport(relay_url, my_eid, session_cookie)
            if relay.register():
                app.log("Relay mode active. Polling for messages...", "system")
                stop_event = threading.Event()
                def on_relay_msg(msg):
                    app.log(f"[Relay] {msg.get('from_eid', '?')[:16]}... sent message", "relay")
                relay.start_polling(on_relay_msg, stop_event)
                while not stop_event.is_set():
                    time.sleep(1)
            else:
                app.log("Relay registration failed.", "error")
            return

        if discover_url and not peer_addr:
            app.log(f"Discovering peers at {discover_url} (topic: {topic})...", "system")
            health_url = discover_url.rstrip('/') + "/health"
            try:
                resp = urllib.request.urlopen(health_url, timeout=3)
                if json.loads(resp.read().decode()).get("status") != "ok":
                    app.log("Discovery server not responding. Start it with Quick Actions.", "error")
                    return
            except Exception:
                app.log("Discovery server not reachable. Start it with Quick Actions.", "error")
                return
            try:
                url = f"{discover_url.rstrip('/')}/discover?topic={topic}"
                resp = urllib.request.urlopen(url, timeout=10)
                result = json.loads(resp.read().decode())
                if result.get("status") == "ok" and result.get("results"):
                    peer = result["results"][0]
                    peer_addr = f"{peer['ip']}:{peer['port']}"
                    app.log(f"Found peer: {peer['eid'][:16]}... @ {peer_addr}", "discovery")
                    estats['peer_eid'] = peer['eid']
                else:
                    app.log("No peers found via discovery.", "system")
                    return
            except Exception as e:
                app.log(f"Discovery error: {e}", "error")
                return

        if mode == "initiator" and peer_addr:
            app.log(f"Connecting to {peer_addr}...", "system")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                parts = peer_addr.split(":")
                sock.connect((parts[0], int(parts[1])))
                app.log("TCP connected!", "system")
            except Exception as e:
                app.log(f"Connection failed: {e}", "error")
                return

            try:
                session = perform_handshake(sock, my_eid, is_initiator=True)
                app.log(f"PSS established with {session.peer_eid[:16]}...", "success")
                estats['peer_eid'] = session.peer_eid
            except ValueError as e:
                app.log(f"Handshake failed: {e}", "error")
                sock.close()
                return

            round_num = 1
            buf = FrameBuffer()
            context_log = []

            while app.running:
                if round_num == 1:
                    my_msg = "Hello! Let's discuss AI and creativity."
                else:
                    ctx = f"Continue. Previous: {' '.join(context_log[-3:])}"
                    my_msg = ask_llm(llm_model, PROMPT_INITIATOR, ctx)

                send_data(sock, session, my_msg)
                estats['packets_sent'] = estats.get('packets_sent', 0) + 1
                token_bucket.consume(1)
                app.log(f"[{my_eid[:8]}...] {my_msg}", "sent")
                context_log.append(f"Me: {my_msg}")

                try:
                    peer_msg = recv_data(sock, session, buf)
                    estats['packets_recv'] = estats.get('packets_recv', 0) + 1
                    app.log(f"[{session.peer_eid[:8]}...] {peer_msg}", "received")
                    context_log.append(f"Peer: {peer_msg}")
                except Exception as e:
                    app.log(f"Disconnected: {e}", "error")
                    break

                round_num += 1
                app.update_stats()
                token_bucket.consume(1)

            sock.close()
            app.log(f"Done. {round_num - 1} rounds completed.", "system")

        elif mode == "responder" and bind_addr:
            parts = bind_addr.split(":")
            bind_ip = parts[0]
            bind_port = int(parts[1])

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((bind_ip, bind_port))
            server.listen(5)
            app.log(f"Listening on {bind_ip}:{bind_port}", "system")

            if discover_url:
                health_url = discover_url.rstrip('/') + "/health"
                try:
                    resp = urllib.request.urlopen(health_url, timeout=3)
                    if json.loads(resp.read().decode()).get("status") == "ok":
                        disc_data = json.dumps({
                            "eid": my_eid, "ip": bind_ip,
                            "port": bind_port, "topic": topic
                        }).encode()
                        req = urllib.request.Request(
                            f"{discover_url.rstrip('/')}/register", data=disc_data,
                            headers={"Content-Type": "application/json"}
                        )
                        resp = urllib.request.urlopen(req, timeout=5)
                        result = json.loads(resp.read().decode())
                        app.log(f"Discovery: {result.get('message', 'ok')}", "discovery")
                except Exception as e:
                    app.log(f"Discovery registration failed: {e}", "error")

            server.settimeout(5.0)
            try:
                conn, addr = server.accept()
                app.log(f"Client connected: {addr[0]}:{addr[1]}", "success")

                session = perform_handshake(conn, my_eid, is_initiator=False)
                app.log(f"PSS established with {session.peer_eid[:16]}...", "success")
                estats['peer_eid'] = session.peer_eid

                round_num = 0
                buf = FrameBuffer()
                context_log = []

                while app.running:
                    try:
                        peer_msg = recv_data(conn, session, buf)
                        estats['packets_recv'] = estats.get('packets_recv', 0) + 1
                        app.log(f"[{session.peer_eid[:8]}...] {peer_msg}", "received")
                        context_log.append(f"Peer: {peer_msg}")
                    except Exception as e:
                        app.log(f"Disconnected: {e}", "error")
                        break

                    ctx = f"Continue. Previous: {' '.join(context_log[-3:])}"
                    my_msg = ask_llm(llm_model, PROMPT_RESPONDER, ctx)
                    send_data(conn, session, my_msg)
                    estats['packets_sent'] = estats.get('packets_sent', 0) + 1
                    app.log(f"[{my_eid[:8]}...] {my_msg}", "sent")
                    context_log.append(f"Me: {my_msg}")
                    round_num += 1
                    app.update_stats()

                conn.close()
                app.log(f"Done. {round_num} rounds.", "system")
            except socket.timeout:
                pass
            finally:
                server.close()
        else:
            app.log("Invalid configuration. Check mode and connection settings.", "error")

    except Exception as e:
        app.log(f"Agent error: {e}", "error")
        import traceback
        app.log(traceback.format_exc(), "error")
    finally:
        app.running = False
        app.btn_connect.config(text="Connect / Start", state="normal")
        app.btn_stop.config(state="disabled")


# =========================================================================
# Desktop App GUI
# =========================================================================

class IACPApp:
    """Full-featured IACP Desktop Application."""

    def __init__(self, discover_url=None):
        self.running = False
        self.discovery_process = None
        self.stats = {
            'reputation': None,
            'token_bucket': None,
            'packets_sent': 0,
            'packets_recv': 0,
            'peer_eid': ''
        }
        self.root = tk.Tk()
        self.root.title("IACP Agent Console")
        self.root.geometry("1100x800")
        self.root.minsize(800, 600)

        # Variables
        self.mode_var = tk.StringVar(value="initiator")
        self.peer_ip_var = tk.StringVar()
        self.bind_var = tk.StringVar(value="0.0.0.0:4001")
        self.use_disc_var = tk.BooleanVar(value=discover_url is not None)
        self.disc_url_var = tk.StringVar(value=discover_url or "http://localhost:8888")
        self.topic_var = tk.StringVar(value="knowledge")
        self.relay_var = tk.BooleanVar(value=False)
        self.relay_url_var = tk.StringVar(value="http://localhost:8888")
        self.llm_model_var = tk.StringVar(value="phi3:mini")
        self.eid_var = tk.StringVar(value="(will be generated on connect)")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        # Main container
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill="both", expand=True, padx=5, pady=5)

        # ==================== LEFT PANEL ====================
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=1)

        # --- Identity Section ---
        id_frame = ttk.LabelFrame(left_frame, text=" Agent Identity (EID) ", padding=10)
        id_frame.pack(fill="x", pady=(0, 5))

        eid_row = ttk.Frame(id_frame)
        eid_row.pack(fill="x")
        ttk.Label(eid_row, textvariable=self.eid_var, font=("Consolas", 10),
                  foreground="#0066cc").pack(side="left")
        ttk.Button(eid_row, text="Copy", width=6,
                   command=self._copy_eid).pack(side="right", padx=2)

        # --- Connection Section ---
        conn_frame = ttk.LabelFrame(left_frame, text=" Connection ", padding=10)
        conn_frame.pack(fill="x", pady=5)

        # Mode
        mode_frame = ttk.Frame(conn_frame)
        mode_frame.pack(fill="x", pady=2)
        ttk.Label(mode_frame, text="Mode:").pack(side="left")
        ttk.Radiobutton(mode_frame, text="Connect (Initiator)",
                        variable=self.mode_var, value="initiator").pack(side="left", padx=5)
        ttk.Radiobutton(mode_frame, text="Wait (Responder)",
                        variable=self.mode_var, value="responder").pack(side="left", padx=5)

        # Peer / Bind
        addr_frame = ttk.Frame(conn_frame)
        addr_frame.pack(fill="x", pady=2)
        ttk.Label(addr_frame, text="Peer IP:Port:").pack(side="left")
        ttk.Entry(addr_frame, textvariable=self.peer_ip_var, width=22).pack(side="left", padx=5)
        ttk.Label(addr_frame, text="Bind:").pack(side="left", padx=(5, 0))
        ttk.Entry(addr_frame, textvariable=self.bind_var, width=18).pack(side="left", padx=5)

        # Discovery
        disc_frame = ttk.LabelFrame(conn_frame, text=" Discovery ", padding=5)
        disc_frame.pack(fill="x", pady=2)
        disc_row1 = ttk.Frame(disc_frame)
        disc_row1.pack(fill="x")
        ttk.Checkbutton(disc_row1, text="Enable",
                        variable=self.use_disc_var).pack(side="left")
        ttk.Label(disc_row1, text="URL:").pack(side="left", padx=(5, 0))
        ttk.Entry(disc_row1, textvariable=self.disc_url_var, width=22).pack(side="left", padx=5)
        disc_row2 = ttk.Frame(disc_frame)
        disc_row2.pack(fill="x")
        ttk.Label(disc_row2, text="Topic:").pack(side="left")
        ttk.Entry(disc_row2, textvariable=self.topic_var, width=15).pack(side="left", padx=5)

        # Relay
        relay_frame = ttk.LabelFrame(conn_frame, text=" Relay (Cross-Network) ", padding=5)
        relay_frame.pack(fill="x", pady=2)
        relay_row = ttk.Frame(relay_frame)
        relay_row.pack(fill="x")
        ttk.Checkbutton(relay_row, text="Enable",
                        variable=self.relay_var).pack(side="left")
        ttk.Label(relay_row, text="URL:").pack(side="left", padx=(5, 0))
        ttk.Entry(relay_row, textvariable=self.relay_url_var, width=22).pack(side="left", padx=5)

        # LLM Model
        llm_frame = ttk.Frame(conn_frame)
        llm_frame.pack(fill="x", pady=2)
        ttk.Label(llm_frame, text="LLM Model:").pack(side="left")
        ttk.Entry(llm_frame, textvariable=self.llm_model_var, width=12).pack(side="left", padx=5)
        ttk.Button(llm_frame, text="Test LLM", command=self._test_llm).pack(side="left", padx=5)

        # Buttons
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.pack(fill="x", pady=(5, 0))
        self.btn_connect = ttk.Button(btn_frame, text="Connect / Start",
                                      command=self._on_connect)
        self.btn_connect.pack(side="left", padx=5)
        self.btn_stop = ttk.Button(btn_frame, text="Stop", state="disabled",
                                   command=self._on_stop)
        self.btn_stop.pack(side="left", padx=5)

        # --- Stats Section ---
        stats_frame = ttk.LabelFrame(left_frame, text=" Session Stats ", padding=10)
        stats_frame.pack(fill="x", pady=5)

        self.stats_vars = {}
        stats_items = [
            ("packets_sent", "Packets Sent:"),
            ("packets_recv", "Packets Received:"),
            ("bucket_tokens", "Token Bucket:"),
            ("rep_state", "Reputation:"),
            ("peer_display", "Peer EID:"),
        ]
        for key, label in stats_items:
            row = ttk.Frame(stats_frame)
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=label, width=16, anchor="e").pack(side="left")
            var = tk.StringVar(value="-")
            ttk.Label(row, textvariable=var, font=("Consolas", 9)).pack(side="left", padx=5)
            self.stats_vars[key] = var

        # --- Quick Actions ---
        cmd_frame = ttk.LabelFrame(left_frame, text=" Quick Actions ", padding=10)
        cmd_frame.pack(fill="x", pady=5)

        ttk.Button(cmd_frame, text="Start Discovery Server",
                   command=self._start_discovery).pack(fill="x", pady=2)
        self.btn_stop_disc = ttk.Button(cmd_frame, text="Stop Discovery Server",
                                        command=self._stop_discovery, state="disabled")
        self.btn_stop_disc.pack(fill="x", pady=2)
        ttk.Button(cmd_frame, text="Export Log",
                   command=self._export_log).pack(fill="x", pady=2)
        ttk.Button(cmd_frame, text="Clear Log",
                   command=self._clear_log).pack(fill="x", pady=2)
        ttk.Button(cmd_frame, text="Demo: Protocol Features",
                   command=self._run_proto_demo).pack(fill="x", pady=2)
        ttk.Button(cmd_frame, text="\U0001f3ac Run Full Demo (Graphical)",
                   command=self._run_full_demo).pack(fill="x", pady=2)

        # ==================== RIGHT PANEL ====================
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=2)

        # --- Log Section ---
        log_frame = ttk.LabelFrame(right_frame, text=" Conversation & Event Log ", padding=10)
        log_frame.pack(fill="both", expand=True)

        # Control bar
        log_ctl = ttk.Frame(log_frame)
        log_ctl.pack(fill="x", pady=(0, 5))
        ttk.Label(log_ctl, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(log_ctl, textvariable=self.filter_var,
                                     values=["all", "sent", "received", "system",
                                             "discovery", "relay", "success", "error"],
                                     width=12, state="readonly")
        filter_combo.pack(side="left", padx=5)

        # Log area with tags for colors
        self.log_area = scrolledtext.ScrolledText(log_frame, font=("Consolas", 10),
                                                   wrap=tk.WORD, state="disabled")
        self.log_area.pack(fill="both", expand=True)

        # Configure tags
        self.log_area.tag_configure("sent", foreground="#0066cc")
        self.log_area.tag_configure("received", foreground="#009933")
        self.log_area.tag_configure("system", foreground="#666666")
        self.log_area.tag_configure("success", foreground="#006600")
        self.log_area.tag_configure("error", foreground="#cc0000")
        self.log_area.tag_configure("discovery", foreground="#9933ff")
        self.log_area.tag_configure("relay", foreground="#cc6600")

        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief="sunken",
                                     anchor="w", padding=(5, 2))
        self.status_bar.pack(fill="x")

    # =========================================================================
    # UI Methods
    # =========================================================================

    def log(self, message: str, tag: str = "system"):
        """Add a timestamped, color-coded message to the log."""
        def _append():
            self.log_area.config(state="normal")
            timestamp = time.strftime("%H:%M:%S")
            tag_display = f"[{tag.upper()}]" if tag != "system" else "     "
            self.log_area.insert(tk.END, f"[{timestamp}] {tag_display} {message}\n", tag)
            self.log_area.see(tk.END)
            self.log_area.config(state="disabled")

        self.root.after(0, _append)

    def update_eid_display(self, eid: str):
        self.eid_var.set(f"EID: {eid[:16]}...{eid[-8:]}")

    def update_stats(self):
        """Update the stats panel."""
        estats = self.stats
        self.stats_vars['packets_sent'].set(str(estats.get('packets_sent', 0)))
        self.stats_vars['packets_recv'].set(str(estats.get('packets_recv', 0)))

        tb = estats.get('token_bucket')
        if tb:
            self.stats_vars['bucket_tokens'].set(f"{tb.tokens:.0f}/{tb.capacity}")

        rep = estats.get('reputation')
        if rep:
            eid_val = estats.get('peer_eid', '')
            if eid_val:
                rep_val = rep.get_reputation(eid_val.encode() if isinstance(eid_val, str) else eid_val)
                self.stats_vars['rep_state'].set(f"{rep_val:.3f}")

        peer = estats.get('peer_eid', '')
        self.stats_vars['peer_display'].set(f"{peer[:16]}..." if peer else "-")

    def _copy_eid(self):
        eid_text = self.eid_var.get().replace("EID: ", "")
        self.root.clipboard_clear()
        self.root.clipboard_append(eid_text)

    def _clear_log(self):
        self.log_area.config(state="normal")
        self.log_area.delete("1.0", tk.END)
        self.log_area.config(state="disabled")

    def _export_log(self):
        """Export log to a text file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"iacp-log-{time.strftime('%Y%m%d-%H%M%S')}.txt"
        )
        if filename:
            try:
                content = self.log_area.get("1.0", tk.END)
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Export", f"Log exported to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _test_llm(self):
        """Test LLM connectivity. Starts Ollama automatically if not running."""
        model = self.llm_model_var.get()
        self.log(f"Testing LLM model '{model}'...", "system")

        def test():
            # First check if Ollama is reachable
            try:
                import urllib.request
                req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
                urllib.request.urlopen(req, timeout=2)
            except Exception:
                self.log("Ollama not running. Attempting to start...", "system")
                try:
                    import subprocess
                    subprocess.Popen(["ollama", "serve"], creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                    import time
                    time.sleep(3)
                    self.log("Ollama server started.", "success")
                except FileNotFoundError:
                    self.log("Ollama not installed. Download from https://ollama.com/download", "error")
                    return
                except Exception as e:
                    self.log(f"Failed to start Ollama: {e}", "error")
                    return

            result = ask_llm(model, "You are a test bot.", "Reply with exactly this sentence and nothing else: 'Hello, I am an AI and this test run was successful!'")
            self.log(f"LLM Response: {result}", "success")

        threading.Thread(target=test, daemon=True).start()

    def _run_proto_demo(self):
        """Run the protocol feature demo in a subprocess - log output live."""
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_core.py")
        self.log("Starting protocol feature demo...", "system")
        def run():
            proc = subprocess.Popen([sys.executable, script],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1)
            for line in proc.stdout:
                self.log(line.rstrip(), "system")
        threading.Thread(target=run, daemon=True).start()

    def _start_discovery(self):
        """Start a discovery server in a subprocess with tracking."""
        if self.discovery_process:
            self.log("Discovery server is already running.", "system")
            return
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "discovery_server.py")
        self.log("Starting Discovery Server on port 8888...", "discovery")
        def run():
            try:
                self.discovery_process = subprocess.Popen(
                    [sys.executable, script],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                self.btn_stop_disc.config(state="normal")
                self.status_bar.config(text="Discovery Server running on :8888")
                for line in self.discovery_process.stdout:
                    self.log(line.rstrip(), "discovery")
            except Exception as e:
                self.log(f"Discovery server error: {e}", "error")
        threading.Thread(target=run, daemon=True).start()

    def _stop_discovery(self):
        """Stop the running discovery server."""
        if self.discovery_process:
            self.log("Stopping Discovery Server...", "discovery")
            try:
                self.discovery_process.terminate()
                self.discovery_process.wait(timeout=3)
                self.discovery_process = None
                self.btn_stop_disc.config(state="disabled")
                self.status_bar.config(text="Discovery Server stopped")
                self.log("Discovery Server stopped.", "system")
            except Exception as e:
                self.log(f"Failed to stop: {e}", "error")
        else:
            self.log("No Discovery Server is running.", "system")

    def _on_connect(self):
        if self.running:
            return

        self.running = True
        self.btn_connect.config(text="Running...", state="disabled")
        self.btn_stop.config(state="normal")
        self.status_bar.config(text="Starting agent...")

        mode = self.mode_var.get()
        peer_addr = self.peer_ip_var.get().strip()
        bind_addr = self.bind_var.get().strip()
        use_discover = self.use_disc_var.get()
        discover_url = self.disc_url_var.get().strip() if use_discover else None
        topic = self.topic_var.get().strip()
        use_relay = self.relay_var.get()
        relay_url = self.relay_url_var.get().strip() if use_relay else None
        llm_model = self.llm_model_var.get().strip() or "phi3:mini"

        thread = threading.Thread(target=agent_thread,
                                   args=(self, mode, peer_addr, bind_addr,
                                         discover_url, topic, use_relay,
                                         relay_url, llm_model),
                                   daemon=True)
        thread.start()

    def _on_stop(self):
        self.running = False
        self.log("Stopping agent...", "system")
        self.status_bar.config(text="Stopped")

    def _on_close(self):
        self.running = False
        if self.discovery_process:
            self.discovery_process.terminate()
        self.root.destroy()

    def _run_full_demo(self):
        """Startet die grafische IACP Full Demo."""
        try:
            viz = DemoVisualizer(self.root)
            viz.run()
            self.log("Full Demo Visualizer geöffnet.", "success")
        except Exception as e:
            self.log(f"Full Demo Fehler: {e}", "error")
            import traceback
            self.log(traceback.format_exc(), "error")

    def run(self):
        self.root.mainloop()


# =========================================================================
# Main Entry Point
# =========================================================================

def main():
    parser = argparse.ArgumentParser(description="IACP Desktop App")
    parser.add_argument("--discover", help="Default discovery server URL")
    args = parser.parse_args()

    app = IACPApp(discover_url=args.discover)
    app.run()


if __name__ == "__main__":
    main()