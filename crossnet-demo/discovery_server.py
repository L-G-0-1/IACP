"""
IACP Discovery Server
=====================
Simulates the DHT-based discovery mechanism from IETF Draft §5.1 and §6.2.
Also provides relay functionality for cross-network communication (§3.7.3, §5.6).

Agents register their EID + IP + port + topic here.
Other agents can look up peers by EID or discover by topic.
If direct connection fails, messages can be relayed through this server.

API:
  POST /register  {"eid": "...", "ip": "...", "port": 4001, "topic": "knowledge"}
  GET  /lookup?eid=<eid>       -> {"ip": "...", "port": 4001, "topic": "..."}
  GET  /discover?topic=<topic> -> [{"eid": "...", "ip": "...", "port": 4001}, ...]
  GET  /list                   -> [{"eid": "...", "ip": "...", "port": 4001, "topic": "..."}, ...]
  
  Relay API (cross-network):
  POST /relay_register  {"eid": "...", "session_cookie": "..."}
  POST /relay           {"from_eid": "...", "to_eid": "...", "encrypted": "...", "session_cookie": "..."}
  GET  /relay_poll?eid=<eid>&session_cookie=...  -> [{"from_eid": "...", "encrypted": "...", "timestamp": ...}, ...]
  GET  /health                         -> {"status": "ok"}
"""

import http.server
import json
import time
import sys
import os
import threading
from typing import Dict, List
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iacp_protocol import ReputationManager, SimpleDHT, generate_eid


REGISTRY: Dict[str, dict] = {}  # eid -> {ip, port, topic, timestamp}
LOCK = threading.Lock()
TTL_SECONDS = 300  # 5 minutes before stale

# Relay-specific storage
RELAY_REGISTRY: Dict[str, dict] = {}  # eid -> {session_cookie, last_poll}
RELAY_QUEUES: Dict[str, List[dict]] = {}  # eid -> [{"from_eid": "...", "encrypted": "...", "timestamp": ...}]
RELAY_LOCK = threading.Lock()
RELAY_QUEUE_MAX = 100  # Max messages per agent


class DiscoveryHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the discovery server."""

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        body = self.rfile.read(length)
        return json.loads(body.decode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        if self.path == "/register":
            data = self._read_body()
            eid = data.get("eid", "")
            ip = data.get("ip", "")
            port = data.get("port", 0)
            topic = data.get("topic", "")

            # port may be 0 for relay-only presence (no direct TCP listener)
            if not eid or not ip:
                self._send_json({"status": "error", "message": "Missing eid or ip"}, 400)
                return
            try:
                port = int(port)
            except (TypeError, ValueError):
                self._send_json({"status": "error", "message": "Invalid port"}, 400)
                return

            # PROTOTYP: no signature check; production needs signed registration
            with LOCK:
                REGISTRY[eid] = {
                    "ip": ip,
                    "port": port,
                    "topic": topic,
                    "timestamp": time.time()
                }

            self._send_json({"status": "ok", "message": f"Registered {eid[:16]}..."})
            print(f"[Discovery] Registered: {eid[:16]}... @ {ip}:{port} ({topic})")
        
        elif self.path == "/relay_register":
            data = self._read_body()
            eid = data.get("eid", "")
            session_cookie = data.get("session_cookie", "")

            if not eid or not session_cookie:
                self._send_json({"status": "error", "message": "Missing eid or session_cookie"}, 400)
                return

            with RELAY_LOCK:
                RELAY_REGISTRY[eid] = {
                    "session_cookie": session_cookie,
                    "last_poll": time.time(),
                    "message_queue": []
                }

            self._send_json({"status": "ok", "message": f"Relay registered for {eid[:16]}..."})
            print(f"[Discovery] Relay registered: {eid[:16]}...")
        
        elif self.path == "/relay":
            data = self._read_body()
            from_eid = data.get("from_eid", "")
            to_eid = data.get("to_eid", "")
            encrypted = data.get("encrypted", "")
            session_cookie = data.get("session_cookie", "")

            if not from_eid or not to_eid or not encrypted or not session_cookie:
                self._send_json({"status": "error", "message": "Missing required fields"}, 400)
                return

            with RELAY_LOCK:
                if from_eid not in RELAY_REGISTRY:
                    self._send_json({"status": "error", "message": "Sender not registered for relay"}, 403)
                    return
                
                if RELAY_REGISTRY[from_eid]["session_cookie"] != session_cookie:
                    self._send_json({"status": "error", "message": "Invalid session cookie"}, 403)
                    return

                if to_eid not in RELAY_QUEUES:
                    RELAY_QUEUES[to_eid] = []
                
                message = {
                    "from_eid": from_eid,
                    "encrypted": encrypted,
                    "timestamp": time.time(),
                    "datetime": datetime.now().isoformat()
                }
                RELAY_QUEUES[to_eid].append(message)
                
                if len(RELAY_QUEUES[to_eid]) > RELAY_QUEUE_MAX:
                    RELAY_QUEUES[to_eid] = RELAY_QUEUES[to_eid][-RELAY_QUEUE_MAX:]

            self._send_json({
                "status": "ok", 
                "message": f"Message queued for {to_eid[:16]}...",
                "queued_at": datetime.now().isoformat()
            })
            print(f"[Discovery] Relay: {from_eid[:16]}... -> {to_eid[:16]}...")
        
        else:
            self._send_json({"status": "error", "message": "Not found"}, 404)

    def do_GET(self):
        if self.path.startswith("/lookup"):
            import urllib.parse
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            eid = params.get("eid", [""])[0]

            if not eid:
                self._send_json({"status": "error", "message": "Missing eid"}, 400)
                return

            with LOCK:
                entry = REGISTRY.get(eid)

            if entry:
                self._send_json({"status": "ok", "entry": entry})
            else:
                self._send_json({"status": "error", "message": "EID not found"}, 404)

        elif self.path.startswith("/discover"):
            import urllib.parse
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            topic = params.get("topic", [""])[0]

            if not topic:
                self._send_json({"status": "error", "message": "Missing topic"}, 400)
                return

            results = []
            with LOCK:
                now = time.time()
                for eid, entry in REGISTRY.items():
                    if entry["topic"] == topic and (now - entry["timestamp"]) < TTL_SECONDS:
                        results.append({"eid": eid, **entry})

            self._send_json({"status": "ok", "results": results})

        elif self.path == "/list":
            results = []
            with LOCK:
                now = time.time()
                for eid, entry in REGISTRY.items():
                    if (now - entry["timestamp"]) < TTL_SECONDS:
                        results.append({"eid": eid, **entry})

            self._send_json({"status": "ok", "agents": results})
        
        elif self.path.startswith("/relay_poll"):
            import urllib.parse
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            eid = params.get("eid", [""])[0]
            session_cookie = params.get("session_cookie", [""])[0]
            timeout = int(params.get("timeout", [5])[0])

            if not eid or not session_cookie:
                self._send_json({"status": "error", "message": "Missing eid or session_cookie"}, 400)
                return

            with RELAY_LOCK:
                if eid not in RELAY_REGISTRY or RELAY_REGISTRY[eid]["session_cookie"] != session_cookie:
                    self._send_json({"status": "error", "message": "Invalid session cookie"}, 403)
                    return
                
                RELAY_REGISTRY[eid]["last_poll"] = time.time()

                messages = RELAY_QUEUES.get(eid, [])
                
                if eid in RELAY_QUEUES:
                    RELAY_QUEUES[eid] = []

            self._send_json({
                "status": "ok",
                "messages": messages,
                "count": len(messages),
                "polled_at": datetime.now().isoformat()
            })
            print(f"[Discovery] Relay poll: {eid[:16]}... received {len(messages)} messages")
        
        elif self.path == "/health":
            self._send_json({
                "status": "ok",
                "version": "1.0",
                "timestamp": time.time(),
                "registered_agents": len(REGISTRY),
                "relay_agents": len(RELAY_REGISTRY),
                "queued_messages": sum(len(q) for q in RELAY_QUEUES.values())
            })
        
        else:
            self._send_json({"status": "error", "message": "Not found"}, 404)

    def log_message(self, format, *args):
        """Suppress default HTTP log output."""
        pass


def run_server(host="0.0.0.0", port=8888):
    """Start the discovery server."""
    server = http.server.HTTPServer((host, port), DiscoveryHandler)
    print(f"[Discovery] Server running on {host}:{port}")
    print(f"[Discovery] API endpoints:")
    print(f"  POST http://{host}:{port}/register")
    print(f"  GET  http://{host}:{port}/lookup?eid=<eid>")
    print(f"  GET  http://{host}:{port}/discover?topic=<topic>")
    print(f"  GET  http://{host}:{port}/list")
    print(f"  POST http://{host}:{port}/relay_register")
    print(f"  POST http://{host}:{port}/relay")
    print(f"  GET  http://{host}:{port}/relay_poll?eid=<eid>&session_cookie=...")
    print(f"  GET  http://{host}:{port}/health")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Discovery] Server stopped.")
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    run_server(port=port)