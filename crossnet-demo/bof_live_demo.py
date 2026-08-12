"""IACP Live Demo"""
import sys, os, time, threading
from typing import Dict, Optional
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
from iacp_protocol import IACPAgent, ReputationManager, PSSManager, PoMManager

ROLES = {
    "explorer": {"name": "Explorer", "color": "\033[96m", "personality": "curious", "model": "phi3:mini"},
    "analyst": {"name": "Analyst", "color": "\033[94m", "personality": "logical", "model": "phi3:mini"},
    "diplomat": {"name": "Diplomat", "color": "\033[92m", "personality": "diplomatic", "model": "phi3:mini"},
}

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║   IACP Live Demo - Autonomous AI Agent Communication         ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(f"\033[95m\033[1m{banner}\033[0m")

def print_topology(agents):
    print("\033[1m[Network Topology]\033[0m")
    for role, data in agents.items():
        rep = data['rep'].get_reputation(data['agent'].eid)
        name = data['role_obj']['name']
        print(f"  [{name:10s}] ONLINE | Rep: {rep:.3f}")

def print_reputation_dashboard(agents):
    print("\033[1m[Reputation Dashboard]\033[0m")
    print("  " + "-" * 50)
    for role, data in agents.items():
        rep = data['rep'].get_reputation(data['agent'].eid)
        bar = "█" * int(rep * 10) + "░" * (10 - int(rep * 10))
        name = data['role_obj']['name']
        print(f"  {name:10s} |{bar}| {rep:.3f}")

def print_message(msg):
    role = msg.get('role', 'unknown')
    role_obj = ROLES.get(role, {})
    color = role_obj.get('color', '')
    name = role_obj.get('name', role)
    print(f"{color}\033[1m[{name}]\033[0m {color}{msg['text'][:80]}\033[0m")

class AgentNetwork:
    def __init__(self):
        self.agents: Dict[str, dict] = {}
        self.lock = threading.Lock()
        self.running = True

    def register_agent(self, role: str, agent: IACPAgent) -> dict:
        with self.lock:
            self.agents[role] = {
                'agent': agent, 'rep': ReputationManager(), 'pss': PSSManager(),
                'pom': PoMManager(ReputationManager()), 'role': role,
                'role_obj': ROLES[role], 'sessions': [], 'messages': [], 'connected_peers': []
            }
            self.agents[role]['rep'].register_eid(agent.eid, agent.public_key)
        return self.agents[role]

    def get_agent(self, role: str) -> Optional[dict]:
        with self.lock: return self.agents.get(role)

    def establish_session(self, from_role: str, to_role: str) -> Optional[dict]:
        with self.lock:
            if from_role not in self.agents or to_role not in self.agents: return None
            a, b = self.agents[from_role], self.agents[to_role]
            pss_init = a['pss'].initiate_pss(a['agent'].eid, b['agent'].eid,
                                             a['agent'].private_key, sfc_requested=True)
            pss_neg = b['pss'].process_pss_init(pss_init, responder_eid=b['agent'].eid,
                                                resp_private_key=b['agent'].private_key)
            session = a['pss'].complete_handshake(pss_neg, initiator_eid=a['agent'].eid, responder_eid=b['agent'].eid)
            if session:
                sess_info = {'session_id': session.session_id.hex(), 'state': session.state}
                a['sessions'].append(sess_info)
                b['sessions'].append(sess_info)
                a['connected_peers'].append(to_role)
                b['connected_peers'].append(from_role)
                return sess_info
            return None

    def broadcast_message(self, from_role: str, text: str):
        with self.lock:
            if from_role not in self.agents: return
            sender = self.agents[from_role]
            msg = {'role': from_role, 'text': text, 'timestamp': time.time()}
            sender['messages'].append(msg)
            for peer_role in sender['connected_peers']:
                if peer_role in self.agents:
                    self.agents[peer_role]['messages'].append(msg)

def agent_behavior(network: AgentNetwork, role: str):
    """Simulated agent behavior: establish sessions and exchange messages."""
    roles = list(network.agents.keys())
    for _ in range(3):
        # Connect to all other peers
        for peer in roles:
            if peer != role:
                sess = network.establish_session(role, peer)
                if sess:
                    print(f"\033[93m[SESSION] {role} <-> {peer} established\033[0m")
        # Exchange a message
        network.broadcast_message(role, f"Hello from {role} (t={time.time():.0f})")
        time.sleep(2)
    network.running = False

def run_orchestrated_demo(peer_roles):
    network = AgentNetwork()
    agents = {}
    print("\033[95m\033[1m=== IACP Multi-Agent Demo ===\033[0m\n")
    for role in peer_roles:
        agent = IACPAgent(role)
        agent.start()
        agents[role] = network.register_agent(role, agent)
        print(f"\033[92m[SETUP] {role} started\033[0m")
    print("\033[92m[INIT] All agents ready.\033[0m\n")
    time.sleep(1)
    threads = []
    for role in peer_roles:
        t = threading.Thread(target=agent_behavior, args=(network, role), daemon=True)
        threads.append(t)
        t.start()
    try:
        for t in threads:
            t.join(timeout=45)
    except KeyboardInterrupt:
        print("\033[91m\n[SHUTDOWN]\033[0m")
        network.running = False
    print("\n\033[95m\033[1m=== Demo Complete ===\033[0m")
    for role in peer_roles:
        data = agents[role]
        rep = data['rep'].get_reputation(data['agent'].eid)
        print(f"  {role}: Sessions={len(data['sessions'])}, Rep={rep:.3f}")

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--peers", nargs="+", default=["explorer", "analyst", "diplomat"])
    args = parser.parse_args()
    if args.all:
        run_orchestrated_demo(args.peers)
    else:
        parser.print_help()
