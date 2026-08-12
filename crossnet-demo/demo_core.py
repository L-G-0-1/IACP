"""
IACP Core Demo - Full Protocol Walkthrough
===========================================

Demonstrates all core components from iacp_protocol.py:
1. EID Reputation System with EMA and Threshold Enforcement
2. Persistent State Sessions (PSS) with Dual-Cookie Handshake
3. Ephemeral State Endpoints (ESE) - Local and Global Points
4. Anti-Abuse Mechanisms (Token-Bucket, Circuit Breaker)
5. Proof of Malfeasance (PoM) and Two-Phase Slashing Escrow (2PSE)
6. MIGRATION_VECTOR with Generation Counting
7. ERP State Machine (UNBOUND -> ALLOCATED -> TRANSITION -> BOUND)

Based on IACP Draft Sections 3.6, 4.2, 5.3, 5.4, 5.5, 6.1, 6.4
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iacp_protocol import (
    IACPAgent, LLContext, ReputationManager, PSSManager, ESEManager,
    PoMManager, TwoPSEManager, MigrationManager, TokenBucket, CircuitBreaker,
    SimpleDHT,
)


def print_section(title):
    """Print section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def main():
    print_section("IACP Core Protocol Demo - PSS, Reputation, PoM, ESE")

    # -----------------------------------------------------------------------
    # Setup: Three Agents
    # -----------------------------------------------------------------------
    print("\n[SETUP] Creating 3 IACP Agents...")

    agent_a = IACPAgent("Agent-A")
    agent_b = IACPAgent("Agent-B")
    agent_c = IACPAgent("Agent-C")

    shared_dht = SimpleDHT(node_id=b"demo-core-dht", port=5001)
    agent_a.ese_manager.set_dht(shared_dht)
    agent_b.ese_manager.set_dht(shared_dht)
    agent_c.ese_manager.set_dht(shared_dht)

    agent_a.start()
    agent_b.start()
    agent_c.start()

    print(f"\n[SETUP] All agents started")
    print(f"  Agent-A: {agent_a.get_eid_hex()[:16]}...")
    print(f"  Agent-B: {agent_b.get_eid_hex()[:16]}...")
    print(f"  Agent-C: {agent_c.get_eid_hex()[:16]}...")

    # -----------------------------------------------------------------------
    # Part 1: EID Reputation System (Section 3.6)
    # -----------------------------------------------------------------------
    print_section("Part 1: EID Reputation System (Section 3.6)")

    print("\n[Reputation] Initial state:")
    for agent in [agent_a, agent_b, agent_c]:
        rep = agent.reputation_manager.get_reputation(agent.eid)
        print(f"  {agent.name}: Reputation = {rep:.4f} (R_State(0) = 1.0)")

    print("\n[Reputation] Simulating network activity...")
    print("  - Agent-A: 100% valid signatures, 99% availability")
    print("  - Agent-B: 95% valid signatures, 90% availability")
    print("  - Agent-C: 80% valid signatures, 85% availability, 1 PoM")

    agent_a.reputation_manager.update_reputation(agent_a.eid, {'s_verify': 1.0, 'a_telemetry': 0.99})
    agent_b.reputation_manager.update_reputation(agent_b.eid, {'s_verify': 0.95, 'a_telemetry': 0.90})
    agent_c.reputation_manager.update_reputation(agent_c.eid, {'s_verify': 0.80, 'a_telemetry': 0.85, 'pom_count': 1})

    print("\n[Reputation] After one evaluation epoch:")
    for agent in [agent_a, agent_b, agent_c]:
        rep = agent.reputation_manager.get_reputation(agent.eid)
        record = agent.reputation_manager.eids[agent.eid]
        print(f"  {agent.name}: Reputation = {rep:.4f} (PoM_Count = {record.pom_count})")

    print("\n[Threshold] Reputation Threshold Enforcement (R_Threshold = 0.7):")
    for agent in [agent_a, agent_b, agent_c]:
        allowed, difficulty = agent.reputation_manager.check_threshold(agent.eid)
        rep = agent.reputation_manager.get_reputation(agent.eid)
        status = "[OK] ALLOWED" if allowed else "[FAIL] BLOCKED"
        print(f"  {agent.name}: R_State = {rep:.4f} -> {status}, PoW Difficulty = {difficulty}")

    # -----------------------------------------------------------------------
    # Part 2: Persistent State Sessions (Section 6.4)
    # -----------------------------------------------------------------------
    print_section("Part 2: Persistent State Sessions - Dual-Cookie Handshake")

    print(f"\n[PSS] {agent_a.name} initiates session with {agent_b.name} (with SFC)")

    pss_init = agent_a.pss_manager.initiate_pss(agent_a.eid, agent_b.eid,
                                                agent_a.private_key, sfc_requested=True)

    if pss_init:
        print(f"\n  [{agent_a.name}] ===> PSS_INIT (Type 0x08)")
        print(f"    I-Cookie: {pss_init['i_cookie'][:8]}...")
        print(f"    SFC Requested: {pss_init['sfc_requested']}")

    pss_neg = agent_b.pss_manager.process_pss_init(pss_init, responder_eid=agent_b.eid,
                                                   resp_private_key=agent_b.private_key)

    if pss_neg:
        print(f"\n  [{agent_b.name}] <=== PSS_NEG (Type 0x0A)")
        print(f"    R-Cookie: {pss_neg['r_cookie'][:8]}...")
        print(f"    SFC Conditions: {pss_neg['sfc_conditions'][:8]}...")

    session = agent_a.pss_manager.complete_handshake(pss_neg, initiator_eid=agent_a.eid, responder_eid=agent_b.eid)

    if session:
        print(f"\n  [{agent_a.name}] [OK] PSS Handshake complete!")
        print(f"    Session ID: {session.session_id.hex()[:16]}...")
        print(f"    State: {session.state}")
        print(f"    SFC Active: {session.sfc_active}")

    # -----------------------------------------------------------------------
    # Part 3: Ephemeral State Endpoints (Section 6.1)
    # -----------------------------------------------------------------------
    print_section("Part 3: Ephemeral State Endpoints (Section 6.1)")

    print(f"\n[ESE] {agent_a.name} creating endpoints...")

    gp = agent_a.ese_manager.create_global_point(agent_a.eid, "discovery.endpoint")
    print(f"  Global Point: {gp.hex()[:16]}...")

    lp = agent_a.ese_manager.create_local_point(agent_a.eid, "local.cache")
    print(f"  Local Point: {lp.hex()[:16]}...")

    gp_data = agent_b.ese_manager.get_endpoint(gp)
    if gp_data:
        print(f"  [{agent_b.name}] [OK] GP found: {gp_data.data['tag']}")

    # -----------------------------------------------------------------------
    # Part 4: Anti-Abuse (Section 5.4)
    # -----------------------------------------------------------------------
    print_section("Part 4: Anti-Abuse: Token-Bucket & Circuit Breaker")

    bucket = TokenBucket(capacity=100, refill_rate=10)
    for i in range(25):
        bucket.consume(1)
    print(f"  Token-Bucket: 25 consumed, {bucket.tokens:.1f} remaining")

    cb = CircuitBreaker(threshold=5, cooldown=60)
    for i in range(7):
        cb.record_failure()
    print(f"  Circuit Breaker: State = {cb.state.value}")

    # -----------------------------------------------------------------------
    # Part 5: Proof of Malfeasance (Section 4.2.7)
    # -----------------------------------------------------------------------
    print_section("Part 5: Proof of Malfeasance & Two-Phase Slashing Escrow")

    print(f"\n[PoM] {agent_c.name} commits protocol violation (Double-Signing)")

    f_a = b"IP=10.0.0.1|Gen=5|Sig=0xabc"
    f_b = b"IP=10.0.0.2|Gen=5|Sig=0xdef"

    pom = agent_b.pom_manager.create_pom_ticket(agent_c.eid, f_a, f_b, agent_b.eid)
    if pom:
        print(f"  [{agent_b.name}] [OK] PoM Ticket created")
        print(f"    Target: {pom.target_eid.hex()[:16]}...")
        print(f"    Valid: {agent_b.pom_manager.validate_pom_ticket(pom)}")

    print(f"\n[2PSE] Starting escrow for {agent_c.name}...")
    agent_b.twopse_manager.initiate_escrow(agent_c.eid)
    escrow_state = agent_b.twopse_manager.get_escrow_state(agent_c.eid)
    print(f"  Escrow State: {escrow_state}")
    print(f"  Duration: 3600s (1 hour)")

    # -----------------------------------------------------------------------
    # Part 6: MIGRATION_VECTOR (Section 4.2.5.1)
    # -----------------------------------------------------------------------
    print_section("Part 6: MIGRATION_VECTOR and Generation Counting")

    print(f"\n[Migration] {agent_a.name} changes network (WiFi -> Mobile)")

    migration = agent_a.migration_manager.create_migration_vector(
        agent_a.eid, "10.0.0.50:12345", agent_a.private_key
    )
    if migration:
        print(f"  [{agent_a.name}] [OK] MIGRATION_VECTOR created (Type 0x17)")
        print(f"    Generation Counter: {migration['generation_counter']}")

    success, new_gen = agent_b.migration_manager.process_migration_vector(migration)
    if success:
        print(f"\n  [{agent_b.name}] [OK] Migration processed")
        print(f"    New Generation: {new_gen}")
        print(f"    New Locator: 10.0.0.50:12345")

    print(f"\n[Generation Counting] Incoming packet validation:")
    test_cases = [
        (new_gen, "EQUAL", True),
        (new_gen + 1, "NEWER", True),
        (new_gen - 1, "STALE", False),
    ]
    for test_gen, desc, expected in test_cases:
        result = agent_b.migration_manager.validate_generation(agent_a.eid, test_gen)
        status = "[OK] ACCEPT" if result else "[FAIL] DROP"
        match = "[OK]" if (result == expected) else "[FAIL]"
        print(f"  Gen={test_gen} ({desc:6s}): {status} {match}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print_section("Demo Complete")
    print("\nAll core IACP protocol components demonstrated:\n")
    print("  [OK] EID Reputation System (EMA)")
    print("  [OK] Persistent State Sessions (Dual-Cookie)")
    print("  [OK] Session Federation Contract (SFC)")
    print("  [OK] Ephemeral State Endpoints (GP/LP)")
    print("  [OK] Token-Bucket & Circuit Breaker")
    print("  [OK] Proof of Malfeasance (PoM)")
    print("  [OK] Two-Phase Slashing Escrow (2PSE)")
    print("  [OK] MIGRATION_VECTOR & Generation Counting\n")


if __name__ == "__main__":
    main()