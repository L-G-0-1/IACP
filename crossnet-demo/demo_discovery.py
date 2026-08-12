"""
IACP Complete Demo - All Protocol Components
=============================================

Demonstrates the complete IACP protocol:
1. DHT with Kademlia XOR metric
2. Discovery Spaces (DS_ANNOUNCE, DS_JOIN)
3. Anonymous Discovery with Proof-of-Work
4. Forwarding Tickets for Locator Updates
5. EID Reputation System with EMA
6. Persistent State Sessions (Dual-Cookie Handshake)
7. Ephemeral State Endpoints (Local/Global Points)
8. Anti-Abuse: Token-Bucket and Circuit Breaker
9. Proof of Malfeasance (PoM)
10. Two-Phase Slashing Escrow (2PSE)
11. MIGRATION_VECTOR with Generation Counting

Based on IACP Draft Sections 3.5, 3.6, 4.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.3
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from iacp_protocol import (
    IACPAgent, SimpleDHT, DiscoverySpaceManager, AnonymousDiscovery,
    ForwardingTicketManager, ReputationManager, PSSManager, ESEManager,
    PoMManager, TwoPSEManager, MigrationManager, TokenBucket, CircuitBreaker
)


def print_section(title):
    """Print section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def main():
    print_section("IACP Complete Protocol Demo")
    
    # -----------------------------------------------------------------------
    # Setup: Three Agents with shared DHT
    # -----------------------------------------------------------------------
    print("\n[SETUP] Creating 3 IACP Agents with shared DHT...")
    
    # Shared DHT for all agents
    shared_dht = SimpleDHT(node_id=b"demo-dht-root", port=5000)
    
    agent_a = IACPAgent("Agent-A")
    agent_b = IACPAgent("Agent-B")
    agent_c = IACPAgent("Agent-C")
    
    # Connect agents to shared DHT
    agent_a.dht = shared_dht
    agent_b.dht = shared_dht
    agent_c.dht = shared_dht
    
    # Update managers with shared DHT
    agent_a.ds_manager = DiscoverySpaceManager(shared_dht)
    agent_b.ds_manager = DiscoverySpaceManager(shared_dht)
    agent_c.ds_manager = DiscoverySpaceManager(shared_dht)
    
    agent_a.discovery = AnonymousDiscovery(shared_dht)
    agent_b.discovery = AnonymousDiscovery(shared_dht)
    agent_c.discovery = AnonymousDiscovery(shared_dht)
    
    agent_a.ticket_manager = ForwardingTicketManager(shared_dht)
    agent_b.ticket_manager = ForwardingTicketManager(shared_dht)
    agent_c.ticket_manager = ForwardingTicketManager(shared_dht)
    
    # Wire shared DHT into ESE managers for cross-agent Global Point resolution
    agent_a.ese_manager.set_dht(shared_dht)
    agent_b.ese_manager.set_dht(shared_dht)
    agent_c.ese_manager.set_dht(shared_dht)
    
    agent_a.start()
    agent_b.start()
    agent_c.start()
    
    print(f"\n[SETUP] All agents started with shared DHT")
    print(f"  Agent-A: {agent_a.get_eid_hex()[:16]}...")
    print(f"  Agent-B: {agent_b.get_eid_hex()[:16]}...")
    print(f"  Agent-C: {agent_c.get_eid_hex()[:16]}...")
    
    # -----------------------------------------------------------------------
    # Part 1: Discovery Spaces (Section 6.2)
    # -----------------------------------------------------------------------
    print_section("Part 1: Discovery Spaces (Section 6.2)")
    
    print("\n[DS] Curator Agent-A creates Discovery Space 'marketplace.energy'")
    
    # Agent-A creates Discovery Space
    ds_created = agent_a.ds_manager.announce_ds(
        namespace="org.agentnet",
        topic="marketplace.energy",
        version=1,
        curator_private_key=agent_a.private_key,
        description="Energy Trading Marketplace"
    )
    
    if ds_created:
        ds_id = agent_a.ds_manager.compute_ds_id("org.agentnet", "marketplace.energy", 1)
        print(f"  [{agent_a.name}] [OK] Discovery Space created")
        print(f"    DS_ID: {ds_id.hex()[:16]}...")
    
    print(f"\n[DS] Agent-B and Agent-C join Discovery Space")
    
    # Agent-B joins
    joined_b = agent_b.ds_manager.join_ds(ds_id, agent_b.private_key)
    print(f"  [{agent_b.name}] {'[OK]' if joined_b else '[FAIL]'} joined Discovery Space")
    
    # Agent-C joins
    joined_c = agent_c.ds_manager.join_ds(ds_id, agent_c.private_key)
    print(f"  [{agent_c.name}] {'[OK]' if joined_c else '[FAIL]'} joined Discovery Space")
    
    # -----------------------------------------------------------------------
    # Part 2: Anonymous Discovery with PoW (Section 6.3)
    # -----------------------------------------------------------------------
    print_section("Part 2: Anonymous Discovery with Proof-of-Work (Section 6.3)")
    
    print(f"\n[Discovery] Agent-C searches for Agent-B (without revealing identity)")
    
    # Agent-C creates anonymous discovery request
    disc_req = agent_c.discovery.create_discovery_req(
        target_eid=agent_b.eid,
        requester_private_key=agent_c.private_key,
        difficulty=2
    )
    
    print(f"  [{agent_c.name}] [OK] DISCOVERY_REQ created (Type 0x01)")
    print(f"    Target: {disc_req['target_space_coordinate'][:16]}...")
    print(f"    PoW Nonce: {disc_req['pow_nonce'][:8]}...")
    print(f"    Difficulty: {disc_req['pow_difficulty']}")
    
    # Agent-B responds
    disc_res = agent_b.discovery.create_discovery_res(
        disc_req,
        responder_eid=agent_b.eid,
        responder_private_key=agent_b.private_key
    )
    
    if disc_res:
        print(f"\n  [{agent_b.name}] [OK] DISCOVERY_RES created (Type 0x02)")
        print(f"    Encrypted EID: {disc_res['encrypted_eid'][:16]}...")
    
    # Agent-C decrypts EID
    discovered_eid = agent_c.discovery.process_discovery_res(disc_res, agent_c.private_key)
    
    if discovered_eid:
        print(f"\n  [{agent_c.name}] [OK] Response decrypted")
        print(f"    Discovered EID: {discovered_eid.hex()[:16]}...")
        print(f"    Match: {'[OK]' if discovered_eid == agent_b.eid else '[FAIL]'}")
    
    # -----------------------------------------------------------------------
    # Part 3: Forwarding Tickets (Section 3.5)
    # -----------------------------------------------------------------------
    print_section("Part 3: Forwarding Tickets & DHT-based Locator Resolution")
    
    print(f"\n[Forwarding] Agent-A will go offline, leaves Forwarding Ticket")
    
    # Agent-A creates Forwarding Ticket
    ticket = agent_a.ticket_manager.create_ticket(
        target_eid=agent_a.eid,
        new_locator="10.0.0.99:54321",
        peer_public_key=agent_b.public_key,
        owner_private_key=agent_a.private_key,
        ttl=3600
    )
    
    if ticket:
        print(f"  [{agent_a.name}] [OK] Forwarding Ticket created (Type 0x05)")
        print(f"    Ticket stored in DHT at KEY = SHA-256({agent_a.get_eid_hex()[:16]}...)")
    
    # Agent-B wants to contact Agent-A
    print(f"\n[Forwarding] Agent-B searches for Agent-A after long offline period")
    
    retrieved_ticket = agent_b.ticket_manager.query_ticket(
        agent_a.eid,
        agent_b.private_key
    )
    
    if retrieved_ticket:
        print(f"  [{agent_b.name}] [OK] Forwarding Ticket found")
        print(f"    Decrypted Locator: {retrieved_ticket.get('decrypted_locator', 'N/A')}")
    
    # -----------------------------------------------------------------------
    # Part 4: EID Reputation System (Section 3.6)
    # -----------------------------------------------------------------------
    print_section("Part 4: EID Reputation System (Section 3.6)")
    
    print("\n[Reputation] Initial state:")
    for agent in [agent_a, agent_b, agent_c]:
        rep = agent.reputation_manager.get_reputation(agent.eid)
        print(f"  {agent.name}: Reputation = {rep:.4f}")
    
    print("\n[Reputation] Simulating network activity over multiple epochs...")
    
    # Epoch 1
    print("\n  --- Epoch 1 ---")
    agent_a.reputation_manager.update_reputation(agent_a.eid, {'s_verify': 1.0, 'a_telemetry': 0.99})
    agent_b.reputation_manager.update_reputation(agent_b.eid, {'s_verify': 0.95, 'a_telemetry': 0.90})
    agent_c.reputation_manager.update_reputation(agent_c.eid, {'s_verify': 0.80, 'a_telemetry': 0.85})
    
    for agent in [agent_a, agent_b, agent_c]:
        rep = agent.reputation_manager.get_reputation(agent.eid)
        print(f"  {agent.name}: R_State = {rep:.4f}")
    
    # Epoch 2 (Agent-C commits violation)
    print("\n  --- Epoch 2 (Agent-C: Protocol Violation) ---")
    agent_c.reputation_manager.update_reputation(agent_c.eid, {
        's_verify': 0.70,
        'a_telemetry': 0.75,
        'pom_count': 2
    })
    
    for agent in [agent_a, agent_b, agent_c]:
        rep = agent.reputation_manager.get_reputation(agent.eid)
        record = agent.reputation_manager.eids[agent.eid]
        print(f"  {agent.name}: R_State = {rep:.4f} (PoM_Count = {record.pom_count})")
    
    print("\n[Threshold] Reputation Threshold Enforcement:")
    for agent in [agent_a, agent_b, agent_c]:
        allowed, difficulty = agent.reputation_manager.check_threshold(agent.eid)
        rep = agent.reputation_manager.get_reputation(agent.eid)
        status = "[OK] ALLOWED" if allowed else "[FAIL] BLOCKED"
        print(f"  {agent.name}: R_State = {rep:.4f} -> {status}, PoW Difficulty = {difficulty}")
    
    # -----------------------------------------------------------------------
    # Part 5: Persistent State Sessions (Section 6.4)
    # -----------------------------------------------------------------------
    print_section("Part 5: Persistent State Sessions - Dual-Cookie Handshake")
    
    print(f"\n[PSS] {agent_a.name} initiates session with {agent_b.name}")
    
    # PSS_INIT
    pss_init = agent_a.pss_manager.initiate_pss(
        initiator_eid=agent_a.eid,
        target_eid=agent_b.eid,
        init_private_key=agent_a.private_key,
        sfc_requested=True
    )
    
    if pss_init:
        print(f"\n  [{agent_a.name}] ===> PSS_INIT (Type 0x08)")
        print(f"    I-Cookie: {pss_init['i_cookie'][:8]}...")
    
    # PSS_NEG
    pss_neg = agent_b.pss_manager.process_pss_init(pss_init, responder_eid=agent_b.eid,
                                                   resp_private_key=agent_b.private_key)
    
    if pss_neg:
        print(f"\n  [{agent_b.name}] <=== PSS_NEG (Type 0x0A)")
        print(f"    R-Cookie: {pss_neg['r_cookie'][:8]}...")
        print(f"    SFC Conditions: {pss_neg['sfc_conditions'][:8]}...")
    
    # PSS_ACK
    session = agent_a.pss_manager.complete_handshake(pss_neg, initiator_eid=agent_a.eid, responder_eid=agent_b.eid)
    
    if session:
        print(f"\n  [{agent_a.name}] [OK] PSS Handshake complete!")
        print(f"    Session ID: {session.session_id.hex()[:16]}...")
        print(f"    State: {session.state}")
        print(f"    SFC Active: {session.sfc_active}")
    
    # -----------------------------------------------------------------------
    # Part 6: Ephemeral State Endpoints (Section 6.1)
    # -----------------------------------------------------------------------
    print_section("Part 6: Ephemeral State Endpoints (Section 6.1)")
    
    print(f"\n[ESE] {agent_a.name} creating Discovery endpoints")
    
    # Global Point
    gp = agent_a.ese_manager.create_global_point(
        agent_a.eid,
        "marketplace.energy.discovery"
    )
    print(f"  GP Coordinate: {gp.hex()[:16]}...")
    print(f"    (SHA-256(EID || Tag))")
    
    # Local Point
    lp = agent_a.ese_manager.create_local_point(agent_a.eid, "local.session")
    print(f"\n  Local Point: {lp.hex()[:16]}...")
    print(f"    (Locally accessible only)")
    
    # Agent-B accesses
    gp_data = agent_b.ese_manager.get_endpoint(gp)
    if gp_data:
        print(f"\n  [{agent_b.name}] [OK] GP found: {gp_data.data['tag']}")
    
    # -----------------------------------------------------------------------
    # Part 7: Anti-Abuse Mechanisms (Section 5.4)
    # -----------------------------------------------------------------------
    print_section("Part 7: Anti-Abuse: Token-Bucket & Circuit Breaker")
    
    print(f"\n[Token-Bucket] {agent_a.name}: Capacity=100, Refill=10/s")
    bucket = agent_a.token_bucket
    
    for i in range(25):
        bucket.consume(1)
    
    print(f"  Consumed 25 tokens, remaining: {bucket.tokens:.1f}")
    
    success = bucket.consume(90)
    print(f"  Attempt 90 more: {'[OK] Success' if success else '[FAIL] Blocked'}")
    
    print(f"\n[Circuit Breaker] {agent_b.name}: Threshold=10, Cooldown=60s")
    cb = agent_b.circuit_breaker
    
    for i in range(12):
        cb.record_failure()
    
    print(f"  After 12 failures: {cb.state.value}")
    print(f"  Can execute: {cb.can_execute()}")
    
    # -----------------------------------------------------------------------
    # Part 8: Proof of Malfeasance & 2PSE (Section 4.2.7)
    # -----------------------------------------------------------------------
    print_section("Part 8: Proof of Malfeasance & Two-Phase Slashing Escrow")
    
    print(f"\n[PoM] {agent_c.name} commits Double-Signing (Protocol Violation)")
    
    fragment_a = b"IP=10.0.0.1|Gen=5|Sig=0xabc"
    fragment_b = b"IP=10.0.0.2|Gen=5|Sig=0xdef"
    
    pom_ticket = agent_b.pom_manager.create_pom_ticket(
        target_eid=agent_c.eid,
        fragment_a=fragment_a,
        fragment_b=fragment_b,
        accuser_eid=agent_b.eid
    )
    
    if pom_ticket:
        print(f"  [{agent_b.name}] [OK] PoM Ticket created")
        valid = agent_b.pom_manager.validate_pom_ticket(pom_ticket)
        print(f"    Valid: {valid}")
    
    print(f"\n[2PSE] Starting escrow for {agent_c.name}...")
    agent_b.twopse_manager.initiate_escrow(agent_c.eid)
    
    escrow_state = agent_b.twopse_manager.get_escrow_state(agent_c.eid)
    print(f"  Escrow State: {escrow_state}")
    print(f"  Duration: 3600s (1 hour)")
    
    rep_after = agent_c.reputation_manager.get_reputation(agent_c.eid)
    print(f"\n  [{agent_c.name}] Reputation: {rep_after:.4f}")
    print(f"  [{agent_c.name}] Is blocked: {agent_c.reputation_manager.is_blocked(agent_c.eid)}")
    
    # -----------------------------------------------------------------------
    # Part 9: MIGRATION_VECTOR (Section 4.2.5.1)
    # -----------------------------------------------------------------------
    print_section("Part 9: MIGRATION_VECTOR and Generation Counting")
    
    print(f"\n[Migration] {agent_a.name} changes network (WiFi -> Mobile)")
    
    migration = agent_a.migration_manager.create_migration_vector(
        source_eid=agent_a.eid,
        new_locator="10.0.0.50:12345",
        private_key=agent_a.private_key
    )
    
    if migration:
        print(f"  [{agent_a.name}] [OK] MIGRATION_VECTOR created (Type 0x17)")
        print(f"    Generation Counter: {migration['generation_counter']}")
    
    # Agent-B processes
    success, new_gen = agent_b.migration_manager.process_migration_vector(migration)
    
    if success:
        print(f"\n  [{agent_b.name}] [OK] Migration processed")
        print(f"    New Generation: {new_gen}")
    
    print(f"\n[Generation Counting] Incoming packet validation:")
    
    # process_migration_vector already registered agent_a (bootstrap-safe)
    # Test EQUAL first (cache still at new_gen), then NEWER (updates cache),
    # then STALE (relative to updated cache)
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
    print_section("Summary")
    
    print(f"\n[OK] DHT & Discovery:")
    print(f"  - SimpleDHT with Kademlia XOR metric")
    print(f"  - Discovery Spaces (DS_ANNOUNCE, DS_JOIN)")
    print(f"  - Anonymous Discovery with PoW")
    print(f"  - Forwarding Tickets for locator updates")
    
    print(f"\n[OK] Reputation & Governance:")
    print(f"  - EMA Reputation: alpha=0.12, w1=0.45, w2=0.35, w3=0.20")
    print(f"  - Threshold Enforcement: R_Threshold=0.7")
    print(f"  - Dynamic PoW Escalation")
    print(f"  - Proof of Malfeasance (PoM)")
    print(f"  - Two-Phase Slashing Escrow (2PSE)")
    
    print(f"\n[OK] Sessions & Endpoints:")
    print(f"  - Persistent State Sessions (PSS) with Dual-Cookie")
    print(f"  - Session Federation Contracts (SFC)")
    print(f"  - Ephemeral State Endpoints (ESE)")
    print(f"  - Global Points & Local Points")
    
    print(f"\n[OK] Mobility & Fault Tolerance:")
    print(f"  - MIGRATION_VECTOR with Generation Counting")
    print(f"  - Cache Invalidation when Gen_New > Gen_Cache")
    print(f"  - Stale Frame Dropping when Gen_Old < Gen_Cache")
    
    print(f"\n[OK] Anti-Abuse:")
    print(f"  - Token-Bucket Rate Limiter")
    print(f"  - Circuit Breaker (STATE_CLOSED <-> STATE_OPEN)")
    
    print(f"\n{'=' * 80}")
    print(" Demo completed successfully!")
    print(f"{'=' * 80}\n")


if __name__ == "__main__":
    main()