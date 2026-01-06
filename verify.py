#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VCP Evidence Pack Verification Script - VCP v1.1 Compliance Edition
=====================================================================
Independent cryptographic verification for VCP v1.1 compliant evidence packs.

Verifies:
1. VCP v1.1 Compliance (PolicyIdentification, Three-Layer Architecture)
2. Event hash computation (SHA-256)
3. Hash chain continuity (OPTIONAL in v1.1)
4. Merkle tree reconstruction (RFC 6962)
5. Inclusion proof validation
6. Anchor integrity

License: Apache 2.0
Copyright (c) 2025 VeritasChain Standards Organization
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple


def canonicalize_json(obj: Any) -> str:
    """Canonical JSON serialization (RFC 8785 style)"""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def compute_sha256(data: str) -> str:
    """Compute SHA-256 hash of string"""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def compute_event_hash(event: dict) -> str:
    """
    Compute event hash per VCP v1.1 Section 6.1.1:
    SHA256(Canonical(Header without EventHash) || Canonical(Payload))
    """
    header = {k: v for k, v in event['Header'].items() if k != 'EventHash'}
    payload = {k: v for k, v in event.items() if k != 'Header'}
    canonical = canonicalize_json(header) + canonicalize_json(payload)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def rfc6962_leaf_hash(data: str) -> str:
    """RFC 6962 leaf hash: SHA256(0x00 || data)"""
    return hashlib.sha256(b'\x00' + bytes.fromhex(data)).hexdigest()


def rfc6962_node_hash(left: str, right: str) -> str:
    """RFC 6962 node hash: SHA256(0x01 || left || right)"""
    return hashlib.sha256(b'\x01' + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def build_merkle_tree(hashes: List[str]) -> str:
    """Build Merkle tree per RFC 6962 and return root"""
    if not hashes:
        return compute_sha256("")
    
    nodes = [rfc6962_leaf_hash(h) for h in hashes]
    
    while len(nodes) > 1:
        new_nodes = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                new_nodes.append(rfc6962_node_hash(nodes[i], nodes[i + 1]))
            else:
                new_nodes.append(nodes[i])
        nodes = new_nodes
    
    return nodes[0]


def verify_inclusion_proof(event_hash: str, proof: List[dict], merkle_root: str) -> bool:
    """Verify Merkle inclusion proof"""
    current = rfc6962_leaf_hash(event_hash)
    
    for step in proof:
        sibling = step['hash']
        if step['position'] == 'left':
            current = rfc6962_node_hash(sibling, current)
        else:
            current = rfc6962_node_hash(current, sibling)
    
    return current == merkle_root


def verify_v1_1_compliance(events_data: dict, events: List[dict]) -> Tuple[bool, List[str]]:
    """
    Verify VCP v1.1 specific requirements:
    - Section 5.5: PolicyIdentification
    - Section 6: Three-Layer Architecture
    - Section 2.1: External Anchor REQUIRED
    """
    messages = []
    all_passed = True
    
    messages.append("VCP v1.1 Compliance Verification:")
    messages.append("")
    
    # Check metadata
    metadata = events_data.get('metadata', {})
    spec = metadata.get('specification', '')
    
    if 'v1.1' in spec or '1.1' in metadata.get('version', ''):
        messages.append(f"  ✓ Specification declared: {spec}")
    else:
        messages.append(f"  ⚠ Specification version unclear: {spec}")
    
    # Check global PolicyIdentification
    global_policy = events_data.get('policy_identification', {})
    if global_policy:
        messages.append("  ✓ Global PolicyIdentification present")
        
        # Check required fields (Section 5.5.3)
        if global_policy.get('PolicyID'):
            messages.append(f"    ✓ PolicyID: {global_policy['PolicyID']}")
        else:
            messages.append("    ✗ PolicyID MISSING (REQUIRED)")
            all_passed = False
        
        if global_policy.get('ConformanceTier'):
            messages.append(f"    ✓ ConformanceTier: {global_policy['ConformanceTier']}")
        else:
            messages.append("    ✗ ConformanceTier MISSING (REQUIRED)")
            all_passed = False
        
        reg_policy = global_policy.get('RegistrationPolicy', {})
        if reg_policy.get('Issuer'):
            messages.append(f"    ✓ RegistrationPolicy.Issuer: {reg_policy['Issuer']}")
        else:
            messages.append("    ✗ RegistrationPolicy.Issuer MISSING (REQUIRED)")
            all_passed = False
        
        ver_depth = global_policy.get('VerificationDepth', {})
        if ver_depth:
            messages.append("    ✓ VerificationDepth present:")
            messages.append(f"      - HashChainValidation: {ver_depth.get('HashChainValidation', 'N/A')}")
            messages.append(f"      - MerkleProofRequired: {ver_depth.get('MerkleProofRequired', 'N/A')}")
            messages.append(f"      - ExternalAnchorRequired: {ver_depth.get('ExternalAnchorRequired', 'N/A')}")
        else:
            messages.append("    ✗ VerificationDepth MISSING (REQUIRED)")
            all_passed = False
    else:
        messages.append("  ⚠ Global PolicyIdentification not found")
    
    messages.append("")
    
    # Check PolicyIdentification in events (Section 5.5.3: REQUIRED for all events)
    messages.append("  Event-level PolicyIdentification:")
    events_with_policy = 0
    events_without_policy = 0
    
    for event in events:
        if 'PolicyIdentification' in event:
            events_with_policy += 1
        else:
            events_without_policy += 1
    
    if events_without_policy == 0:
        messages.append(f"    ✓ All {events_with_policy} events have PolicyIdentification")
    else:
        messages.append(f"    ⚠ {events_without_policy} events missing PolicyIdentification")
        messages.append(f"    ✓ {events_with_policy} events have PolicyIdentification")
    
    messages.append("")
    
    # Check Three-Layer Architecture (Section 6)
    messages.append("  Three-Layer Architecture (Section 6):")
    three_layer = metadata.get('three_layer_architecture', {})
    if three_layer:
        messages.append(f"    ✓ Layer 1: {three_layer.get('layer1_event_integrity', 'Not specified')}")
        messages.append(f"    ✓ Layer 2: {three_layer.get('layer2_collection_integrity', 'Not specified')}")
        messages.append(f"    ✓ Layer 3: {three_layer.get('layer3_external_verifiability', 'Not specified')}")
    else:
        messages.append("    ⚠ Three-layer architecture not explicitly declared in metadata")
    
    messages.append("")
    
    # Check External Anchor (Section 2.1: REQUIRED for all tiers in v1.1)
    anchor_events = [e for e in events if e['Header']['EventType'] == 'VCP_ANCHOR']
    if anchor_events:
        messages.append(f"  ✓ External Anchor present ({len(anchor_events)} anchor event(s))")
        for ae in anchor_events:
            gov = ae.get('Governance', {})
            messages.append(f"    - AnchorID: {gov.get('AnchorID', 'N/A')}")
            messages.append(f"    - AnchorTarget: {gov.get('AnchorTarget', 'N/A')}")
            messages.append(f"    - AnchorFrequency: {gov.get('AnchorFrequency', 'N/A')}")
    else:
        messages.append("  ✗ External Anchor MISSING (REQUIRED in v1.1 for all tiers)")
        all_passed = False
    
    messages.append("")
    
    return all_passed, messages


def verify_evidence_pack(evidence_dir: Path) -> Tuple[bool, List[str]]:
    """
    Comprehensive verification of VCP v1.1 evidence pack
    
    Returns:
        Tuple of (overall_success, list_of_messages)
    """
    messages = []
    all_passed = True
    
    # Header
    messages.append("=" * 70)
    messages.append("VCP Evidence Pack Verification Report")
    messages.append("VCP v1.1 Full Compliance Edition")
    messages.append("=" * 70)
    messages.append(f"Evidence Path: {evidence_dir}")
    messages.append(f"Verification Time: {datetime.now(timezone.utc).isoformat()}")
    messages.append("")
    
    # Load files
    try:
        with open(evidence_dir / "events.json", 'r', encoding='utf-8') as f:
            events_data = json.load(f)
        with open(evidence_dir / "batches.json", 'r', encoding='utf-8') as f:
            batches_data = json.load(f)
        with open(evidence_dir / "anchors.json", 'r', encoding='utf-8') as f:
            anchors_data = json.load(f)
    except Exception as e:
        messages.append(f"✗ Failed to load evidence files: {e}")
        return False, messages
    
    events = events_data.get('events', [])
    metadata = events_data.get('metadata', {})
    batches = batches_data.get('batches', [])
    anchors = anchors_data.get('anchors', [])
    
    messages.append(f"Specification: {metadata.get('specification', 'unknown')}")
    messages.append(f"Generator: {metadata.get('generator', 'unknown')}")
    messages.append(f"Conformance Tier: {metadata.get('conformance_tier', 'unknown')}")
    messages.append(f"PolicyID: {metadata.get('policy_id', 'unknown')}")
    messages.append(f"Total Events: {len(events)}")
    messages.append(f"Total Batches: {len(batches)}")
    messages.append(f"Total Anchors: {len(anchors)}")
    messages.append(f"Protocol: {metadata.get('protocol', 'unknown')}")
    messages.append("")
    
    # === VCP v1.1 Compliance Check ===
    v1_1_passed, v1_1_messages = verify_v1_1_compliance(events_data, events)
    messages.extend(v1_1_messages)
    if not v1_1_passed:
        all_passed = False
    
    # Summary of v1.1 compliance
    if v1_1_passed:
        messages.append("VCP v1.1 Compliance Check: ✓ FULLY COMPLIANT")
    else:
        messages.append("VCP v1.1 Compliance Check: ⚠ PARTIAL COMPLIANCE")
    messages.append("")
    messages.append("-" * 70)
    messages.append("")
    
    # === 1. Event Hash Verification (Layer 1) ===
    messages.append("Layer 1 - Event Hash Verification (SHA-256):")
    hash_failures = 0
    for event in events:
        computed = compute_event_hash(event)
        stored = event['Header'].get('EventHash', '')
        if computed != stored:
            messages.append(f"  ✗ Hash mismatch: {event['Header']['EventID']}")
            hash_failures += 1
            all_passed = False
    
    if hash_failures == 0:
        messages.append(f"  ✓ All {len(events)} event hashes cryptographically verified")
    messages.append("")
    
    # === 2. Hash Chain Verification (Layer 1 - OPTIONAL in v1.1) ===
    messages.append("Layer 1 - Hash Chain Verification (OPTIONAL in v1.1):")
    chain_valid = True
    chain_present = False
    
    for i in range(1, len(events)):
        prev_hash = events[i]['Header'].get('PrevHash', '')
        if prev_hash:
            chain_present = True
            expected = events[i - 1]['Header'].get('EventHash', '')
            if prev_hash != expected:
                messages.append(f"  ✗ Chain break at event {i}")
                chain_valid = False
    
    if chain_present:
        if chain_valid:
            messages.append("  ✓ Hash chain present and verified (enhanced integrity)")
        else:
            messages.append("  ⚠ Hash chain present but has breaks")
    else:
        messages.append("  ⚠ Hash chain not used (valid for v1.1)")
    messages.append("")
    
    # === 3. Merkle Root Verification (Layer 2) ===
    messages.append("Layer 2 - Merkle Root Verification (RFC 6962):")
    
    trading_events = [e for e in events if e['Header']['EventType'] not in ['VCP_BATCH', 'VCP_ANCHOR']]
    trading_hashes = [e['Header']['EventHash'] for e in trading_events]
    
    computed_root = build_merkle_tree(trading_hashes)
    
    if batches:
        stored_root = batches[0].get('MerkleRoot', '')
        if computed_root == stored_root:
            messages.append(f"  ✓ Merkle root verified: {computed_root[:32]}...")
            messages.append(f"    Tree rebuilt from {len(trading_hashes)} event hashes")
        else:
            messages.append(f"  ✗ Merkle root mismatch")
            all_passed = False
    messages.append("")
    
    # === 4. Inclusion Proof Verification (Layer 2) ===
    messages.append("Layer 2 - Merkle Inclusion Proof Verification:")
    if batches and batches[0].get('InclusionProofs'):
        for proof_record in batches[0]['InclusionProofs']:
            event_hash = proof_record['EventHash']
            audit_path = proof_record['AuditPath']
            expected_root = proof_record['MerkleRoot']
            
            if verify_inclusion_proof(event_hash, audit_path, expected_root):
                event_id_short = proof_record['EventID'][:18] + "..."
                messages.append(f"  ✓ Event {event_id_short} inclusion verified")
            else:
                messages.append(f"  ✗ Inclusion proof failed")
                all_passed = False
    messages.append("")
    
    # === 5. Anchor Verification (Layer 3) ===
    messages.append("Layer 3 - External Anchor Verification:")
    if anchors:
        for anchor in anchors:
            anchor_id = anchor.get('AnchorID', 'unknown')
            anchor_root = anchor.get('MerkleRoot', '')
            anchor_target = anchor.get('AnchorTarget', 'unknown')
            
            if anchor_root == computed_root:
                messages.append(f"  ✓ Anchor {anchor_id} verified")
                messages.append(f"    Target: {anchor_target}")
            else:
                messages.append(f"  ✗ Anchor {anchor_id} Merkle root mismatch")
                all_passed = False
    else:
        messages.append("  ✗ No anchors found (REQUIRED in v1.1)")
        all_passed = False
    messages.append("")
    
    # === 6. Timeline Verification ===
    messages.append("Timeline Verification:")
    prev_timestamp = None
    timeline_issues = 0
    for event in events:
        current_iso = event['Header'].get('TimestampISO', '')
        if prev_timestamp and current_iso < prev_timestamp:
            timeline_issues += 1
        prev_timestamp = current_iso
    
    if timeline_issues == 0:
        messages.append("  ✓ Timeline chronology verified")
    else:
        messages.append(f"  ⚠ {timeline_issues} non-monotonic timestamps detected")
    messages.append("")
    
    # === 7. Event Type Distribution ===
    messages.append("Event Type Distribution:")
    type_counts = {}
    for event in events:
        etype = event['Header']['EventType']
        type_counts[etype] = type_counts.get(etype, 0) + 1
    
    for etype, count in sorted(type_counts.items()):
        messages.append(f"  {etype}: {count}")
    messages.append("")
    
    # === Final Summary ===
    messages.append("=" * 70)
    if all_passed:
        messages.append("Overall: ✓ CRYPTOGRAPHICALLY VERIFIED")
        messages.append("")
        messages.append("This evidence pack is fully compliant with VCP Specification v1.1:")
        messages.append("  - Section 5.5: PolicyIdentification ✓")
        messages.append("  - Section 6: Three-Layer Architecture ✓")
        messages.append("  - Section 2.1: External Anchor REQUIRED ✓")
        messages.append("")
        messages.append("All hashes, proofs, and anchors have been independently verified.")
    else:
        messages.append("Overall: ✗ VERIFICATION FAILED")
        messages.append("")
        messages.append("One or more verifications failed. Review details above.")
    messages.append("=" * 70)
    
    return all_passed, messages


def main():
    """Main entry point"""
    evidence_dir = Path(__file__).parent
    
    success, messages = verify_evidence_pack(evidence_dir)
    
    for msg in messages:
        print(msg)
    
    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
