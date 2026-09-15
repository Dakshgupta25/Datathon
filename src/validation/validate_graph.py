"""
TraceONE Evidence-Backed Investigation Graph Validation Suite
Phase H: Step 14 - Graph Validation

Verifies unique node IDs, unique edge IDs, valid source and target endpoints,
provenance completeness, relationship confidence bounds, self-loop prevention,
duplicate edge prevention, and real-data investigation scenarios.
"""

from pathlib import Path
import json
import sys
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def run_graph_validation():
    print("=" * 70)
    print("TRACEONE INVESTIGATION GRAPH VALIDATION (PHASE H)")
    print("=" * 70)

    nodes_df = pd.read_csv(PROCESSED_DIR / "graph_nodes.csv")
    edges_df = pd.read_csv(PROCESSED_DIR / "graph_edges.csv")

    with open(PROCESSED_DIR / "graph_metadata.json") as f:
        metadata = json.load(f)

    with open(PROCESSED_DIR / "investigation_scenarios.json") as f:
        scenarios = json.load(f)

    passed_checks = 0
    total_checks = 0

    def assert_check(condition, name, msg=""):
        nonlocal passed_checks, total_checks
        total_checks += 1
        if condition:
            passed_checks += 1
            print(f" [PASS] {name}")
        else:
            print(f"![FAIL] {name}: {msg}")

    # Check 1: Unique Node IDs
    unique_nodes = len(nodes_df) == nodes_df['node_id'].nunique()
    assert_check(unique_nodes, "Unique Node IDs", f"Total: {len(nodes_df)}, Unique: {nodes_df['node_id'].nunique()}")

    # Check 2: Unique Edge IDs
    unique_edges = len(edges_df) == edges_df['edge_id'].nunique()
    assert_check(unique_edges, "Unique Edge IDs", f"Total: {len(edges_df)}, Unique: {edges_df['edge_id'].nunique()}")

    # Check 3: Valid Source Node Endpoints
    valid_node_set = set(nodes_df['node_id'])
    valid_sources = set(edges_df['source_id']).issubset(valid_node_set)
    assert_check(valid_sources, "Valid Source Node Endpoints", "Unmatched source IDs found")

    # Check 4: Valid Target Node Endpoints
    valid_targets = set(edges_df['target_id']).issubset(valid_node_set)
    assert_check(valid_targets, "Valid Target Node Endpoints", "Unmatched target IDs found")

    # Check 5: Valid Relationship Types
    valid_rel_types = {'BELONGS_TO', 'ASSOCIATED_WITH_HOST', 'AUTHENTICATED_VIA',
                       'CONNECTED_FROM_IP', 'COMMUNICATED_WITH_IP', 'TRIGGERED_EVENT',
                       'INVOLVED_IN_SEQUENCE', 'SEQUENCE_INCLUDES_EVENT',
                       'HAS_RISK_ASSESSMENT', 'SUPPORTED_BY_EVIDENCE'}
    rel_valid = set(edges_df['relationship_type']).issubset(valid_rel_types)
    assert_check(rel_valid, "Valid Relationship Types", f"Unexpected types: {set(edges_df['relationship_type']) - valid_rel_types}")

    # Check 6: Provenance Completeness (source_dataset & source_record_id non-null)
    prov_complete = (edges_df['source_dataset'].notna().all() and 
                     edges_df['source_record_id'].notna().all() and
                     (edges_df['source_dataset'] != 'Unknown').all())
    assert_check(prov_complete, "Edge Provenance Completeness", "Missing or Unknown dataset provenance found in edges")

    # Check 7: Relationship Confidence Categories
    valid_conf_set = {'EXACT', 'PROBABLE', 'UNMATCHED'}
    conf_valid = set(edges_df['relationship_confidence']).issubset(valid_conf_set)
    assert_check(conf_valid, "Relationship Confidence Categories", f"Unexpected confidence values: {set(edges_df['relationship_confidence']) - valid_conf_set}")

    # Check 8: Self-Loop Prevention (source_id != target_id)
    no_self_loops = (edges_df['source_id'] != edges_df['target_id']).all()
    assert_check(no_self_loops, "Self-Loop Prevention", "Self-loop edge detected")

    # Check 9: Duplicate Edge Prevention
    dup_edges = edges_df.duplicated(subset=['source_id', 'target_id', 'relationship_type']).sum() == 0
    assert_check(dup_edges, "Duplicate Edge Prevention", "Duplicate edge tuples detected")

    # Check 10: Real-Data Investigation Scenarios Generated
    scenarios_valid = len(scenarios) >= 4 and all('investigation_context' in s for s in scenarios)
    assert_check(scenarios_valid, "Real-Data Investigation Scenarios Completeness", f"Valid scenarios: {len(scenarios)}")

    print("-" * 70)
    print(f"VALIDATION SUMMARY: {passed_checks}/{total_checks} CHECKS PASSED")
    print("=" * 70)

    if passed_checks < total_checks:
        sys.exit(1)


if __name__ == "__main__":
    run_graph_validation()
