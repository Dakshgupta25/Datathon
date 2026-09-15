"""
TraceONE Evidence-Backed Investigation Graph Builder
Phase H: Graph Construction Engine

Builds deterministic, evidence-backed node and edge tables linking Users,
Departments, Hosts, Sessions, IPs, Events, Temporal Sequences, and Risk Assessments.
Preserves exact source record provenance and relationship confidence.
"""

from pathlib import Path
import json
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def build_investigation_graph():
    print("=" * 70)
    print("TRACEONE INVESTIGATION GRAPH BUILDER (PHASE H)")
    print("=" * 70)

    users_df = pd.read_csv(PROCESSED_DIR / "canonical_users.csv")
    hosts_df = pd.read_csv(PROCESSED_DIR / "canonical_hosts.csv")
    sessions_df = pd.read_csv(PROCESSED_DIR / "canonical_sessions.csv")
    events_df = pd.read_csv(PROCESSED_DIR / "canonical_events.csv")
    rel_df = pd.read_csv(PROCESSED_DIR / "canonical_relationships.csv")
    risk_df = pd.read_csv(PROCESSED_DIR / "traceone_risk_scores.csv")
    seq_df = pd.read_csv(PROCESSED_DIR / "temporal_sequences.csv")
    seq_ev_df = pd.read_csv(PROCESSED_DIR / "temporal_evidence.csv")
    risk_ev_df = pd.read_csv(PROCESSED_DIR / "normalized_evidence_table.csv")

    nodes = []
    edges = []
    edge_counter = 10000

    # ---------------------------------------------------------
    # 1. BUILD NODES
    # ---------------------------------------------------------
    print("Building Graph Nodes...")

    # USER Nodes
    for idx, r in users_df.iterrows():
        nodes.append({
            'node_id': str(r['user_id']),
            'node_type': 'USER',
            'label': str(r['username']),
            'department': str(r['department']),
            'status': str(r['status']),
            'source_dataset': 'canonical_users',
            'source_record_id': str(r['user_id'])
        })

    # DEPARTMENT Nodes
    departments = users_df['department'].unique()
    for d in departments:
        nodes.append({
            'node_id': f"DEPT-{d.upper().replace(' ', '_')}",
            'node_type': 'DEPARTMENT',
            'label': str(d),
            'department': str(d),
            'status': 'Active',
            'source_dataset': 'canonical_users',
            'source_record_id': f"DEPT-{d}"
        })

    # HOST Nodes
    for idx, r in hosts_df.iterrows():
        nodes.append({
            'node_id': str(r['hostname']),
            'node_type': 'HOST',
            'label': str(r['hostname']),
            'department': 'Unknown',
            'status': 'Managed' if r.get('is_managed', True) else 'Unmanaged',
            'source_dataset': 'canonical_hosts',
            'source_record_id': str(r['hostname'])
        })

    # IP Nodes (Unique valid IP addresses)
    src_ips = set(events_df['source_ip'].dropna().unique())
    dst_ips = set(events_df['destination_ip'].dropna().unique())
    all_ips = (src_ips | dst_ips) - {'Unknown', 'nan'}

    for ip in all_ips:
        nodes.append({
            'node_id': f"IP-{ip}",
            'node_type': 'IP',
            'label': str(ip),
            'department': 'Unknown',
            'status': 'Active',
            'source_dataset': 'canonical_events',
            'source_record_id': f"IP-{ip}"
        })

    # SESSION Nodes
    for idx, r in sessions_df.iterrows():
        nodes.append({
            'node_id': str(r['session_id']),
            'node_type': 'SESSION',
            'label': str(r['session_id']),
            'department': str(r.get('department', 'Unknown')),
            'status': 'Active',
            'source_dataset': 'canonical_sessions',
            'source_record_id': str(r['session_id'])
        })

    # RISK ASSESSMENT Nodes
    for idx, r in risk_df.iterrows():
        nodes.append({
            'node_id': f"RISK-{r['entity_id']}",
            'node_type': 'RISK_ASSESSMENT',
            'label': f"Risk: {r['traceone_risk_score']} ({r['risk_level']})",
            'department': str(r.get('department', 'Unknown')),
            'status': str(r['risk_level']),
            'source_dataset': 'traceone_risk_scores',
            'source_record_id': str(r['entity_id'])
        })

    # TEMPORAL SEQUENCE Nodes
    for idx, r in seq_df.iterrows():
        nodes.append({
            'node_id': str(r['sequence_id']),
            'node_type': 'TEMPORAL_SEQUENCE',
            'label': f"{r['sequence_type']} (Strength: {r['sequence_strength']})",
            'department': 'Unknown',
            'status': 'Detected',
            'source_dataset': 'temporal_sequences',
            'source_record_id': str(r['sequence_id'])
        })

    # EVENT Nodes (Sample high-signal / representative canonical events)
    flagged_event_ids = set(risk_ev_df['event_id']).union(set(seq_ev_df['event_id']))
    event_sub_df = events_df[events_df['event_id'].isin(flagged_event_ids)]

    for idx, r in event_sub_df.iterrows():
        nodes.append({
            'node_id': str(r['event_id']),
            'node_type': 'EVENT',
            'label': f"{r['event_category']}: {r['action']}",
            'department': str(r.get('department', 'Unknown')),
            'status': str(r.get('severity', 'Normal')),
            'source_dataset': str(r['source_dataset']),
            'source_record_id': str(r['source_record_id'])
        })

    nodes_df = pd.DataFrame(nodes).drop_duplicates(subset=['node_id'])

    # ---------------------------------------------------------
    # 2. BUILD EDGES
    # ---------------------------------------------------------
    print("Building Graph Edges...")

    # Edge 1: User -> BELONGS_TO -> Department
    for idx, r in users_df.iterrows():
        dept_node_id = f"DEPT-{str(r['department']).upper().replace(' ', '_')}"
        edges.append({
            'edge_id': f"EDG-{edge_counter}",
            'source_id': str(r['user_id']),
            'target_id': dept_node_id,
            'relationship_type': 'BELONGS_TO',
            'relationship_confidence': 'EXACT',
            'source_dataset': 'canonical_users',
            'source_record_id': str(r['user_id']),
            'evidence_type': 'ORGANIZATIONAL_ASSIGNMENT'
        })
        edge_counter += 1

    # Edge 2: User -> ASSOCIATED_WITH_HOST -> Host
    for idx, r in rel_df.iterrows():
        edges.append({
            'edge_id': f"EDG-{edge_counter}",
            'source_id': str(r['source_node']),
            'target_id': str(r['target_node']),
            'relationship_type': 'ASSOCIATED_WITH_HOST',
            'relationship_confidence': str(r.get('confidence', 'PROBABLE')),
            'source_dataset': str(r.get('provenance', 'canonical_relationships')),
            'source_record_id': f"REL-{idx}",
            'evidence_type': 'TELEMETRY_ASSOCIATION'
        })
        edge_counter += 1

    # Edge 3 & 4: User -> AUTHENTICATED_VIA -> Session -> CONNECTED_FROM_IP -> IP (from canonical IAM events)
    iam_session_events = events_df[events_df['session_id'].notna() & (events_df['session_id'] != 'Unknown')].head(10000)

    for idx, r in iam_session_events.iterrows():
        sid = str(r['session_id'])
        uid = str(r['user_id'])
        ip = str(r['source_ip'])

        if uid != 'Unknown':
            edges.append({
                'edge_id': f"EDG-{edge_counter}",
                'source_id': uid,
                'target_id': sid,
                'relationship_type': 'AUTHENTICATED_VIA',
                'relationship_confidence': 'EXACT',
                'source_dataset': 'canonical_events',
                'source_record_id': str(r['source_record_id']),
                'evidence_type': 'IAM_SESSION_ESTABLISHMENT'
            })
            edge_counter += 1

        if ip not in ('Unknown', 'nan'):
            edges.append({
                'edge_id': f"EDG-{edge_counter}",
                'source_id': sid,
                'target_id': f"IP-{ip}",
                'relationship_type': 'CONNECTED_FROM_IP',
                'relationship_confidence': 'EXACT',
                'source_dataset': 'canonical_events',
                'source_record_id': str(r['source_record_id']),
                'evidence_type': 'NETWORK_ORIGIN_IP'
            })
            edge_counter += 1

    # Edge 5: Host -> COMMUNICATED_WITH_IP -> IP (from Firewall events)
    fw_events = events_df[events_df['event_category'] == 'NETWORK_FLOW'].head(10000)
    for idx, r in fw_events.iterrows():
        if pd.notna(r['hostname']) and str(r['hostname']) != 'Unknown':
            if pd.notna(r['destination_ip']) and str(r['destination_ip']) not in ('Unknown', 'nan'):
                edges.append({
                    'edge_id': f"EDG-{edge_counter}",
                    'source_id': str(r['hostname']),
                    'target_id': f"IP-{r['destination_ip']}",
                    'relationship_type': 'COMMUNICATED_WITH_IP',
                    'relationship_confidence': 'EXACT',
                    'source_dataset': 'canonical_events',
                    'source_record_id': str(r['source_record_id']),
                    'evidence_type': 'FIREWALL_NETWORK_FLOW'
                })
                edge_counter += 1

    # Edge 6: User / Host -> HAS_RISK_ASSESSMENT -> Risk Assessment
    for idx, r in risk_df.iterrows():
        edges.append({
            'edge_id': f"EDG-{edge_counter}",
            'source_id': str(r['entity_id']),
            'target_id': f"RISK-{r['entity_id']}",
            'relationship_type': 'HAS_RISK_ASSESSMENT',
            'relationship_confidence': 'EXACT',
            'source_dataset': 'traceone_risk_scores',
            'source_record_id': str(r['entity_id']),
            'evidence_type': 'EXPLAINABLE_RISK_EVALUATION'
        })
        edge_counter += 1

    # Edge 7: Risk Assessment -> SUPPORTED_BY_EVIDENCE -> Event
    for idx, r in risk_ev_df.iterrows():
        edges.append({
            'edge_id': f"EDG-{edge_counter}",
            'source_id': f"RISK-{r['entity_id']}",
            'target_id': str(r['event_id']),
            'relationship_type': 'SUPPORTED_BY_EVIDENCE',
            'relationship_confidence': 'EXACT',
            'source_dataset': str(r['source_dataset']),
            'source_record_id': str(r['source_record_id']),
            'evidence_type': 'FLAGGED_ANOMALY_EVIDENCE'
        })
        edge_counter += 1

    # Edge 8: Entity -> INVOLVED_IN_SEQUENCE -> Temporal Sequence
    for idx, r in seq_df.iterrows():
        edges.append({
            'edge_id': f"EDG-{edge_counter}",
            'source_id': str(r['entity_id']),
            'target_id': str(r['sequence_id']),
            'relationship_type': 'INVOLVED_IN_SEQUENCE',
            'relationship_confidence': 'EXACT',
            'source_dataset': 'temporal_sequences',
            'source_record_id': str(r['sequence_id']),
            'evidence_type': 'CHRONOLOGICAL_SEQUENCE_MEMBER'
        })
        edge_counter += 1

    # Edge 9: Temporal Sequence -> SEQUENCE_INCLUDES_EVENT -> Event
    for idx, r in seq_ev_df.iterrows():
        edges.append({
            'edge_id': f"EDG-{edge_counter}",
            'source_id': str(r['sequence_id']),
            'target_id': str(r['event_id']),
            'relationship_type': 'SEQUENCE_INCLUDES_EVENT',
            'relationship_confidence': 'EXACT',
            'source_dataset': str(r['source_dataset']),
            'source_record_id': str(r['source_record_id']),
            'evidence_type': 'SEQUENCE_EVENT_STEP'
        })
        edge_counter += 1

    edges_df = pd.DataFrame(edges).drop_duplicates(subset=['source_id', 'target_id', 'relationship_type'])

    # Filter edges to only include nodes that exist in nodes_df
    valid_node_ids = set(nodes_df['node_id'])
    edges_df = edges_df[edges_df['source_id'].isin(valid_node_ids) & edges_df['target_id'].isin(valid_node_ids)].copy()

    # Save Output Graph Tables
    nodes_df.to_csv(PROCESSED_DIR / "graph_nodes.csv", index=False)
    edges_df.to_csv(PROCESSED_DIR / "graph_edges.csv", index=False)

    metadata = {
        'total_nodes': len(nodes_df),
        'total_edges': len(edges_df),
        'node_distribution': nodes_df['node_type'].value_counts().to_dict(),
        'edge_distribution': edges_df['relationship_type'].value_counts().to_dict(),
        'provenance_preserved': True
    }

    with open(PROCESSED_DIR / "graph_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nGraph Construction Summary:")
    print(f" - Total Nodes: {len(nodes_df):,}")
    print(f" - Total Edges: {len(edges_df):,}")
    print(f" - Node Types: {metadata['node_distribution']}")
    print(f" - Relationship Types: {metadata['edge_distribution']}")
    print("=" * 70)


if __name__ == "__main__":
    build_investigation_graph()
