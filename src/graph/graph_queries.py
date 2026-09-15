"""
TraceONE Investigation Graph Query Engine & Scenarios
Phase H: Graph Queries, Traversal, and Investigation Context

Implements high-performance in-memory graph traversal queries, bounded neighborhood expansion,
shortest path search, chronological timeline construction, and structured investigation scenario generation.
"""

from pathlib import Path
import json
import collections
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


class InvestigationGraphEngine:

    def __init__(self, processed_dir=PROCESSED_DIR):
        self.processed_dir = Path(processed_dir)
        self.nodes_df = pd.read_csv(self.processed_dir / "graph_nodes.csv")
        self.edges_df = pd.read_csv(self.processed_dir / "graph_edges.csv")
        self.risk_df = pd.read_csv(self.processed_dir / "traceone_risk_scores.csv")
        self.hypo_df = pd.read_csv(self.processed_dir / "security_hypotheses.csv")
        
        # Build node attribute lookup table
        self.node_dict = self.nodes_df.set_index('node_id').to_dict('index')

        # Build adjacency maps (outbound and inbound)
        self.adj_out = collections.defaultdict(list)
        self.adj_in = collections.defaultdict(list)

        for idx, r in self.edges_df.iterrows():
            src = str(r['source_id'])
            tgt = str(r['target_id'])
            edge_info = {
                'edge_id': str(r['edge_id']),
                'target': tgt,
                'source': src,
                'relationship_type': str(r['relationship_type']),
                'confidence': str(r['relationship_confidence']),
                'source_dataset': str(r['source_dataset']),
                'source_record_id': str(r['source_record_id']),
                'evidence_type': str(r['evidence_type'])
            }
            self.adj_out[src].append(edge_info)
            self.adj_in[tgt].append(edge_info)

    def get_node(self, node_id):
        """Retrieve node attributes or default missing representation."""
        return self.node_dict.get(str(node_id), {
            'node_id': str(node_id),
            'node_type': 'UNKNOWN',
            'label': 'NO_VERIFIED_RELATIONSHIP',
            'department': 'Unknown',
            'status': 'Unknown'
        })

    def get_connected_entities(self, entity_id):
        """Get all directly connected nodes and edge relationships."""
        entity_id = str(entity_id)
        outbound = self.adj_out.get(entity_id, [])
        inbound = self.adj_in.get(entity_id, [])
        return {
            'entity_id': entity_id,
            'outbound_connections': outbound,
            'inbound_connections': inbound
        }

    def get_user_hosts(self, user_id):
        """Get all hosts associated with a user."""
        user_id = str(user_id)
        out_edges = self.adj_out.get(user_id, [])
        hosts = [e['target'] for e in out_edges if e['relationship_type'] == 'ASSOCIATED_WITH_HOST']
        return hosts

    def get_host_ips(self, hostname):
        """Get all IPs communicated with by a host."""
        hostname = str(hostname)
        out_edges = self.adj_out.get(hostname, [])
        ips = [e['target'].replace('IP-', '') for e in out_edges if e['relationship_type'] == 'COMMUNICATED_WITH_IP']
        return ips

    def get_shared_infrastructure_entities(self, ip_address):
        """Get all entities sharing a specific IP address."""
        ip_node_id = f"IP-{ip_address}" if not str(ip_address).startswith('IP-') else str(ip_address)
        in_edges = self.adj_in.get(ip_node_id, [])
        sources = [e['source'] for e in in_edges]
        return {
            'ip_address': ip_node_id.replace('IP-', ''),
            'connected_entities_count': len(sources),
            'connected_entities': sources
        }

    def get_entity_sequences(self, entity_id):
        """Get all temporal sequences involving an entity."""
        entity_id = str(entity_id)
        out_edges = self.adj_out.get(entity_id, [])
        seq_ids = [e['target'] for e in out_edges if e['relationship_type'] == 'INVOLVED_IN_SEQUENCE']
        return seq_ids

    def get_risk_evidence(self, entity_id):
        """Get risk assessment and supporting event evidence for an entity."""
        entity_id = str(entity_id)
        risk_node_id = f"RISK-{entity_id}"
        out_edges = self.adj_out.get(risk_node_id, [])
        evidence_events = [e['target'] for e in out_edges if e['relationship_type'] == 'SUPPORTED_BY_EVIDENCE']

        risk_row = self.risk_df[self.risk_df['entity_id'] == entity_id]
        risk_info = risk_row.to_dict('records')[0] if len(risk_row) > 0 else {}

        return {
            'entity_id': entity_id,
            'risk_info': risk_info,
            'supporting_evidence_events': evidence_events
        }

    def get_bounded_neighborhood(self, entity_id, max_hops=2):
        """Perform breadth-first search (BFS) traversal up to max_hops."""
        entity_id = str(entity_id)
        visited_nodes = {entity_id}
        visited_edges = []
        queue = collections.deque([(entity_id, 0)])

        while queue:
            curr, depth = queue.popleft()
            if depth >= max_hops:
                continue

            for edge in self.adj_out.get(curr, []):
                tgt = edge['target']
                visited_edges.append(edge)
                if tgt not in visited_nodes:
                    visited_nodes.add(tgt)
                    queue.append((tgt, depth + 1))

            for edge in self.adj_in.get(curr, []):
                src = edge['source']
                visited_edges.append(edge)
                if src not in visited_nodes:
                    visited_nodes.add(src)
                    queue.append((src, depth + 1))

        return {
            'root_entity': entity_id,
            'max_hops': max_hops,
            'node_count': len(visited_nodes),
            'edge_count': len(visited_edges),
            'nodes': list(visited_nodes),
            'edges': visited_edges
        }

    def get_shortest_path(self, source_id, target_id):
        """Find shortest evidence-backed path using BFS."""
        source_id, target_id = str(source_id), str(target_id)
        if source_id == target_id:
            return [source_id]

        queue = collections.deque([(source_id, [source_id])])
        visited = {source_id}

        while queue:
            curr, path = queue.popleft()
            neighbors = [e['target'] for e in self.adj_out.get(curr, [])] + [e['source'] for e in self.adj_in.get(curr, [])]
            for nxt in neighbors:
                if nxt == target_id:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt]))

        return []  # Path not found

    def get_investigation_context(self, entity_id):
        """Construct complete machine-readable investigation object for an entity."""
        entity_id = str(entity_id)
        node_attr = self.get_node(entity_id)
        risk_ev = self.get_risk_evidence(entity_id)
        sequences = self.get_entity_sequences(entity_id)
        connected = self.get_connected_entities(entity_id)

        hypo_row = self.hypo_df[self.hypo_df['entity_id'] == entity_id]
        hypo = hypo_row['hypothesis'].values[0] if len(hypo_row) > 0 else "NO_ACTIONABLE_HYPOTHESIS"

        return {
            'entity_id': entity_id,
            'entity_type': node_attr.get('node_type', 'UNKNOWN'),
            'label': node_attr.get('label', entity_id),
            'department': node_attr.get('department', 'Unknown'),
            'status': node_attr.get('status', 'Unknown'),
            'risk_summary': risk_ev.get('risk_info', {}),
            'hypothesis': hypo,
            'connected_entities_summary': {
                'outbound_count': len(connected['outbound_connections']),
                'inbound_count': len(connected['inbound_connections'])
            },
            'temporal_sequence_ids': sequences,
            'supporting_evidence_event_ids': risk_ev.get('supporting_evidence_events', []),
            'investigation_readiness': 'READY'
        }


def generate_investigation_scenarios(engine):
    """Generate 4 deterministic investigation scenarios from real data."""
    print("Generating Real-Data Investigation Scenarios...")

    risk_df = engine.risk_df.sort_values('traceone_risk_score', ascending=False)
    
    top_user = risk_df[risk_df['entity_type'] == 'USER'].iloc[0]['entity_id']
    top_host = risk_df[risk_df['entity_type'] == 'HOST'].iloc[0]['entity_id']

    scenarios = [
        {
            'scenario_id': 'SCENARIO-01',
            'title': 'Highest Risk User Investigation',
            'description': f"Deep-dive investigation of top-risk user {top_user}",
            'target_entity': top_user,
            'investigation_context': engine.get_investigation_context(top_user)
        },
        {
            'scenario_id': 'SCENARIO-02',
            'title': 'High Risk Host Endpoint & Network Investigation',
            'description': f"Investigation of critical risk host {top_host}",
            'target_entity': top_host,
            'investigation_context': engine.get_investigation_context(top_host)
        }
    ]

    # Shared IP Scenario
    host_ips = engine.get_host_ips(top_host)
    if not host_ips:
        # Find any active IP node in graph
        ip_nodes = engine.nodes_df[engine.nodes_df['node_type'] == 'IP']
        if len(ip_nodes) > 0:
            host_ips = [ip_nodes.iloc[0]['node_id'].replace('IP-', '')]

    if host_ips:
        shared_ip = host_ips[0]
        shared_ctx = engine.get_shared_infrastructure_entities(shared_ip)
        scenarios.append({
            'scenario_id': 'SCENARIO-03',
            'title': 'Shared Infrastructure IP Investigation',
            'description': f"Infrastructure correlation for active IP {shared_ip}",
            'target_entity': f"IP-{shared_ip}",
            'investigation_context': shared_ctx
        })

    # Temporal Sequence Scenario
    seq_ids = engine.get_entity_sequences(top_user)
    target_seq_user = top_user
    if not seq_ids:
        # Find first user/host with sequences
        for uid in risk_df['entity_id']:
            seq_ids = engine.get_entity_sequences(uid)
            if seq_ids:
                target_seq_user = uid
                break

    if seq_ids:
        scenarios.append({
            'scenario_id': 'SCENARIO-04',
            'title': 'Temporal Sequence Event Chain Investigation',
            'description': f"Sequence event chain for entity {target_seq_user} (Sequence {seq_ids[0]})",
            'target_entity': seq_ids[0],
            'investigation_context': engine.get_connected_entities(seq_ids[0])
        })

    return scenarios


def main():
    print("=" * 70)
    print("TRACEONE INVESTIGATION GRAPH ENGINE & QUERIES (PHASE H)")
    print("=" * 70)

    engine = InvestigationGraphEngine()
    print(f"Graph Engine Initialized with {len(engine.node_dict):,} nodes and {len(engine.edges_df):,} edges.")

    scenarios = generate_investigation_scenarios(engine)

    with open(PROCESSED_DIR / "investigation_scenarios.json", "w") as f:
        json.dump(scenarios, f, indent=2)

    print("\nSaved output files to data/processed/:")
    print(" - investigation_scenarios.json")
    print("=" * 70)
    print("PHASE H GRAPH QUERIES COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
