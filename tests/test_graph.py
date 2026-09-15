"""
TraceONE Unit Test Suite for Evidence-Backed Investigation Graph
Phase H: Step 15 - Graph Engine Unit Testing
"""

import unittest
import numpy as np
import pandas as pd
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.graph.graph_queries import InvestigationGraphEngine


class TestInvestigationGraph(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = InvestigationGraphEngine()

    def test_1_node_generation_types(self):
        """Test node table contains expected canonical node types."""
        node_types = set(self.engine.nodes_df['node_type'])
        expected_types = {'USER', 'HOST', 'IP', 'SESSION', 'EVENT', 'TEMPORAL_SEQUENCE', 'RISK_ASSESSMENT', 'DEPARTMENT'}
        self.assertTrue(expected_types.issubset(node_types))

    def test_2_edge_generation_types(self):
        """Test edge table contains expected relationship types."""
        rel_types = set(self.engine.edges_df['relationship_type'])
        expected_rels = {'BELONGS_TO', 'ASSOCIATED_WITH_HOST', 'AUTHENTICATED_VIA', 'CONNECTED_FROM_IP',
                         'COMMUNICATED_WITH_IP', 'HAS_RISK_ASSESSMENT', 'SUPPORTED_BY_EVIDENCE',
                         'INVOLVED_IN_SEQUENCE', 'SEQUENCE_INCLUDES_EVENT'}
        self.assertTrue(expected_rels.issubset(rel_types))

    def test_3_provenance_preservation(self):
        """Test every edge retains non-null source dataset and record ID."""
        self.assertTrue(self.engine.edges_df['source_dataset'].notna().all())
        self.assertTrue(self.engine.edges_df['source_record_id'].notna().all())
        self.assertNotIn('Unknown', set(self.engine.edges_df['source_dataset']))

    def test_4_relationship_confidence(self):
        """Test relationship confidence values are valid categories."""
        conf_set = set(self.engine.edges_df['relationship_confidence'])
        self.assertTrue(conf_set.issubset({'EXACT', 'PROBABLE', 'UNMATCHED'}))

    def test_5_duplicate_edge_prevention(self):
        """Test duplicate edge tuples are prevented."""
        dups = self.engine.edges_df.duplicated(subset=['source_id', 'target_id', 'relationship_type']).sum()
        self.assertEqual(dups, 0)

    def test_6_missing_entity_handling(self):
        """Test node lookup for missing entity returns NO_VERIFIED_RELATIONSHIP fallback."""
        missing_info = self.engine.get_node("NON_EXISTENT_ENTITY_12345")
        self.assertEqual(missing_info['label'], "NO_VERIFIED_RELATIONSHIP")

    def test_7_bounded_neighborhood_query(self):
        """Test bounded neighborhood traversal restricts depth to max_hops."""
        sample_user = self.engine.nodes_df[self.engine.nodes_df['node_type'] == 'USER'].iloc[0]['node_id']
        hood = self.engine.get_bounded_neighborhood(sample_user, max_hops=1)
        self.assertGreater(hood['node_count'], 1)
        self.assertEqual(hood['max_hops'], 1)

    def test_8_shortest_path_query(self):
        """Test shortest path query between connected user and department."""
        sample_user = self.engine.nodes_df[self.engine.nodes_df['node_type'] == 'USER'].iloc[0]['node_id']
        connected = self.engine.get_connected_entities(sample_user)
        outbound = connected['outbound_connections']
        dept_target = [e['target'] for e in outbound if e['relationship_type'] == 'BELONGS_TO'][0]

        path = self.engine.get_shortest_path(sample_user, dept_target)
        self.assertEqual(len(path), 2)
        self.assertEqual(path[0], sample_user)
        self.assertEqual(path[1], dept_target)

    def test_9_temporal_sequence_integration(self):
        """Test temporal sequence nodes are linked in graph."""
        seq_nodes = self.engine.nodes_df[self.engine.nodes_df['node_type'] == 'TEMPORAL_SEQUENCE']
        self.assertGreater(len(seq_nodes), 0)

    def test_10_risk_evidence_retrieval(self):
        """Test risk evidence lookup for a user."""
        sample_user = self.engine.nodes_df[self.engine.nodes_df['node_type'] == 'USER'].iloc[0]['node_id']
        risk_ev = self.engine.get_risk_evidence(sample_user)
        self.assertEqual(risk_ev['entity_id'], sample_user)
        self.assertIn('traceone_risk_score', risk_ev['risk_info'])


if __name__ == "__main__":
    unittest.main()
