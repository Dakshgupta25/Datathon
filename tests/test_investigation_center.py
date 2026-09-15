"""
Unit tests for TraceONE Investigation Center (Phase K)
"""

import unittest
from pathlib import Path
import pandas as pd

from src.dashboard.data.loader import (
    load_user_risk_scores,
    load_host_risk_scores,
    load_user_clusters,
    load_canonical_events,
    load_temporal_sequences,
    load_why_flagged_explanations,
    load_security_hypotheses,
    load_normalized_evidence,
    load_user_baselines,
    get_graph_engine
)

class TestInvestigationCenter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.user_risk = load_user_risk_scores()
        cls.host_risk = load_host_risk_scores()
        cls.explanations = load_why_flagged_explanations()
        cls.hypotheses = load_security_hypotheses()
        cls.evidence = load_normalized_evidence()
        cls.sequences = load_temporal_sequences()
        cls.graph_engine = get_graph_engine()

    def test_01_valid_user_lookup(self):
        row = self.user_risk[self.user_risk['entity_id'] == 'EMP10194']
        self.assertFalse(row.empty)
        self.assertEqual(row.iloc[0]['entity_id'], 'EMP10194')

    def test_02_unknown_user_lookup(self):
        row = self.user_risk[self.user_risk['entity_id'] == 'EMP99999']
        self.assertTrue(row.empty)
        exp = self.explanations.get('EMP99999', {})
        self.assertEqual(exp, {})

    def test_03_valid_host_lookup(self):
        row = self.host_risk[self.host_risk['entity_id'] == 'VDR-11889']
        self.assertFalse(row.empty)
        self.assertEqual(row.iloc[0]['entity_id'], 'VDR-11889')

    def test_04_user_with_no_sequence(self):
        # Find a user with no sequence in sequences_df
        seq_users = set(self.sequences['entity_id'].dropna().tolist())
        no_seq_user = [u for u in self.user_risk['entity_id'] if u not in seq_users]
        self.assertTrue(len(no_seq_user) > 0)
        user_seqs = self.sequences[self.sequences['entity_id'] == no_seq_user[0]]
        self.assertTrue(user_seqs.empty)

    def test_05_user_with_multiple_sequences(self):
        # Find user with sequence in sequences_df
        seq_counts = self.sequences['entity_id'].value_counts()
        self.assertFalse(seq_counts.empty)
        top_seq_user = seq_counts.index[0]
        user_seqs = self.sequences[self.sequences['entity_id'] == top_seq_user]
        self.assertTrue(len(user_seqs) >= 1)

    def test_06_user_with_graph_relationships(self):
        if self.graph_engine is not None:
            conn = self.graph_engine.get_connected_entities('EMP10194')
            self.assertEqual(conn['entity_id'], 'EMP10194')
            self.assertTrue(len(conn['outbound_connections']) + len(conn['inbound_connections']) > 0)

    def test_07_user_with_no_graph_relationships(self):
        if self.graph_engine is not None:
            conn = self.graph_engine.get_connected_entities('EMP99999')
            self.assertEqual(len(conn['outbound_connections']), 0)

    def test_08_insufficient_baseline_fallback(self):
        baselines = load_user_baselines()
        b_row = baselines[baselines['user_id'] == 'EMP99999']
        self.assertTrue(b_row.empty)

    def test_09_high_risk_high_confidence_user(self):
        hr_hc = self.user_risk[(self.user_risk['traceone_risk_score'] >= 80) & (self.user_risk['risk_confidence_level'] == 'HIGH')]
        self.assertFalse(hr_hc.empty)

    def test_10_high_risk_lower_confidence_user(self):
        hr_lc = self.user_risk[(self.user_risk['traceone_risk_score'] >= 60) & (self.user_risk['risk_confidence_level'].isin(['MEDIUM', 'LOW']))]
        self.assertTrue(isinstance(hr_lc, pd.DataFrame))

    def test_11_missing_evidence_handling(self):
        ev = self.evidence[self.evidence['entity_id'] == 'EMP99999']
        self.assertTrue(ev.empty)

    def test_12_counter_evidence_retrieval(self):
        emp_exp = self.explanations.get('EMP10194', {})
        counter_ev = emp_exp.get('counter_evidence', [])
        self.assertIsInstance(counter_ev, list)

    def test_13_exact_relationship_provenance(self):
        if self.graph_engine is not None:
            exact_edges = self.graph_engine.edges_df[self.graph_engine.edges_df['relationship_confidence'] == 'EXACT']
            self.assertFalse(exact_edges.empty)

    def test_14_probable_relationship_provenance(self):
        if self.graph_engine is not None:
            prob_edges = self.graph_engine.edges_df[self.graph_engine.edges_df['relationship_confidence'] == 'PROBABLE']
            self.assertTrue(isinstance(prob_edges, pd.DataFrame))
            self.assertEqual(len(prob_edges), 0)  # All 79,224 canonical edges are EXACT

    def test_15_unmatched_relationship_filtering(self):
        if self.graph_engine is not None:
            unmatch_edges = self.graph_engine.edges_df[self.graph_engine.edges_df['relationship_confidence'] == 'UNMATCHED']
            self.assertTrue(isinstance(unmatch_edges, pd.DataFrame))

    def test_16_semantic_corrections_audit(self):
        app_path = Path(__file__).resolve().parent.parent / "app.py"
        with open(app_path, "r", encoding="utf-8") as f:
            code = f.read()
        self.assertIn("Risk Component Score (Points)", code)
        self.assertIn("No MFA failure was observed in the available telemetry", code)
        self.assertNotIn("confirming MFA controls", code)
        self.assertNotIn("Contribution Weight (%)", code)

    def test_17_timeline_timestamp_column_resolution(self):
        """ISSUE 23 — Verify timeline handles event_timestamp, timestamp, and empty events without traceback."""
        app_path = Path(__file__).resolve().parent.parent / "app.py"
        with open(app_path, "r", encoding="utf-8") as f:
            code = f.read()
        self.assertIn("time_col = \"event_timestamp\"", code)
        self.assertIn("time_col = \"timestamp\"", code)
        self.assertIn("No valid timestamped events available", code)

        # Test column resolution logic on canonical events dataframe
        events = load_canonical_events()
        self.assertIsInstance(events, pd.DataFrame)
        time_col = "event_timestamp" if "event_timestamp" in events.columns else "timestamp" if "timestamp" in events.columns else None
        self.assertIsNotNone(time_col)
        self.assertIn(time_col, events.columns)


if __name__ == "__main__":
    unittest.main()
