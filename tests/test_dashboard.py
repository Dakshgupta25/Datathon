"""
Unit tests for TraceONE Dashboard Data Loader (Phase J.1)
"""

import unittest
from pathlib import Path
import pandas as pd

from src.dashboard.data.loader import (
    load_user_risk_scores,
    load_host_risk_scores,
    load_user_clusters,
    load_cluster_profiles,
    load_temporal_sequences,
    load_peer_anomalies,
    load_multidim_outliers,
    load_data_trust_status
)

class TestDashboardDataLoader(unittest.TestCase):
    
    def test_load_user_risk_scores(self):
        df = load_user_risk_scores()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 3000)
        self.assertIn('entity_id', df.columns)
        self.assertIn('traceone_risk_score', df.columns)
        self.assertIn('risk_level', df.columns)
        
    def test_load_host_risk_scores(self):
        df = load_host_risk_scores()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 8413)
        self.assertIn('entity_id', df.columns)
        self.assertIn('traceone_risk_score', df.columns)
        
    def test_load_user_clusters(self):
        df = load_user_clusters()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 3000)
        self.assertIn('cluster_id', df.columns)
        self.assertIn('cluster_label', df.columns)

    def test_load_cluster_profiles(self):
        df = load_cluster_profiles()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 4)
        self.assertIn('cluster_id', df.columns)
        self.assertIn('avg_risk_score', df.columns)
        c3 = df[df['cluster_id'] == 'CLUSTER_3'].iloc[0]
        self.assertEqual(c3['avg_risk_score'], 100.0)
        
    def test_load_temporal_sequences(self):
        df = load_temporal_sequences()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 2412)
        self.assertIn('sequence_id', df.columns)
        
    def test_load_peer_anomalies(self):
        df = load_peer_anomalies()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 3000)
        self.assertIn('peer_outlier_flag', df.columns)
        
    def test_load_multidim_outliers(self):
        df = load_multidim_outliers()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertEqual(len(df), 11413)
        
    def test_data_trust_status(self):
        status = load_data_trust_status()
        self.assertIsInstance(status, dict)
        self.assertEqual(status.get("pipeline_health"), "PASSED")
        self.assertEqual(status.get("iam_firewall_overlap_pct"), "2.26%")
        self.assertEqual(status.get("telemetry_window"), "2026-08-01 → 2026-08-15")

if __name__ == "__main__":
    unittest.main()
