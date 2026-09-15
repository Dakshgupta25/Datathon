"""
Unit tests for TraceONE Phase I — Advanced Security Insights Engine
"""

from pathlib import Path
import json
import unittest
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


class TestAdvancedInsights(unittest.TestCase):

    def setUp(self):
        self.clusters_df = pd.read_csv(PROCESSED_DIR / "user_behavior_clusters.csv")
        self.profiles_df = pd.read_csv(PROCESSED_DIR / "cluster_profiles.csv")
        self.drift_df = pd.read_csv(PROCESSED_DIR / "behavioral_drift.csv")
        self.multi_df = pd.read_csv(PROCESSED_DIR / "multi_dimension_outliers.csv")
        self.peer_df = pd.read_csv(PROCESSED_DIR / "peer_group_outliers.csv")
        self.burst_df = pd.read_csv(PROCESSED_DIR / "temporal_bursts.csv")
        with open(PROCESSED_DIR / "advanced_insight_summary.json") as f:
            self.summary = json.load(f)

    def test_user_cluster_counts(self):
        self.assertEqual(len(self.clusters_df), 3000)
        self.assertEqual(self.clusters_df["user_id"].nunique(), 3000)

    def test_cluster_profiles_completeness(self):
        self.assertEqual(len(self.profiles_df), 4)
        self.assertEqual(self.profiles_df["population_count"].sum(), 3000)
        self.assertIn("dominant_features", self.profiles_df.columns)

    def test_drift_score_bounds(self):
        self.assertEqual(len(self.drift_df), 3000)
        self.assertTrue((self.drift_df["drift_score"] >= 0.0).all())
        self.assertTrue((self.drift_df["drift_score"] <= 100.0).all())

    def test_multi_dimensional_outlier_structure(self):
        self.assertEqual(len(self.multi_df), 11413)
        self.assertIn("active_dimensions", self.multi_df.columns)
        self.assertTrue((self.multi_df["outlier_dimension_count"] >= 0).all())

    def test_peer_group_taxonomy(self):
        self.assertEqual(len(self.peer_df), 3000)
        valid_cats = {
            "NORMAL_GLOBALLY_NORMAL_PEER",
            "NORMAL_GLOBALLY_ANOMALOUS_PEER",
            "ANOMALOUS_GLOBALLY_NORMAL_PEER",
            "ANOMALOUS_GLOBALLY_ANOMALOUS_PEER",
        }
        self.assertTrue(set(self.peer_df["global_vs_peer_behavior"]).issubset(valid_cats))

    def test_temporal_burst_window(self):
        if len(self.burst_df) > 0:
            self.assertTrue((self.burst_df["event_count"] >= 3).all())
            self.assertIn("burst_category", self.burst_df.columns)

    def test_forecasting_decision_justification(self):
        self.assertEqual(self.summary["forecasting_decision"], "DEFERRED_DUE_TO_15_DAY_TIME_SPAN_LIMITATION")
        self.assertEqual(len(self.summary["top_security_discoveries"]), 5)


if __name__ == "__main__":
    unittest.main()
