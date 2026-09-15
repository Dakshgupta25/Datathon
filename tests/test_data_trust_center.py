"""
Unit Tests for TraceONE Data Trust & Lineage Center (Phase L)
Verifies data loaders, provenance lookup engine, data dictionary parser, and trust semantics.
"""

import unittest
from pathlib import Path
import pandas as pd

from src.dashboard.data.loader import (
    load_data_trust_status,
    load_before_after_summary,
    load_cleaning_log,
    load_data_dictionary,
    load_validation_scoreboard,
    load_provenance_record,
    load_user_risk_scores,
    load_host_risk_scores,
    load_canonical_events,
    load_temporal_sequences
)


class TestDataTrustCenter(unittest.TestCase):

    def test_01_data_trust_status(self):
        status = load_data_trust_status()
        self.assertIsInstance(status, dict)
        self.assertEqual(status.get("pipeline_health"), "PASSED")
        self.assertEqual(status.get("iam_firewall_overlap_pct"), "2.26%")
        self.assertEqual(status.get("telemetry_window"), "2026-08-01 → 2026-08-15")

    def test_02_before_after_summary(self):
        df = load_before_after_summary()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertIn("dataset", df.columns)
        self.assertIn("raw_rows", df.columns)
        self.assertIn("cleaned_rows", df.columns)
        self.assertEqual(len(df), 4)

    def test_03_cleaning_log(self):
        df = load_cleaning_log()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertIn("dataset", df.columns)
        self.assertIn("action", df.columns)
        self.assertGreaterEqual(len(df), 30)

    def test_04_data_dictionary_parser(self):
        df = load_data_dictionary()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertFalse(df.empty)
        self.assertIn("field", df.columns)
        self.assertIn("meaning", df.columns)
        fields = df["field"].tolist()
        self.assertIn("user_id", fields)

    def test_05_validation_scoreboard(self):
        scoreboard = load_validation_scoreboard()
        self.assertIsInstance(scoreboard, list)
        self.assertGreaterEqual(len(scoreboard), 12)
        for item in scoreboard:
            self.assertEqual(item["status"], "PASSED")
            self.assertIn("phase", item)
            self.assertIn("name", item)

    def test_06_provenance_user_lookup(self):
        rec = load_provenance_record("User / Host", "EMP10194")
        self.assertTrue(rec.get("found"))
        self.assertEqual(rec.get("entity_type"), "User Identity")
        self.assertEqual(rec.get("risk_score"), 100.0)
        self.assertIn("track2_identity_asset_master.csv", rec.get("source_datasets", []))

    def test_07_provenance_host_lookup(self):
        rec = load_provenance_record("User / Host", "VDR-11889")
        self.assertTrue(rec.get("found"))
        self.assertEqual(rec.get("entity_type"), "Host Device")
        self.assertIn("track2_endpoint_alerts.xlsx", rec.get("source_datasets", []))

    def test_08_provenance_sequence_lookup(self):
        rec = load_provenance_record("Temporal Sequence", "SEQ-USR-1000")
        self.assertTrue(rec.get("found"))
        self.assertEqual(rec.get("entity_type"), "Temporal Sequence")

    def test_09_provenance_event_lookup(self):
        rec = load_provenance_record("Event", "IAM00008974")
        self.assertTrue(rec.get("found"))
        self.assertEqual(rec.get("entity_type"), "Canonical Event")

    def test_10_provenance_fallback(self):
        rec = load_provenance_record("User / Host", "UNKNOWN_EMP_99999")
        self.assertFalse(rec.get("found"))
        self.assertIn("not found", rec.get("message", "").lower())

    def test_11_dynamic_volume_counts(self):
        user_risk = load_user_risk_scores()
        host_risk = load_host_risk_scores()
        events = load_canonical_events()
        seqs = load_temporal_sequences()
        self.assertEqual(len(user_risk), 3000)
        self.assertEqual(len(host_risk), 8413)
        self.assertEqual(len(events), 58000)
        self.assertEqual(len(seqs), 2412)

    def test_12_known_limitations_integrity(self):
        path = Path("src/ui/data_trust_center.py")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("2.26% IAM ↔ Firewall Session Overlap", content)
        self.assertIn("Unmanaged Hostnames", content)
        self.assertIn("Unknown Timestamps", content)

    def test_13_app_wiring(self):
        path = Path("app.py")
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("render_data_trust_center", content)
        self.assertIn("🛡️ Data Trust & Lineage Center", content)


if __name__ == "__main__":
    unittest.main()
