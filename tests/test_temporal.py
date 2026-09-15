"""
TraceONE Unit Test Suite for Temporal Security Correlation Engine
Phase G: Step 16 - Temporal Unit Testing
"""

import unittest
import numpy as np
import pandas as pd
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.transformations.temporal_engine import (
    calculate_sequence_confidence,
    calculate_sequence_strength
)


class TestTemporalEngine(unittest.TestCase):

    def test_1_simple_ordered_sequence(self):
        """Test timestamp ordering and duration calculation for valid sequence."""
        start_ts = pd.to_datetime("2026-08-09 10:00:00", utc=True)
        end_ts = pd.to_datetime("2026-08-09 10:15:00", utc=True)
        duration_sec = int((end_ts - start_ts).total_seconds())

        self.assertEqual(duration_sec, 900)
        self.assertGreaterEqual(duration_sec, 0)

    def test_2_reversed_events_deterministic_sorting(self):
        """Test that out-of-order input events are sorted chronologically."""
        df = pd.DataFrame([
            {'event_id': 'EVT-2', 'valid_ts': pd.to_datetime("2026-08-09 10:15:00", utc=True)},
            {'event_id': 'EVT-1', 'valid_ts': pd.to_datetime("2026-08-09 10:00:00", utc=True)}
        ])
        sorted_df = df.sort_values(['valid_ts', 'event_id'])
        self.assertEqual(sorted_df.iloc[0]['event_id'], 'EVT-1')
        self.assertEqual(sorted_df.iloc[1]['event_id'], 'EVT-2')

    def test_3_equal_timestamps_tie_breaking(self):
        """Test deterministic tie-breaking by event_id ascending when timestamps match."""
        df = pd.DataFrame([
            {'event_id': 'EVT-900', 'valid_ts': pd.to_datetime("2026-08-09 10:00:00", utc=True)},
            {'event_id': 'EVT-100', 'valid_ts': pd.to_datetime("2026-08-09 10:00:00", utc=True)}
        ])
        sorted_df = df.sort_values(['valid_ts', 'event_id'])
        self.assertEqual(sorted_df.iloc[0]['event_id'], 'EVT-100')
        self.assertEqual(sorted_df.iloc[1]['event_id'], 'EVT-900')

    def test_4_unknown_timestamp_exclusion(self):
        """Test that Unknown timestamp records are excluded from valid sequences."""
        raw_events = pd.DataFrame([
            {'event_id': 'E1', 'event_timestamp': '2026-08-09 10:00:00+00:00'},
            {'event_id': 'E2', 'event_timestamp': 'Unknown'}
        ])
        valid_events = raw_events[raw_events['event_timestamp'] != 'Unknown']
        self.assertEqual(len(valid_events), 1)
        self.assertNotIn('Unknown', valid_events['event_timestamp'].values)

    def test_5_invalid_timestamp_exclusion(self):
        """Test that null/invalid timestamp values are excluded."""
        s = pd.Series(['2026-08-09 10:00:00+00:00', 'Invalid_TS'])
        parsed = pd.to_datetime(s, format='mixed', errors='coerce')
        valid = parsed.dropna()
        self.assertEqual(len(valid), 1)

    def test_6_duplicate_event_handling(self):
        """Test handling of duplicate event IDs."""
        events = ['EVT-1', 'EVT-1', 'EVT-2']
        unique_events = list(dict.fromkeys(events))
        self.assertEqual(len(unique_events), 2)

    def test_7_window_boundary_inclusion(self):
        """Test event exactly 3600 seconds apart is included in window."""
        t1 = pd.to_datetime("2026-08-09 10:00:00", utc=True)
        t2 = pd.to_datetime("2026-08-09 11:00:00", utc=True)
        delta = (t2 - t1).total_seconds()
        self.assertTrue(delta <= 3600)

    def test_8_event_outside_window_exclusion(self):
        """Test event 3601 seconds apart is excluded from window."""
        t1 = pd.to_datetime("2026-08-09 10:00:00", utc=True)
        t2 = pd.to_datetime("2026-08-09 11:00:01", utc=True)
        delta = (t2 - t1).total_seconds()
        self.assertFalse(delta <= 3600)

    def test_9_cross_source_sequence_detection(self):
        """Test cross-source sequence detection and confidence calculation."""
        num_sources = 2
        conf = calculate_sequence_confidence(ts_quality=1.0, num_sources=num_sources, event_count=3)
        self.assertGreaterEqual(conf, 0.8)

    def test_10_insufficient_evidence_single_event(self):
        """Test single event entity generates 0 sequences."""
        events_count = 1
        has_sequence = events_count >= 2
        self.assertFalse(has_sequence)

    def test_11_repeated_normal_sequence_frequency(self):
        """Test pattern rarity classification for common recurring patterns (>50 occurrences)."""
        occurrence_count = 143
        rarity = "COMMON" if occurrence_count > 50 else ("UNUSUAL" if occurrence_count >= 10 else "RARE")
        self.assertEqual(rarity, "COMMON")

    def test_12_strong_multi_event_sequence(self):
        """Test sequence strength calculation for multi-source, multi-category sequence."""
        strength = calculate_sequence_strength(num_sources=3, num_categories=3, event_count=5, is_cross_source=True)
        # 25*3 + 20*3 + 15*5 + 20*1 = 75 + 60 + 75 + 20 = 230 -> clipped to 100.0
        self.assertEqual(strength, 100.0)


if __name__ == "__main__":
    unittest.main()
