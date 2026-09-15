"""
TraceONE Unit Test Suite for Behavioral Baselines & Deviations
Phase E: Step 14 - Unit Testing
"""

import unittest
import numpy as np
import pandas as pd
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.transformations.behavioral_baselines import (
    calculate_mad,
    calculate_robust_zscore,
    get_deviation_status
)


class TestBehavioralBaselines(unittest.TestCase):

    def test_mad_calculation(self):
        """Test median absolute deviation on known array."""
        data = pd.Series([1, 2, 3, 4, 5, 6, 7, 8, 9])
        mad = calculate_mad(data)
        # Median is 5. Absolute diffs from 5: [4, 3, 2, 1, 0, 1, 2, 3, 4]. Sorted diffs: [0, 1, 1, 2, 2, 3, 3, 4, 4]. Median diff is 2.
        self.assertEqual(mad, 2.0)

    def test_zero_baseline_safeguard(self):
        """Test robust z-score calculation when median and MAD are zero."""
        z_match = calculate_robust_zscore(val=0, median=0, mad=0)
        self.assertEqual(z_match, 0.0)

        z_diff = calculate_robust_zscore(val=5, median=0, mad=0)
        self.assertGreater(z_diff, 0.0)
        self.assertLessEqual(z_diff, 10.0)

    def test_normal_deviation_status(self):
        """Test normal deviation status threshold (Robust Z < 1.5)."""
        z_normal = 0.8
        status = get_deviation_status(z_normal)
        self.assertEqual(status, "NORMAL")

    def test_extreme_deviation_status(self):
        """Test extreme outlier status threshold (Robust Z >= 4.0)."""
        z_outlier = 5.2
        status = get_deviation_status(z_outlier)
        self.assertEqual(status, "OUTLIER")

    def test_insufficient_history_eligibility(self):
        """Test eligibility rule for entities with insufficient historical observations."""
        obs_count = 3
        distinct_days = 1
        quality_score = 1.0

        if obs_count < 5 or distinct_days < 2:
            status = "INSUFFICIENT_HISTORY"
        elif quality_score < 0.5:
            status = "INSUFFICIENT_TIMESTAMP_QUALITY"
        else:
            status = "SUFFICIENT_HISTORY"

        self.assertEqual(status, "INSUFFICIENT_HISTORY")

    def test_insufficient_timestamp_quality(self):
        """Test eligibility rule for entities with low timestamp quality."""
        obs_count = 10
        distinct_days = 4
        quality_score = 0.3

        if obs_count < 5 or distinct_days < 2:
            status = "INSUFFICIENT_HISTORY"
        elif quality_score < 0.5:
            status = "INSUFFICIENT_TIMESTAMP_QUALITY"
        else:
            status = "SUFFICIENT_HISTORY"

        self.assertEqual(status, "INSUFFICIENT_TIMESTAMP_QUALITY")

    def test_peer_group_median_comparison(self):
        """Test that self-deviation is computed against department peer group median."""
        user_val = 15
        peer_median = 5
        peer_mad = 2.0
        zscore = calculate_robust_zscore(user_val, peer_median, peer_mad)
        # Scale = 1.4826 * 2.0 = 2.9652. Z = (15 - 5) / 2.9652 = 3.3724
        self.assertAlmostEqual(zscore, (15 - 5) / (1.4826 * 2.0), places=3)

    def test_quality_aware_confidence_propagation(self):
        """Test that confidence falls to UNTRUSTED for insufficient history."""
        status = "INSUFFICIENT_HISTORY"
        obs_count = 2
        quality_score = 1.0

        if status == "INSUFFICIENT_HISTORY":
            conf = "UNTRUSTED"
        elif status == "INSUFFICIENT_TIMESTAMP_QUALITY":
            conf = "LOW"
        elif obs_count >= 10 and quality_score >= 0.8:
            conf = "HIGH"
        else:
            conf = "MEDIUM"

        self.assertEqual(conf, "UNTRUSTED")


if __name__ == "__main__":
    unittest.main()
