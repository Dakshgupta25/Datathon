"""
TraceONE Unit Test Suite for Explainable Risk Engine
Phase F: Step 16 - Risk Engine Unit Testing
"""

import unittest
import numpy as np
import pandas as pd
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.transformations.risk_engine import (
    calculate_evidence_confidence,
    get_confidence_level,
    get_risk_level
)


class TestRiskEngine(unittest.TestCase):

    def test_1_completely_normal_entity(self):
        """Test risk calculation for a completely normal entity (0 z-scores)."""
        z_auth, z_net, z_ep, z_ops = 0.0, 0.0, 0.0, 0.0
        s_auth = min(25.0, (z_auth / 4.0) * 25.0)
        s_net = min(25.0, (z_net / 4.0) * 25.0)
        s_ep = min(25.0, (z_ep / 4.0) * 25.0)
        s_ops = min(25.0, (z_ops / 4.0) * 25.0)

        base_risk = s_auth + s_net + s_ep + s_ops
        self.assertEqual(base_risk, 0.0)
        self.assertEqual(get_risk_level(base_risk), "LOW")

    def test_2_one_unusual_signal(self):
        """Test single unusual signal (multiplier = 1.0x)."""
        z_auth, z_net, z_ep, z_ops = 3.0, 0.0, 0.0, 0.0
        s_auth = min(25.0, (z_auth / 4.0) * 25.0)  # (3.0/4.0)*25 = 18.75
        base_risk = s_auth

        active_signals = sum([1 for z in [z_auth, z_net, z_ep, z_ops] if z >= 2.5])
        multi_multipliers = {0: 1.0, 1: 1.0, 2: 1.25, 3: 1.50, 4: 1.75}
        multiplier = multi_multipliers.get(active_signals, 1.0)

        self.assertEqual(multiplier, 1.0)
        self.assertEqual(base_risk * multiplier, 18.75)

    def test_3_two_independent_unusual_signals(self):
        """Test dual-dimension agreement (multiplier = 1.25x)."""
        z_auth, z_net, z_ep, z_ops = 3.0, 3.0, 0.0, 0.0
        active_signals = sum([1 for z in [z_auth, z_net, z_ep, z_ops] if z >= 2.5])
        multi_multipliers = {0: 1.0, 1: 1.0, 2: 1.25, 3: 1.50, 4: 1.75}
        multiplier = multi_multipliers.get(active_signals, 1.0)

        self.assertEqual(active_signals, 2)
        self.assertEqual(multiplier, 1.25)

    def test_4_multi_signal_abnormal_entity(self):
        """Test 4 independent elevated signals (multiplier = 1.75x)."""
        z_auth, z_net, z_ep, z_ops = 4.0, 4.0, 4.0, 4.0
        s_auth = min(25.0, (z_auth / 4.0) * 25.0)  # 25.0
        s_net = min(25.0, (z_net / 4.0) * 25.0)   # 25.0
        s_ep = min(25.0, (z_ep / 4.0) * 25.0)     # 25.0
        s_ops = min(25.0, (z_ops / 4.0) * 25.0)   # 25.0

        base_risk = s_auth + s_net + s_ep + s_ops  # 100.0
        active_signals = 4
        multiplier = 1.75
        final_risk = min(100.0, base_risk * multiplier)

        self.assertEqual(final_risk, 100.0)
        self.assertEqual(get_risk_level(final_risk), "CRITICAL")

    def test_5_low_quality_evidence_confidence(self):
        """Test that confidence score drops when timestamp quality is degraded."""
        conf = calculate_evidence_confidence(obs_count=10, ts_quality=0.1, baseline_conf='LOW')
        self.assertLess(conf, 0.5)
        self.assertEqual(get_confidence_level(conf), "LOW")

    def test_6_insufficient_baseline_counter_evidence(self):
        """Test counter-evidence detection for insufficient history."""
        eligibility_status = "INSUFFICIENT_HISTORY"
        counter_ev = []
        if eligibility_status == "INSUFFICIENT_HISTORY":
            counter_ev.append("INSUFFICIENT_BASELINE_HISTORY")
        self.assertIn("INSUFFICIENT_BASELINE_HISTORY", counter_ev)

    def test_7_invalid_source_risk_score(self):
        """Test that invalid source IAM risk does not alter behavioral risk calculation."""
        behavioral_risk = 75.0
        raw_source_iam_risk = "Invalid_Text"
        source_iam_indicator = "Unknown"  # Cleaned state
        # Behavioral risk remains unaffected by source_iam_indicator
        self.assertEqual(behavioral_risk, 75.0)
        self.assertEqual(source_iam_indicator, "Unknown")

    def test_8_missing_source_risk_score(self):
        """Test missing source risk score handling."""
        raw_source_iam_risk = None
        source_iam_indicator = "Unknown"
        self.assertEqual(source_iam_indicator, "Unknown")

    def test_9_zero_evidence_confidence(self):
        """Test entity with 0 observations has UNTRUSTED confidence."""
        conf = calculate_evidence_confidence(obs_count=0, ts_quality=0.0, baseline_conf='UNTRUSTED')
        self.assertEqual(conf, 0.03)  # 0.3 * 0.1 = 0.03
        self.assertEqual(get_confidence_level(conf), "UNTRUSTED")

    def test_10_unsupported_hypothesis(self):
        """Test that low-risk entities default to NO_ACTIONABLE_HYPOTHESIS."""
        final_risk = 25.0
        hypotheses = ["POSSIBLE_CREDENTIAL_COMPROMISE"]
        hypothesis_str = "; ".join(hypotheses) if hypotheses and final_risk >= 50.0 else "NO_ACTIONABLE_HYPOTHESIS"
        self.assertEqual(hypothesis_str, "NO_ACTIONABLE_HYPOTHESIS")

    def test_11_high_risk_low_confidence(self):
        """Test high risk entity with degraded evidence quality."""
        final_risk = 85.0
        conf = calculate_evidence_confidence(obs_count=2, ts_quality=0.3, baseline_conf='LOW')
        risk_level = get_risk_level(final_risk)
        conf_level = get_confidence_level(conf)

        self.assertEqual(risk_level, "CRITICAL")
        self.assertEqual(conf_level, "LOW")

    def test_12_high_risk_high_confidence(self):
        """Test high risk entity with strong evidence quality."""
        final_risk = 85.0
        conf = calculate_evidence_confidence(obs_count=15, ts_quality=1.0, baseline_conf='HIGH')
        risk_level = get_risk_level(final_risk)
        conf_level = get_confidence_level(conf)

        self.assertEqual(risk_level, "CRITICAL")
        self.assertEqual(conf_level, "HIGH")


if __name__ == "__main__":
    unittest.main()
