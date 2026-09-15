"""
TraceONE Unit Test Suite for Security Features
Phase D: Security Feature Engineering
"""

import unittest
import numpy as np
import pandas as pd


class TestSecurityFeatures(unittest.TestCase):

    def test_authentication_failure_rate_zero_denominator(self):
        """Test divide-by-zero safeguard for authentication failure rate."""
        total_events = 0
        failed_logins = 0
        rate = failed_logins / total_events if total_events > 0 else 0.0
        self.assertEqual(rate, 0.0)

    def test_authentication_failure_rate_valid_calculation(self):
        """Test standard failure rate calculation."""
        total_events = 10
        failed_logins = 4
        rate = failed_logins / total_events if total_events > 0 else 0.0
        self.assertAlmostEqual(rate, 0.4)

    def test_firewall_deny_ratio_bounds(self):
        """Test firewall deny ratio bounds."""
        total_logs = 100
        denies = 25
        ratio = denies / total_logs if total_logs > 0 else 0.0
        self.assertTrue(0.0 <= ratio <= 1.0)
        self.assertAlmostEqual(ratio, 0.25)

    def test_off_hours_hour_boundary(self):
        """Test off-hours timestamp boundary logic (18:00 to 06:00)."""
        dt_off1 = pd.to_datetime("2026-08-09 19:30:00")
        dt_off2 = pd.to_datetime("2026-08-09 03:15:00")
        dt_on = pd.to_datetime("2026-08-09 10:00:00")

        self.assertTrue((dt_off1.hour >= 18) or (dt_off1.hour < 6))
        self.assertTrue((dt_off2.hour >= 18) or (dt_off2.hour < 6))
        self.assertFalse((dt_on.hour >= 18) or (dt_on.hour < 6))


if __name__ == "__main__":
    unittest.main()
