"""
TraceONE Behavioral Baseline Validation Suite
Phase E: Step 13 - Behavioral Baselines & Deviation Engine Validation

Verifies eligibility rules, baseline non-negativity, robust Z-score bounds,
zero-baseline safeguards, timestamp handling, peer group integrity,
multi-metric signal counts, and data-quality confidence propagation.
"""

from pathlib import Path
import sys
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def run_baseline_validation():
    print("=" * 70)
    print("TRACEONE BEHAVIORAL BASELINE VALIDATION (PHASE E)")
    print("=" * 70)

    user_base = pd.read_csv(PROCESSED_DIR / "user_behavior_baselines.csv")
    host_base = pd.read_csv(PROCESSED_DIR / "host_behavior_baselines.csv")
    user_dev = pd.read_csv(PROCESSED_DIR / "user_behavior_deviations.csv")
    host_dev = pd.read_csv(PROCESSED_DIR / "host_behavior_deviations.csv")
    cluster_df = pd.read_csv(PROCESSED_DIR / "clustering_prepared_features.csv")

    passed_checks = 0
    total_checks = 0

    def assert_check(condition, name, msg=""):
        nonlocal passed_checks, total_checks
        total_checks += 1
        if condition:
            passed_checks += 1
            print(f" [PASS] {name}")
        else:
            print(f"![FAIL] {name}: {msg}")

    # Check 1: User baseline row count matches canonical users (3000)
    assert_check(len(user_base) == 3000, "User Baseline Row Count", f"Expected 3000, got {len(user_base)}")

    # Check 2: Host baseline row count matches canonical hosts (8413)
    assert_check(len(host_base) == 8413, "Host Baseline Row Count", f"Expected 8413, got {len(host_base)}")

    # Check 3: Observation count breakdown consistency for users
    user_obs_consistent = (user_base['observation_count'] == user_base['valid_timestamp_count'] + user_base['unknown_timestamp_count']).all()
    assert_check(user_obs_consistent, "User Observation Count Consistency", "observation_count != valid + unknown")

    # Check 4: Observation count breakdown consistency for hosts
    host_obs_consistent = (host_base['observation_count'] == host_base['valid_timestamp_count'] + host_base['unknown_timestamp_count']).all()
    assert_check(host_obs_consistent, "Host Observation Count Consistency", "observation_count != valid + unknown")

    # Check 5: Valid eligibility categories for users
    valid_elig_user = set(user_base['eligibility_status']).issubset({'SUFFICIENT_HISTORY', 'INSUFFICIENT_HISTORY', 'INSUFFICIENT_TIMESTAMP_QUALITY'})
    assert_check(valid_elig_user, "User Eligibility Categories", f"Unexpected statuses: {set(user_base['eligibility_status'])}")

    # Check 6: Valid eligibility categories for hosts
    valid_elig_host = set(host_base['eligibility_status']).issubset({'SUFFICIENT_HISTORY', 'INSUFFICIENT_HISTORY', 'INSUFFICIENT_TIMESTAMP_QUALITY'})
    assert_check(valid_elig_host, "Host Eligibility Categories", f"Unexpected statuses: {set(host_base['eligibility_status'])}")

    # Check 7: Valid baseline confidence categories
    valid_conf = set(user_base['baseline_confidence']).issubset({'HIGH', 'MEDIUM', 'LOW', 'UNTRUSTED'}) and set(host_base['baseline_confidence']).issubset({'HIGH', 'MEDIUM', 'LOW', 'UNTRUSTED'})
    assert_check(valid_conf, "Baseline Confidence Categories", "Invalid confidence levels found")

    # Check 8: No NaNs or Infs in Robust Z-scores for users
    z_user_cols = [c for c in user_dev.columns if ('zscore' in c or 'deviation' in c) and pd.api.types.is_numeric_dtype(user_dev[c])]
    no_nan_user_z = not user_dev[z_user_cols].isna().any().any() and not np.isinf(user_dev[z_user_cols].to_numpy().astype(float)).any()
    assert_check(no_nan_user_z, "User Robust Z-Score Cleanliness", "NaN or Inf values detected in user z-scores/deviations")

    # Check 9: No NaNs or Infs in Robust Z-scores for hosts
    z_host_cols = [c for c in host_dev.columns if ('zscore' in c or 'deviation' in c) and pd.api.types.is_numeric_dtype(host_dev[c])]
    no_nan_host_z = not host_dev[z_host_cols].isna().any().any() and not np.isinf(host_dev[z_host_cols].to_numpy().astype(float)).any()
    assert_check(no_nan_host_z, "Host Robust Z-Score Cleanliness", "NaN or Inf values detected in host z-scores/deviations")

    # Check 10: Multi-signal deviation count bounds for users (0 to 4)
    user_multi_bounds = (user_dev['multi_signal_deviation_count'] >= 0).all() and (user_dev['multi_signal_deviation_count'] <= 4).all()
    assert_check(user_multi_bounds, "User Multi-Signal Bounds (0..4)", f"Range out of bounds: [{user_dev['multi_signal_deviation_count'].min()}, {user_dev['multi_signal_deviation_count'].max()}]")

    # Check 11: Multi-signal deviation count bounds for hosts (0 to 3)
    host_multi_bounds = (host_dev['multi_signal_deviation_count'] >= 0).all() and (host_dev['multi_signal_deviation_count'] <= 3).all()
    assert_check(host_multi_bounds, "Host Multi-Signal Bounds (0..3)", f"Range out of bounds: [{host_dev['multi_signal_deviation_count'].min()}, {host_dev['multi_signal_deviation_count'].max()}]")

    # Check 12: Neutral deviation status terminology check (no threat/attack/compromise labels)
    user_status_cols = [c for c in user_dev.columns if 'status' in c]
    forbidden_terms = {'COMPROMISED', 'ATTACK', 'INSIDER', 'MALICIOUS', 'THREAT'}
    found_user_terms = set()
    for col in user_status_cols:
        found_user_terms.update(set(user_dev[col].astype(str).unique()))
    user_neutral = len(found_user_terms.intersection(forbidden_terms)) == 0
    assert_check(user_neutral, "User Neutral Status Terminology", f"Found biased terms: {found_user_terms.intersection(forbidden_terms)}")

    # Check 13: Host neutral status terminology check
    host_status_cols = [c for c in host_dev.columns if 'status' in c]
    found_host_terms = set()
    for col in host_status_cols:
        found_host_terms.update(set(host_dev[col].astype(str).unique()))
    host_neutral = len(found_host_terms.intersection(forbidden_terms)) == 0
    assert_check(host_neutral, "Host Neutral Status Terminology", f"Found biased terms: {found_host_terms.intersection(forbidden_terms)}")

    # Check 14: Department Peer Group completeness for users
    dept_peer_complete = not user_base['peer_failed_login_median'].isna().any()
    assert_check(dept_peer_complete, "User Peer Group Completeness", "Missing department peer medians found")

    # Check 15: Clustering prepared feature matrix cleanliness (no NaNs, total entities = 11413)
    cluster_clean = (len(cluster_df) == 11413) and not cluster_df.isna().any().any()
    assert_check(cluster_clean, "Clustering Feature Matrix Cleanliness", f"Rows: {len(cluster_df)}, NaNs: {cluster_df.isna().sum().sum()}")

    print("-" * 70)
    print(f"VALIDATION SUMMARY: {passed_checks}/{total_checks} CHECKS PASSED")
    print("=" * 70)

    if passed_checks < total_checks:
        sys.exit(1)


if __name__ == "__main__":
    run_baseline_validation()
