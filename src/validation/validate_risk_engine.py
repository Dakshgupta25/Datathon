"""
TraceONE Explainable Risk Engine Validation Suite
Phase F: Step 15 - Risk Engine Validation

Verifies risk score bounds [0, 100], threshold classifications, contributor non-negativity,
evidence confidence bounds [0.0, 1.0], source record evidence linkage, counter-evidence,
hypothesis evidence backing, and strict separation of legacy IAM source risk.
"""

from pathlib import Path
import json
import sys
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def run_risk_engine_validation():
    print("=" * 70)
    print("TRACEONE RISK ENGINE VALIDATION (PHASE F)")
    print("=" * 70)

    user_risk = pd.read_csv(PROCESSED_DIR / "user_risk_scores.csv")
    host_risk = pd.read_csv(PROCESSED_DIR / "host_risk_scores.csv")
    combined_risk = pd.read_csv(PROCESSED_DIR / "traceone_risk_scores.csv")
    contrib_df = pd.read_csv(PROCESSED_DIR / "risk_contributors.csv")
    hypo_df = pd.read_csv(PROCESSED_DIR / "security_hypotheses.csv")
    evidence_df = pd.read_csv(PROCESSED_DIR / "normalized_evidence_table.csv")

    with open(PROCESSED_DIR / "why_flagged_explanations.json") as f:
        explanations = json.load(f)

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

    # Check 1: User risk score bounds [0.0, 100.0]
    u_bounded = (user_risk['traceone_risk_score'] >= 0.0).all() and (user_risk['traceone_risk_score'] <= 100.0).all()
    assert_check(u_bounded, "User Risk Score Bounds [0, 100]", f"Min: {user_risk['traceone_risk_score'].min()}, Max: {user_risk['traceone_risk_score'].max()}")

    # Check 2: Host risk score bounds [0.0, 100.0]
    h_bounded = (host_risk['traceone_risk_score'] >= 0.0).all() and (host_risk['traceone_risk_score'] <= 100.0).all()
    assert_check(h_bounded, "Host Risk Score Bounds [0, 100]", f"Min: {host_risk['traceone_risk_score'].min()}, Max: {host_risk['traceone_risk_score'].max()}")

    # Check 3: Risk Level Threshold Consistency
    def check_level(row):
        score = row['traceone_risk_score']
        level = row['risk_level']
        if score < 30.0:
            return level == "LOW"
        elif score < 60.0:
            return level == "MODERATE"
        elif score < 80.0:
            return level == "HIGH"
        else:
            return level == "CRITICAL"

    level_consistent = combined_risk.apply(check_level, axis=1).all()
    assert_check(level_consistent, "Risk Level Threshold Consistency", "Mismatch between risk score and assigned level")

    # Check 4: Evidence Confidence Score Bounds [0.0, 1.0]
    conf_bounded = (combined_risk['risk_confidence_score'] >= 0.0).all() and (combined_risk['risk_confidence_score'] <= 1.0).all()
    assert_check(conf_bounded, "Risk Confidence Score Bounds [0, 1]", f"Min: {combined_risk['risk_confidence_score'].min()}, Max: {combined_risk['risk_confidence_score'].max()}")

    # Check 5: Risk Contributor Non-Negativity
    contrib_cols = ['auth_contribution', 'network_contribution', 'endpoint_contribution', 'operational_contribution', 'multi_signal_boost']
    no_neg_contrib = (contrib_df[contrib_cols] >= 0.0).all().all()
    assert_check(no_neg_contrib, "Risk Contributor Non-Negativity", "Negative contributor value detected")

    # Check 6: Entity ID Coverage (3000 Users + 8413 Hosts = 11413 Total)
    total_entities = len(combined_risk) == 11413 and combined_risk['entity_id'].isna().sum() == 0
    assert_check(total_entities, "Entity ID Coverage (11,413 Total)", f"Total rows: {len(combined_risk)}, NaNs: {combined_risk['entity_id'].isna().sum()}")

    # Check 7: Normalized Evidence Table Linkage Integrity
    ev_linked = len(evidence_df) > 0 and 'source_record_id' in evidence_df.columns and evidence_df['source_record_id'].isna().sum() == 0
    assert_check(ev_linked, "Normalized Evidence Table Linkage Integrity", f"Rows: {len(evidence_df)}, Missing record IDs: {evidence_df['source_record_id'].isna().sum()}")

    # Check 8: "Why Flagged" Machine-Readable Object Completeness
    ex_valid = len(explanations) > 0 and all('top_contributors' in e and 'counter_evidence' in e for e in explanations)
    assert_check(ex_valid, "Why Flagged Explanation Object Completeness", f"Valid JSON objects: {len(explanations)}")

    # Check 9: Security Hypotheses Evidence Backing (High Risk Entities have Non-Null Hypotheses)
    high_risk_entities = set(combined_risk[combined_risk['traceone_risk_score'] >= 60.0]['entity_id'])
    high_risk_hypo = hypo_df[hypo_df['entity_id'].isin(high_risk_entities)]
    hypo_backed = not high_risk_hypo['hypothesis'].isna().any()
    assert_check(hypo_backed, "Security Hypotheses Evidence Backing", "Missing hypothesis for high risk entity")

    # Check 10: Strict Separation of Legacy IAM Source Risk
    user_iam_sep = 'source_iam_risk_indicator' in user_risk.columns and 'source_iam_risk_quality' in user_risk.columns
    assert_check(user_iam_sep, "Strict Separation of Legacy Source IAM Risk", "Missing source_iam_risk_indicator or quality columns")

    print("-" * 70)
    print(f"VALIDATION SUMMARY: {passed_checks}/{total_checks} CHECKS PASSED")
    print("=" * 70)

    if passed_checks < total_checks:
        sys.exit(1)


if __name__ == "__main__":
    run_risk_engine_validation()
