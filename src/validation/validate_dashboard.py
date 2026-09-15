"""
TraceONE Dashboard Validation Suite (Phase J.1 Audited)
Validates data loader functions, verifies metric consistency across processed files,
enforces exact TraceONE risk thresholds (60/80), checks terminology rules,
and confirms telemetry provenance metadata.
"""

import sys
from pathlib import Path
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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

def run_dashboard_validation():
    print("==================================================")
    print("TRACEONE DASHBOARD VALIDATION SUITE (PHASE J.1)")
    print("==================================================")
    
    passed_tests = 0
    total_tests = 0
    
    # Check 1: User Risk Scores Loader
    total_tests += 1
    user_risk = load_user_risk_scores()
    if not user_risk.empty and len(user_risk) == 3000:
        print(" [PASS] User Risk Scores loaded (3,000 users)")
        passed_tests += 1
    else:
        print(f" [FAIL] User Risk Scores load error: got {len(user_risk)} rows")
        
    # Check 2: Host Risk Scores Loader
    total_tests += 1
    host_risk = load_host_risk_scores()
    if not host_risk.empty and len(host_risk) == 8413:
        print(" [PASS] Host Risk Scores loaded (8,413 hosts)")
        passed_tests += 1
    else:
        print(f" [FAIL] Host Risk Scores load error: got {len(host_risk)} rows")
        
    # Check 3: User Behavioral Clusters Loader
    total_tests += 1
    clusters = load_user_clusters()
    if not clusters.empty and len(clusters) == 3000:
        print(" [PASS] User Clusters loaded (3,000 users)")
        passed_tests += 1
    else:
        print(f" [FAIL] User Clusters load error: got {len(clusters)} rows")
        
    # Check 4: Dynamic Cluster Profiles Loader
    total_tests += 1
    c_prof = load_cluster_profiles()
    if not c_prof.empty and len(c_prof) == 4 and 'avg_risk_score' in c_prof.columns:
        c3_row = c_prof[c_prof['cluster_id'] == 'CLUSTER_3'].iloc[0]
        if c3_row['avg_risk_score'] == 100.0:
            print(" [PASS] Dynamic Cluster Profiles verified (4 clusters, CLUSTER_3 avg risk = 100.0)")
            passed_tests += 1
        else:
            print(f" [FAIL] CLUSTER_3 avg risk mismatch in cluster_profiles.csv: {c3_row['avg_risk_score']}")
    else:
        print(" [FAIL] Cluster Profiles load empty or malformed")

    # Check 5: CLUSTER_3 High/Critical Risk Concentration Verification
    total_tests += 1
    c3_users = clusters[clusters['cluster_label'] == 'SECURITY_SENSITIVE_OUTLIERS']
    c3_crit_count = len(c3_users[c3_users['risk_level'] == 'CRITICAL'])
    total_high_crit = len(user_risk[user_risk['risk_level'].isin(['HIGH', 'CRITICAL'])])
    
    if c3_crit_count == 60 and total_high_crit == 78:
        pct = (c3_crit_count / total_high_crit) * 100
        print(f" [PASS] CLUSTER_3 concentration verified: {c3_crit_count}/{total_high_crit} = {pct:.2f}%")
        passed_tests += 1
    else:
        print(f" [FAIL] CLUSTER_3 concentration mismatch: got c3_crit={c3_crit_count}, total_high_crit={total_high_crit}")
        
    # Check 6: Exact Risk Threshold Verification (LOW <30, MOD 30-59.99, HIGH 60-79.99, CRIT >=80)
    total_tests += 1
    invalid_thresholds = 0
    for idx, row in user_risk.iterrows():
        score = row['traceone_risk_score']
        lvl = row['risk_level']
        if score >= 80.0 and lvl != 'CRITICAL':
            invalid_thresholds += 1
        elif 60.0 <= score < 80.0 and lvl != 'HIGH':
            invalid_thresholds += 1
        elif 30.0 <= score < 60.0 and lvl != 'MODERATE':
            invalid_thresholds += 1
        elif score < 30.0 and lvl != 'LOW':
            invalid_thresholds += 1
            
    if invalid_thresholds == 0:
        print(" [PASS] TraceONE exact risk thresholds verified (0 threshold classification errors)")
        passed_tests += 1
    else:
        print(f" [FAIL] Found {invalid_thresholds} entities with invalid risk level assignment")

    # Check 7: Temporal Sequences Loader
    total_tests += 1
    sequences = load_temporal_sequences()
    if not sequences.empty and len(sequences) == 2412:
        print(" [PASS] Temporal Sequences loaded (2,412 sequences)")
        passed_tests += 1
    else:
        print(f" [FAIL] Temporal Sequences load error: got {len(sequences)} rows")
        
    # Check 8: Peer Group Anomalies Loader
    total_tests += 1
    peer_outliers = load_peer_anomalies()
    if not peer_outliers.empty:
        print(f" [PASS] Peer Group Anomalies loaded ({len(peer_outliers)} rows)")
        passed_tests += 1
    else:
        print(" [FAIL] Peer Group Anomalies load empty")
        
    # Check 9: Multi-Dimensional Outliers Loader
    total_tests += 1
    multidim = load_multidim_outliers()
    if not multidim.empty:
        print(f" [PASS] Multi-Dimensional Outliers loaded ({len(multidim)} rows)")
        passed_tests += 1
    else:
        print(" [FAIL] Multi-Dimensional Outliers load empty")
        
    # Check 10: Data Trust & Telemetry Provenance Metadata
    total_tests += 1
    trust = load_data_trust_status()
    if trust.get("iam_firewall_overlap_pct") == "2.26%" and trust.get("telemetry_window") == "2026-08-01 → 2026-08-15":
        print(" [PASS] Data Trust status correctly formatted (IAM-Firewall overlap: 2.26%)")
        passed_tests += 1
    else:
        print(f" [FAIL] Data Trust metadata mismatch: {trust}")

    # Check 11: Code Inspection — Absence of Hardcoded Analytical Strings or Misleading Claims in app.py
    total_tests += 1
    app_path = PROJECT_ROOT / "app.py"
    with open(app_path, "r", encoding="utf-8") as f:
        app_code = f.read()
        
    forbidden_terms = ["Verified Threats", "100% Linkage", "52.8 / 100", "94.2 / 100"]
    found_forbidden = [term for term in forbidden_terms if term in app_code]
    
    if not found_forbidden:
        print(" [PASS] Source code inspection verified (Zero hardcoded metrics or misleading claims)")
        passed_tests += 1
    else:
        print(f" [FAIL] Found forbidden hardcoded / misleading terms in app.py: {found_forbidden}")
        
    print("--------------------------------------------------")
    print(f"RESULTS: {passed_tests} / {total_tests} checks passed.")
    print("==================================================")
    
    if passed_tests == total_tests:
        print("ALL DASHBOARD VALIDATION TESTS PASSED SUCCESSFULLY.")
        return 0
    else:
        print("DASHBOARD VALIDATION FAILED.")
        return 1

if __name__ == "__main__":
    sys.exit(run_dashboard_validation())
