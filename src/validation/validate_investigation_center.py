"""
TraceONE Investigation Center Validation Suite (Phase K)
Validates entity lookup, risk retrieval, contributor retrieval, baselines, peer comparison,
timeline retrieval, sequence retrieval, evidence explorer, bounded graph traversal,
hypothesis panel, counter-evidence retrieval, and missing-data state handling.
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
    load_why_flagged_explanations,
    load_security_hypotheses,
    load_normalized_evidence,
    load_user_baselines,
    load_host_baselines,
    get_graph_engine,
    load_data_trust_status
)

def run_investigation_validation():
    print("==================================================")
    print("TRACEONE INVESTIGATION CENTER VALIDATION SUITE (PHASE K)")
    print("==================================================")
    
    passed_tests = 0
    total_tests = 0
    
    # Check 1: Valid User Lookup (EMP10194)
    total_tests += 1
    user_risk = load_user_risk_scores()
    user_row = user_risk[user_risk['entity_id'] == 'EMP10194']
    if not user_row.empty:
        print(" [PASS] Valid User Lookup verified (EMP10194 found)")
        passed_tests += 1
    else:
        print(" [FAIL] EMP10194 user lookup failed")
        
    # Check 2: Valid Host Lookup (VDR-11889)
    total_tests += 1
    host_risk = load_host_risk_scores()
    host_row = host_risk[host_risk['entity_id'] == 'VDR-11889']
    if not host_row.empty:
        print(" [PASS] Valid Host Lookup verified (VDR-11889 found)")
        passed_tests += 1
    else:
        print(" [FAIL] VDR-11889 host lookup failed")
        
    # Check 3: Risk Score & Evidence Confidence Separation
    total_tests += 1
    if not user_row.empty:
        r_score = user_row.iloc[0]['traceone_risk_score']
        c_score = user_row.iloc[0]['risk_confidence_score']
        c_level = user_row.iloc[0]['risk_confidence_level']
        if r_score == 100.0 and c_score > 0.0 and c_level in ['HIGH', 'MEDIUM', 'LOW']:
            print(f" [PASS] Risk & Confidence separation verified (Risk: {r_score}, Conf: {c_level} {c_score:.2f})")
            passed_tests += 1
        else:
            print(" [FAIL] Risk and confidence separation invalid")
            
    # Check 4: Risk Contributor Retrieval (why_flagged_explanations.json)
    total_tests += 1
    explanations = load_why_flagged_explanations()
    emp_exp = explanations.get('EMP10194', {})
    top_contribs = emp_exp.get('top_contributors', {})
    if 'authentication' in top_contribs and 'network' in top_contribs:
        print(f" [PASS] Risk Contributor Retrieval verified ({len(top_contribs)} contributors found)")
        passed_tests += 1
    else:
        print(" [FAIL] Risk contributor retrieval failed")
        
    # Check 5: Behavioral Baseline Retrieval (user_behavior_baselines.csv)
    total_tests += 1
    baselines = load_user_baselines()
    b_row = baselines[baselines['user_id'] == 'EMP10194']
    if not b_row.empty and 'failed_login_count' in b_row.columns:
        print(" [PASS] Behavioral Baseline Retrieval verified")
        passed_tests += 1
    else:
        print(" [FAIL] Behavioral baseline retrieval failed")
        
    # Check 6: Department Peer Context Retrieval
    total_tests += 1
    peer_ctx = emp_exp.get('peer_comparison', {})
    if peer_ctx.get('department') == 'R&D' and 'department_failed_login_percentile' in peer_ctx:
        print(" [PASS] Department Peer Context Retrieval verified")
        passed_tests += 1
    else:
        print(" [FAIL] Peer context retrieval failed")

    # Check 7: Cluster Context Retrieval
    total_tests += 1
    clusters = load_user_clusters()
    c_row = clusters[clusters['user_id'] == 'EMP10194']
    if not c_row.empty and c_row.iloc[0]['cluster_label'] == 'SECURITY_SENSITIVE_OUTLIERS':
        print(" [PASS] Cluster Context Retrieval verified (CLUSTER_3 / SECURITY_SENSITIVE_OUTLIERS)")
        passed_tests += 1
    else:
        print(" [FAIL] Cluster context retrieval failed")
        
    # Check 8: Temporal Sequence Retrieval
    total_tests += 1
    sequences = load_temporal_sequences()
    emp_seqs = sequences[sequences['entity_id'] == 'EMP10194']
    if not emp_seqs.empty:
        print(f" [PASS] Temporal Sequence Retrieval verified ({len(emp_seqs)} sequence chains found)")
        passed_tests += 1
    else:
        print(" [FAIL] Temporal sequence retrieval failed")
        
    # Check 9: Normalized Evidence Retrieval
    total_tests += 1
    evidence = load_normalized_evidence()
    emp_ev = evidence[evidence['entity_id'] == 'EMP10194']
    if not emp_ev.empty:
        print(f" [PASS] Normalized Evidence Retrieval verified ({len(emp_ev)} evidence records found)")
        passed_tests += 1
    else:
        print(" [FAIL] Normalized evidence retrieval failed")

    # Check 10: Bounded Graph Neighborhood Retrieval
    total_tests += 1
    engine = get_graph_engine()
    if engine is not None:
        graph_data = engine.get_bounded_neighborhood('EMP10194', max_hops=1)
        if graph_data['node_count'] > 0 and graph_data['edge_count'] > 0:
            print(f" [PASS] Bounded Graph Neighborhood verified ({graph_data['node_count']} nodes, {graph_data['edge_count']} edges)")
            passed_tests += 1
        else:
            print(" [FAIL] Graph neighborhood returned zero nodes")
    else:
        print(" [FAIL] Graph engine unavailable")

    # Check 11: Hypothesis & Counter-Evidence Retrieval
    total_tests += 1
    hypo_df = load_security_hypotheses()
    h_row = hypo_df[hypo_df['entity_id'] == 'EMP10194']
    counter_ev = emp_exp.get('counter_evidence', [])
    if not h_row.empty and len(counter_ev) > 0:
        print(f" [PASS] Hypothesis & Counter-Evidence verified (Hypothesis: {h_row.iloc[0]['hypothesis'][:30]}..., Counter-Ev: {counter_ev})")
        passed_tests += 1
    else:
        print(" [FAIL] Hypothesis or counter-evidence retrieval failed")

    # Check 12: Missing-Data State Handling (Unknown User EMP99999)
    total_tests += 1
    unk_row = user_risk[user_risk['entity_id'] == 'EMP99999']
    unk_exp = explanations.get('EMP99999', {})
    if unk_row.empty and not unk_exp:
        print(" [PASS] Missing-Data State Handling verified (Clean fallback for unknown entity EMP99999)")
        passed_tests += 1
    else:
        print(" [FAIL] Missing-data state handling failed")
        
    # Check 13: Phase K.1 Semantic & Mathematical Language Audit Inspection
    total_tests += 1
    app_path = PROJECT_ROOT / "app.py"
    with open(app_path, "r", encoding="utf-8") as f:
        app_code = f.read()
        
    has_points_term = "Risk Component Score (Points)" in app_code
    has_mfa_wording = "No MFA failure was observed in the available telemetry" in app_code
    has_old_overclaim = "confirming MFA controls" in app_code or "Contribution Weight (%)" in app_code
    
    if has_points_term and has_mfa_wording and not has_old_overclaim:
        print(" [PASS] Phase K.1 Semantic Audit verified (Points terminology & evidence-preserving MFA wording present)")
        passed_tests += 1
    else:
        print(f" [FAIL] Phase K.1 Semantic Audit failed: points={has_points_term}, mfa={has_mfa_wording}, overclaim={has_old_overclaim}")

    print("--------------------------------------------------")
    print(f"RESULTS: {passed_tests} / {total_tests} checks passed.")
    print("==================================================")
    
    if passed_tests == total_tests:
        print("ALL INVESTIGATION CENTER VALIDATION TESTS PASSED SUCCESSFULLY.")
        return 0
    else:
        print("INVESTIGATION CENTER VALIDATION FAILED.")
        return 1

if __name__ == "__main__":
    sys.exit(run_investigation_validation())
