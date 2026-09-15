"""
TraceONE Explainable Evidence-Based Risk Engine
Phase F: Risk Engine Implementation

Calculates mathematically transparent risk scores, multi-signal correlation multipliers,
evidence confidence scores, contributor breakdowns, counter-evidence flags,
and evidence-backed security hypotheses while strictly maintaining source provenance.
"""

from pathlib import Path
import json
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def calculate_evidence_confidence(obs_count, ts_quality, baseline_conf):
    """
    Calculate evidence confidence score bounded [0.0, 1.0].
    Separates evidence trustworthiness from risk magnitude.
    """
    conf_map = {'HIGH': 1.0, 'MEDIUM': 0.75, 'LOW': 0.4, 'UNTRUSTED': 0.1}
    base_weight = conf_map.get(str(baseline_conf).upper(), 0.5)
    obs_weight = min(1.0, float(obs_count) / 10.0) if obs_count is not None else 0.0
    ts_weight = float(ts_quality) if pd.notna(ts_quality) else 0.0
    
    conf_score = 0.4 * ts_weight + 0.3 * obs_weight + 0.3 * base_weight
    return round(float(np.clip(conf_score, 0.0, 1.0)), 4)


def get_confidence_level(conf_score):
    """Classify confidence score into categorical levels."""
    if conf_score >= 0.8:
        return "HIGH"
    elif conf_score >= 0.5:
        return "MEDIUM"
    elif conf_score >= 0.2:
        return "LOW"
    else:
        return "UNTRUSTED"


def get_risk_level(risk_score):
    """Classify TraceONE risk score into transparent risk levels."""
    if risk_score < 30.0:
        return "LOW"
    elif risk_score < 60.0:
        return "MODERATE"
    elif risk_score < 80.0:
        return "HIGH"
    else:
        return "CRITICAL"


def build_user_risk_scores(user_dev, events_df):
    """Compute User risk scores, contributions, counter-evidence, and explanations."""
    print("Computing User TraceONE Risk Scores & Explanations...")
    
    df = user_dev.copy()

    risk_records = []
    contributor_records = []
    hypothesis_records = []
    explanation_objects = []

    for idx, row in df.iterrows():
        uid = str(row['user_id'])
        uname = str(row['username'])
        dept = str(row['department'])

        # Dimension Robust Z-scores
        z_auth = max(0.0, float(row.get('authentication_deviation', 0.0)))
        z_net = max(0.0, float(row.get('network_deviation', 0.0)))
        z_ep = max(0.0, float(row.get('endpoint_deviation', 0.0)))
        z_ops = max(0.0, float(row.get('off_hours_deviation', 0.0)))

        # Bounded Base Dimension Contributions (0 to 25 each)
        s_auth = min(25.0, (z_auth / 4.0) * 25.0)
        s_net = min(25.0, (z_net / 4.0) * 25.0)
        s_ep = min(25.0, (z_ep / 4.0) * 25.0)
        s_ops = min(25.0, (z_ops / 4.0) * 25.0)

        base_risk = s_auth + s_net + s_ep + s_ops

        # Multi-Signal Corroboration Multiplier
        active_signals = sum([1 for z in [z_auth, z_net, z_ep, z_ops] if z >= 2.5])
        multi_multipliers = {0: 1.0, 1: 1.0, 2: 1.25, 3: 1.50, 4: 1.75}
        m_multi = multi_multipliers.get(active_signals, 1.0)

        # Final TraceONE Risk Score
        raw_risk = base_risk * m_multi
        final_risk = round(float(np.clip(raw_risk, 0.0, 100.0)), 2)
        risk_level = get_risk_level(final_risk)

        # Evidence Confidence Score
        obs_count = row['observation_count']
        ts_qual = row['timestamp_quality_score']
        base_conf = row['baseline_confidence']
        conf_score = calculate_evidence_confidence(obs_count, ts_qual, base_conf)
        conf_level = get_confidence_level(conf_score)

        # Dimension Contributor Breakdown
        c_auth = round(s_auth * m_multi, 2)
        c_net = round(s_net * m_multi, 2)
        c_ep = round(s_ep * m_multi, 2)
        c_ops = round(s_ops * m_multi, 2)
        multi_boost = round(base_risk * (m_multi - 1.0), 2)

        # Counter-Evidence Detection
        counter_ev = []
        if ts_qual < 0.5:
            counter_ev.append("LOW_TIMESTAMP_QUALITY")
        if str(row['eligibility_status']) == "INSUFFICIENT_HISTORY":
            counter_ev.append("INSUFFICIENT_BASELINE_HISTORY")
        if final_risk >= 30.0 and active_signals <= 1:
            counter_ev.append("UNCORROBORATED_SINGLE_DIMENSION")
        if pd.isna(row.get('mfa_failure_count')) or row.get('mfa_failure_count') == 0:
            counter_ev.append("ZERO_MFA_FAILURES_OBSERVED")
        
        counter_ev_str = "; ".join(counter_ev) if counter_ev else "NONE_OBSERVED"

        # Security Hypothesis Generation
        hypotheses = []
        if c_auth >= 15.0 and c_net >= 10.0:
            hypotheses.append("POSSIBLE_CREDENTIAL_COMPROMISE")
        if c_auth >= 15.0 and (c_ops >= 10.0 or active_signals >= 3):
            hypotheses.append("POSSIBLE_ACCOUNT_TAKEOVER")
        if c_ep >= 15.0 and (c_net >= 10.0 or row.get('critical_endpoint_alert_count', 0) > 0):
            hypotheses.append("POSSIBLE_SUSPICIOUS_ENDPOINT_ACTIVITY")
        if c_net >= 15.0 and c_ops >= 10.0:
            hypotheses.append("POSSIBLE_ANOMALOUS_DATA_EXFILTRATION")

        hypothesis_str = "; ".join(hypotheses) if hypotheses and final_risk >= 50.0 else "NO_ACTIONABLE_HYPOTHESIS"

        # Source IAM Risk Information Preservation (STRICT SEPARATION)
        source_iam_numeric = row.get('risk_score_numeric', 'Unknown')
        source_iam_flag = row.get('risk_quality_flag', 'UNKNOWN')

        risk_records.append({
            'entity_id': uid,
            'entity_type': 'USER',
            'username': uname,
            'department': dept,
            'traceone_risk_score': final_risk,
            'risk_level': risk_level,
            'risk_confidence_score': conf_score,
            'risk_confidence_level': conf_level,
            'independent_signal_count': active_signals,
            'multi_signal_multiplier': m_multi,
            'source_iam_risk_indicator': source_iam_numeric,
            'source_iam_risk_quality': source_iam_flag,
            'eligibility_status': row['eligibility_status'],
            'counter_evidence': counter_ev_str,
            'primary_hypothesis': hypothesis_str
        })

        contributor_records.append({
            'entity_id': uid,
            'entity_type': 'USER',
            'traceone_risk_score': final_risk,
            'auth_contribution': c_auth,
            'network_contribution': c_net,
            'endpoint_contribution': c_ep,
            'operational_contribution': c_ops,
            'multi_signal_boost': multi_boost
        })

        hypothesis_records.append({
            'entity_id': uid,
            'entity_type': 'USER',
            'hypothesis': hypothesis_str,
            'traceone_risk_score': final_risk,
            'confidence_score': conf_score,
            'supporting_signals': f"Auth:{c_auth}, Net:{c_net}, Ep:{c_ep}, Ops:{c_ops}",
            'counter_evidence': counter_ev_str,
            'limitations': f"Observed events: {obs_count}, TS Quality: {ts_qual}"
        })

        # Machine-Readable "Why Flagged" Explanation Object
        if final_risk >= 50.0:
            explanation_objects.append({
                'entity_id': uid,
                'entity_type': 'USER',
                'overall_risk': final_risk,
                'risk_level': risk_level,
                'confidence': conf_level,
                'confidence_score': conf_score,
                'top_contributors': {
                    'authentication': c_auth,
                    'network': c_net,
                    'endpoint': c_ep,
                    'operational_off_hours': c_ops
                },
                'multi_signal_corroboration': {
                    'active_elevated_signals': active_signals,
                    'multiplier': m_multi
                },
                'observed_values': {
                    'failed_login_count': int(row.get('failed_login_count', 0)),
                    'auth_failure_rate': float(row.get('authentication_failure_rate', 0.0)),
                    'off_hours_activity_count': int(row.get('off_hours_activity_count', 0)),
                    'endpoint_alert_count': int(row.get('endpoint_alert_count', 0))
                },
                'deviations': {
                    'authentication_zscore': round(z_auth, 2),
                    'network_zscore': round(z_net, 2),
                    'endpoint_zscore': round(z_ep, 2),
                    'off_hours_zscore': round(z_ops, 2)
                },
                'peer_comparison': {
                    'department': dept,
                    'peer_failed_login_median': float(row.get('peer_failed_login_median', 0.0)),
                    'department_failed_login_percentile': float(row.get('department_failed_login_percentile', 0.0))
                },
                'counter_evidence': counter_ev,
                'primary_hypothesis': hypothesis_str
            })

    return (pd.DataFrame(risk_records), pd.DataFrame(contributor_records),
            pd.DataFrame(hypothesis_records), explanation_objects)


def build_host_risk_scores(host_dev, events_df):
    """Compute Host risk scores, contributions, counter-evidence, and explanations."""
    print("Computing Host TraceONE Risk Scores & Explanations...")
    
    df = host_dev.copy()

    risk_records = []
    contributor_records = []
    hypothesis_records = []
    explanation_objects = []

    for idx, row in df.iterrows():
        host = str(row['hostname'])

        z_net = max(0.0, float(row.get('network_deviation', 0.0)))
        z_ep = max(0.0, float(row.get('endpoint_deviation', 0.0)))
        z_vol = max(0.0, float(row.get('volume_deviation', 0.0)))

        s_net = min(33.33, (z_net / 4.0) * 33.33)
        s_ep = min(33.33, (z_ep / 4.0) * 33.33)
        s_vol = min(33.34, (z_vol / 4.0) * 33.34)

        base_risk = s_net + s_ep + s_vol

        active_signals = sum([1 for z in [z_net, z_ep, z_vol] if z >= 2.5])
        multi_multipliers = {0: 1.0, 1: 1.0, 2: 1.25, 3: 1.50}
        m_multi = multi_multipliers.get(active_signals, 1.0)

        raw_risk = base_risk * m_multi
        final_risk = round(float(np.clip(raw_risk, 0.0, 100.0)), 2)
        risk_level = get_risk_level(final_risk)

        obs_count = row['observation_count']
        ts_qual = row['timestamp_quality_score']
        base_conf = row['baseline_confidence']
        conf_score = calculate_evidence_confidence(obs_count, ts_qual, base_conf)
        conf_level = get_confidence_level(conf_score)

        c_net = round(s_net * m_multi, 2)
        c_ep = round(s_ep * m_multi, 2)
        c_vol = round(s_vol * m_multi, 2)
        multi_boost = round(base_risk * (m_multi - 1.0), 2)

        counter_ev = []
        if ts_qual < 0.5:
            counter_ev.append("LOW_TIMESTAMP_QUALITY")
        if str(row['eligibility_status']) == "INSUFFICIENT_HISTORY":
            counter_ev.append("INSUFFICIENT_BASELINE_HISTORY")
        if not bool(row.get('is_managed', True)):
            counter_ev.append("UNMANAGED_HOST_CONTEXT")
        if final_risk >= 30.0 and active_signals <= 1:
            counter_ev.append("UNCORROBORATED_SINGLE_DIMENSION")

        counter_ev_str = "; ".join(counter_ev) if counter_ev else "NONE_OBSERVED"

        hypotheses = []
        if c_ep >= 15.0 and (c_net >= 10.0 or row.get('critical_endpoint_alert_count', 0) > 0):
            hypotheses.append("POSSIBLE_SUSPICIOUS_ENDPOINT_ACTIVITY")
        if c_net >= 15.0 and c_vol >= 10.0:
            hypotheses.append("POSSIBLE_ANOMALOUS_NETWORK_TRAFFIC")

        hypothesis_str = "; ".join(hypotheses) if hypotheses and final_risk >= 50.0 else "NO_ACTIONABLE_HYPOTHESIS"

        risk_records.append({
            'entity_id': host,
            'entity_type': 'HOST',
            'username': 'Unknown',
            'department': 'Unknown',
            'traceone_risk_score': final_risk,
            'risk_level': risk_level,
            'risk_confidence_score': conf_score,
            'risk_confidence_level': conf_level,
            'independent_signal_count': active_signals,
            'multi_signal_multiplier': m_multi,
            'source_iam_risk_indicator': 'Not Applicable',
            'source_iam_risk_quality': 'NOT_APPLICABLE',
            'eligibility_status': row['eligibility_status'],
            'counter_evidence': counter_ev_str,
            'primary_hypothesis': hypothesis_str
        })

        contributor_records.append({
            'entity_id': host,
            'entity_type': 'HOST',
            'traceone_risk_score': final_risk,
            'auth_contribution': 0.0,
            'network_contribution': c_net,
            'endpoint_contribution': c_ep,
            'operational_contribution': c_vol,
            'multi_signal_boost': multi_boost
        })

        hypothesis_records.append({
            'entity_id': host,
            'entity_type': 'HOST',
            'hypothesis': hypothesis_str,
            'traceone_risk_score': final_risk,
            'confidence_score': conf_score,
            'supporting_signals': f"Net:{c_net}, Ep:{c_ep}, Vol:{c_vol}",
            'counter_evidence': counter_ev_str,
            'limitations': f"Observed events: {obs_count}, Managed: {row.get('is_managed', True)}"
        })

        if final_risk >= 50.0:
            explanation_objects.append({
                'entity_id': host,
                'entity_type': 'HOST',
                'overall_risk': final_risk,
                'risk_level': risk_level,
                'confidence': conf_level,
                'confidence_score': conf_score,
                'top_contributors': {
                    'network': c_net,
                    'endpoint': c_ep,
                    'volume': c_vol
                },
                'multi_signal_corroboration': {
                    'active_elevated_signals': active_signals,
                    'multiplier': m_multi
                },
                'observed_values': {
                    'firewall_deny_count': int(row.get('firewall_deny_count', 0)),
                    'firewall_deny_ratio': float(row.get('firewall_deny_ratio', 0.0)),
                    'endpoint_alert_count': int(row.get('endpoint_alert_count', 0))
                },
                'counter_evidence': counter_ev,
                'primary_hypothesis': hypothesis_str
            })

    return (pd.DataFrame(risk_records), pd.DataFrame(contributor_records),
            pd.DataFrame(hypothesis_records), explanation_objects)


def build_normalized_evidence_table(events_df, user_risk_df, host_risk_df):
    """Build normalized evidence table linking flagged risk entities directly to source events."""
    print("Building Normalized Evidence Table...")
    
    flagged_users = set(user_risk_df[user_risk_df['traceone_risk_score'] >= 30.0]['entity_id'])
    flagged_hosts = set(host_risk_df[host_risk_df['traceone_risk_score'] >= 30.0]['entity_id'])

    evidence_rows = []
    
    # Filter events matching flagged users or hosts
    matching_events = events_df[(events_df['user_id'].isin(flagged_users)) | (events_df['hostname'].isin(flagged_hosts))]

    for idx, row in matching_events.head(15000).iterrows():
        entity_id = row['user_id'] if row['user_id'] in flagged_users else row['hostname']
        entity_type = 'USER' if row['user_id'] in flagged_users else 'HOST'

        evidence_rows.append({
            'entity_id': entity_id,
            'entity_type': entity_type,
            'event_id': row['event_id'],
            'source_dataset': row['source_dataset'],
            'source_record_id': row['source_record_id'],
            'event_category': row['event_category'],
            'event_timestamp': row['event_timestamp'],
            'severity': row['severity'],
            'action': row['action'],
            'data_quality_status': row['data_quality_status'],
            'resolution_confidence': row['resolution_confidence']
        })

    return pd.DataFrame(evidence_rows)


def run_sensitivity_analysis(user_dev, user_base):
    """Perform sensitivity analysis across parameter variations."""
    print("Performing Sensitivity Analysis on Risk Scoring Methodology...")
    df = pd.merge(user_dev, user_base[['user_id', 'observation_count', 'timestamp_quality_score', 'baseline_confidence']], on='user_id', how='left')

    variations = {
        'Baseline (1.0x)': 1.0,
        'Sensitivity -10% (0.9x)': 0.9,
        'Sensitivity +10% (1.1x)': 1.1
    }

    results = {}
    for name, factor in variations.items():
        scores = []
        for idx, row in df.iterrows():
            z_auth = max(0.0, float(row.get('authentication_deviation', 0.0))) * factor
            z_net = max(0.0, float(row.get('network_deviation', 0.0))) * factor
            z_ep = max(0.0, float(row.get('endpoint_deviation', 0.0))) * factor
            z_ops = max(0.0, float(row.get('off_hours_deviation', 0.0))) * factor

            s_auth = min(25.0, (z_auth / 4.0) * 25.0)
            s_net = min(25.0, (z_net / 4.0) * 25.0)
            s_ep = min(25.0, (z_ep / 4.0) * 25.0)
            s_ops = min(25.0, (z_ops / 4.0) * 25.0)

            base = s_auth + s_net + s_ep + s_ops
            active = sum([1 for z in [z_auth, z_net, z_ep, z_ops] if z >= 2.5])
            m = {0: 1.0, 1: 1.0, 2: 1.25, 3: 1.50, 4: 1.75}.get(active, 1.0)
            score = float(np.clip(base * m, 0.0, 100.0))
            scores.append(score)

        s_series = pd.Series(scores)
        results[name] = {
            'mean': round(float(s_series.mean()), 2),
            'median': round(float(s_series.median()), 2),
            'high_critical_count': int((s_series >= 60.0).sum()),
            'pct_high_critical': round(float((s_series >= 60.0).mean() * 100), 2)
        }

    return results


def main():
    print("=" * 70)
    print("TRACEONE EXPLAINABLE RISK ENGINE (PHASE F)")
    print("=" * 70)

    # Load canonical and Phase E datasets
    events_df = pd.read_csv(PROCESSED_DIR / "canonical_events.csv")
    user_dev = pd.read_csv(PROCESSED_DIR / "user_behavior_deviations.csv")
    user_base = pd.read_csv(PROCESSED_DIR / "user_behavior_baselines.csv")
    host_dev = pd.read_csv(PROCESSED_DIR / "host_behavior_deviations.csv")
    host_base = pd.read_csv(PROCESSED_DIR / "host_behavior_baselines.csv")

    # Also load user_security_features to get risk_score_numeric and risk_quality_flag
    user_feats = pd.read_csv(PROCESSED_DIR / "user_security_features.csv")
    if 'risk_score_numeric' in user_feats.columns:
        user_dev = pd.merge(user_dev, user_feats[['user_id', 'risk_score_numeric', 'risk_quality_flag']], on='user_id', how='left')

    # Step 6 - 12: Build User Risk & Host Risk
    u_risk, u_contrib, u_hypo, u_explanations = build_user_risk_scores(user_dev, events_df)
    h_risk, h_contrib, h_hypo, h_explanations = build_host_risk_scores(host_dev, events_df)

    # Combine Risk Scores
    combined_risk = pd.concat([u_risk, h_risk], ignore_index=True)
    combined_contrib = pd.concat([u_contrib, h_contrib], ignore_index=True)
    combined_hypo = pd.concat([u_hypo, h_hypo], ignore_index=True)

    # Step 14: Normalized Evidence Table
    evidence_table = build_normalized_evidence_table(events_df, u_risk, h_risk)

    # Step 17: Sensitivity Analysis
    sensitivity_results = run_sensitivity_analysis(user_dev, user_base)

    # Save Output CSV Tables
    u_risk.to_csv(PROCESSED_DIR / "user_risk_scores.csv", index=False)
    h_risk.to_csv(PROCESSED_DIR / "host_risk_scores.csv", index=False)
    combined_risk.to_csv(PROCESSED_DIR / "traceone_risk_scores.csv", index=False)
    combined_contrib.to_csv(PROCESSED_DIR / "risk_contributors.csv", index=False)
    combined_hypo.to_csv(PROCESSED_DIR / "security_hypotheses.csv", index=False)
    evidence_table.to_csv(PROCESSED_DIR / "normalized_evidence_table.csv", index=False)

    # Save Machine-Readable "Why Flagged" JSON Explanations
    all_explanations = u_explanations + h_explanations
    with open(PROCESSED_DIR / "why_flagged_explanations.json", "w") as f:
        json.dump(all_explanations, f, indent=2)

    # Save Sensitivity Analysis JSON
    with open(PROCESSED_DIR / "sensitivity_analysis_results.json", "w") as f:
        json.dump(sensitivity_results, f, indent=2)

    print("\nSaved output files to data/processed/:")
    print(" - user_risk_scores.csv")
    print(" - host_risk_scores.csv")
    print(" - traceone_risk_scores.csv")
    print(" - risk_contributors.csv")
    print(" - security_hypotheses.csv")
    print(" - normalized_evidence_table.csv")
    print(" - why_flagged_explanations.json")
    print(" - sensitivity_analysis_results.json")
    print("=" * 70)
    print("PHASE F RISK ENGINE EXECUTION COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
