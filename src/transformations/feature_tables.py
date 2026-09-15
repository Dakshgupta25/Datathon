"""
TraceONE Security Feature Layer Generator
Phase D: Observable Security Feature Engineering

Generates:
- user_security_features.csv / .parquet (3,000 rows)
- host_security_features.csv / .parquet (8,413 rows)
- session_security_features.csv / .parquet (36,433 rows)
- event_security_features.csv / .parquet (58,000 rows)
"""

from pathlib import Path
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CLEANED_DIR = PROJECT_ROOT / "data" / "cleaned"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def build_user_features():
    print("[1/4] Building User Security Features...")
    id_df = pd.read_csv(CLEANED_DIR / "identity_cleaned.csv", low_memory=False)
    iam_df = pd.read_csv(CLEANED_DIR / "iam_cleaned.csv", low_memory=False)
    ep_df = pd.read_csv(CLEANED_DIR / "endpoint_cleaned.csv", low_memory=False)
    fw_df = pd.read_csv(CLEANED_DIR / "firewall_cleaned.csv", low_memory=False)

    # IAM user aggregations
    iam_agg = iam_df.groupby('user_id').agg(
        authentication_event_count=('event_id', 'count'),
        failed_login_count=('event_type', lambda x: (x == 'login_failed').sum()),
        successful_login_count=('event_type', lambda x: (x == 'login_success').sum()),
        mfa_failure_count=('mfa_passed', lambda x: (x == 'False').sum()),
        unique_source_ip_count=('source_ip', lambda x: len(set(x) - {'Unknown'})),
        session_count=('session_id', lambda x: len(set(x) - {'Unknown'})),
        unknown_evidence_count=('data_quality_status', lambda x: (x == 'UNKNOWN').sum())
    ).reset_index()

    # Off-hours IAM activity
    iam_valid_ts = iam_df[iam_df['timestamp'] != 'Unknown'].copy()
    iam_valid_ts['dt'] = pd.to_datetime(iam_valid_ts['timestamp'], errors='coerce')
    iam_valid_ts['is_off_hours'] = (iam_valid_ts['dt'].dt.hour >= 18) | (iam_valid_ts['dt'].dt.hour < 6)
    off_hours = iam_valid_ts.groupby('user_id')['is_off_hours'].sum().reset_index().rename(columns={'is_off_hours': 'off_hours_activity_count'})

    # EDR user aggregations
    ep_agg = ep_df.groupby('user_id').agg(
        endpoint_alert_count=('alert_id', 'count'),
        critical_endpoint_alert_count=('severity', lambda x: (x == 'Critical').sum()),
        high_endpoint_alert_count=('severity', lambda x: (x == 'High').sum()),
        medium_endpoint_alert_count=('severity', lambda x: (x == 'Medium').sum()),
        low_endpoint_alert_count=('severity', lambda x: (x == 'Low').sum()),
        unique_host_count=('hostname', lambda x: len(set(x) - {'Unknown'}))
    ).reset_index()

    # Merge into User Master
    user_feats = pd.merge(id_df[['user_id', 'username', 'department', 'status', 'hostname']], iam_agg, on='user_id', how='left').fillna(0)
    user_feats = pd.merge(user_feats, off_hours, on='user_id', how='left').fillna(0)
    user_feats = pd.merge(user_feats, ep_agg, on='user_id', how='left').fillna(0)

    # Ratios (Divide-by-zero safe)
    user_feats['authentication_failure_rate'] = np.where(
        user_feats['authentication_event_count'] > 0,
        user_feats['failed_login_count'] / user_feats['authentication_event_count'],
        0.0
    )

    user_feats['mfa_failure_rate'] = np.where(
        user_feats['failed_login_count'] > 0,
        user_feats['mfa_failure_count'] / user_feats['failed_login_count'],
        0.0
    )

    # Evidence Counts & Quality Flags
    user_feats['evidence_count'] = user_feats['authentication_event_count'] + user_feats['endpoint_alert_count']
    user_feats['valid_evidence_count'] = user_feats['evidence_count'] - user_feats['unknown_evidence_count']
    user_feats['feature_confidence'] = np.where(user_feats['evidence_count'] > 0, 'EXACT', 'UNMATCHED')

    # Department Percentiles
    user_feats['department_failed_login_percentile'] = user_feats.groupby('department')['failed_login_count'].rank(pct=True) * 100.0

    # Save
    user_feats.to_csv(PROCESSED_DIR / "user_security_features.csv", index=False)
    try:
        user_feats.to_parquet(PROCESSED_DIR / "user_security_features.parquet", index=False)
    except Exception:
        pass

    print(f"User Security Features generated: {len(user_feats):,} rows")
    return user_feats


def build_host_features():
    print("[2/4] Building Host Security Features...")
    id_df = pd.read_csv(CLEANED_DIR / "identity_cleaned.csv", low_memory=False)
    fw_df = pd.read_csv(CLEANED_DIR / "firewall_cleaned.csv", low_memory=False)
    ep_df = pd.read_csv(CLEANED_DIR / "endpoint_cleaned.csv", low_memory=False)

    managed_hosts = set(id_df['hostname'].dropna().unique())

    all_hosts = set(id_df['hostname']).union(set(fw_df['hostname'])).union(set(ep_df['hostname']))
    all_hosts.discard('Unknown')

    fw_host = fw_df.groupby('hostname').agg(
        firewall_event_count=('log_id', 'count'),
        firewall_deny_count=('action', lambda x: (x == 'DENY').sum()),
        threat_flag_count=('threat_flag', lambda x: (x == True).sum()),
        unique_source_ip_count=('src_ip', lambda x: len(set(x) - {'Unknown'})),
        unique_destination_ip_count=('dst_ip', lambda x: len(set(x) - {'Unknown'})),
        bytes_sent=('bytes_sent', 'sum'),
        bytes_received=('bytes_received', 'sum'),
        session_count=('session_id', lambda x: len(set(x) - {'Unknown'}))
    ).reset_index()

    ep_host = ep_df.groupby('hostname').agg(
        endpoint_alert_count=('alert_id', 'count'),
        critical_endpoint_alert_count=('severity', lambda x: (x == 'Critical').sum())
    ).reset_index()

    host_feats = pd.DataFrame({'hostname': list(all_hosts)})
    host_feats = pd.merge(host_feats, fw_host, on='hostname', how='left').fillna(0)
    host_feats = pd.merge(host_feats, ep_host, on='hostname', how='left').fillna(0)

    host_feats['is_managed'] = host_feats['hostname'].isin(managed_hosts)

    host_feats['firewall_deny_ratio'] = np.where(
        host_feats['firewall_event_count'] > 0,
        host_feats['firewall_deny_count'] / host_feats['firewall_event_count'],
        0.0
    )

    host_feats['evidence_count'] = host_feats['firewall_event_count'] + host_feats['endpoint_alert_count']
    host_feats['feature_confidence'] = np.where(host_feats['is_managed'], 'EXACT', 'PROBABLE')

    host_feats.to_csv(PROCESSED_DIR / "host_security_features.csv", index=False)
    try:
        host_feats.to_parquet(PROCESSED_DIR / "host_security_features.parquet", index=False)
    except Exception:
        pass

    print(f"Host Security Features generated: {len(host_feats):,} rows")
    return host_feats


def build_session_features():
    print("[3/4] Building Session Security Features...")
    iam_df = pd.read_csv(CLEANED_DIR / "iam_cleaned.csv", low_memory=False)
    fw_df = pd.read_csv(CLEANED_DIR / "firewall_cleaned.csv", low_memory=False)

    iam_sess = iam_df[iam_df['session_id'] != 'Unknown'].groupby('session_id').agg(
        iam_event_count=('event_id', 'count'),
        has_failed_login=('event_type', lambda x: (x == 'login_failed').any())
    ).reset_index()

    fw_sess = fw_df[fw_df['session_id'] != 'Unknown'].groupby('session_id').agg(
        firewall_log_count=('log_id', 'count'),
        has_firewall_deny=('action', lambda x: (x == 'DENY').any()),
        has_threat_flag=('threat_flag', lambda x: (x == True).any())
    ).reset_index()

    sess_feats = pd.merge(iam_sess, fw_sess, on='session_id', how='outer').fillna({'iam_event_count': 0, 'firewall_log_count': 0, 'has_failed_login': False, 'has_firewall_deny': False, 'has_threat_flag': False})

    sess_feats['present_in_iam'] = sess_feats['iam_event_count'] > 0
    sess_feats['present_in_firewall'] = sess_feats['firewall_log_count'] > 0
    sess_feats['match_status'] = np.where(sess_feats['present_in_iam'] & sess_feats['present_in_firewall'], 'EXACT', 'UNMATCHED')
    sess_feats['session_event_count'] = sess_feats['iam_event_count'] + sess_feats['firewall_log_count']
    sess_feats['feature_confidence'] = sess_feats['match_status']

    sess_feats.to_csv(PROCESSED_DIR / "session_security_features.csv", index=False)
    try:
        sess_feats.to_parquet(PROCESSED_DIR / "session_security_features.parquet", index=False)
    except Exception:
        pass

    print(f"Session Security Features generated: {len(sess_feats):,} rows")
    return sess_feats


def build_event_features():
    print("[4/4] Building Event Security Features...")
    events = pd.read_csv(PROCESSED_DIR / "canonical_events.csv", low_memory=False)
    ep_df = pd.read_csv(CLEANED_DIR / "endpoint_cleaned.csv", low_memory=False)

    # Chronology issues lookup
    chron_issues = set(ep_df[ep_df['chronology_issue'] == True]['alert_id']) if 'chronology_issue' in ep_df.columns else set()

    event_feats = events[['event_id', 'source_dataset', 'source_record_id', 'event_category', 'event_type', 'severity', 'action', 'user_id', 'hostname', 'session_id', 'data_quality_status']].copy()

    # Off-hours calculation
    valid_ts = events[events['event_timestamp'] != 'Unknown'].copy()
    valid_ts['dt'] = pd.to_datetime(valid_ts['event_timestamp'], errors='coerce')
    valid_ts['is_off_hours'] = (valid_ts['dt'].dt.hour >= 18) | (valid_ts['dt'].dt.hour < 6)

    event_feats['is_off_hours'] = False
    event_feats.loc[valid_ts[valid_ts['is_off_hours'] == True].index, 'is_off_hours'] = True

    event_feats['is_chronology_anomaly'] = event_feats['event_id'].isin(chron_issues)
    event_feats['feature_confidence'] = np.where(event_feats['data_quality_status'] == 'VALID', 'EXACT', 'PROBABLE')

    event_feats.to_csv(PROCESSED_DIR / "event_security_features.csv", index=False)
    try:
        event_feats.to_parquet(PROCESSED_DIR / "event_security_features.parquet", index=False)
    except Exception:
        pass

    print(f"Event Security Features generated: {len(event_feats):,} rows")
    return event_feats


def main():
    print("=" * 70)
    print("TRACEONE SECURITY FEATURE GENERATION")
    print("=" * 70)
    build_user_features()
    build_host_features()
    build_session_features()
    build_event_features()
    print("\n" + "=" * 70)
    print("FEATURE GENERATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
