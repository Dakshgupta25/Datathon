"""
TraceONE Canonical Security Event & Entity Model Generator
Phase C: Canonical Model & Analytical Integration

Transforms cleaned datasets (Identity, IAM, Endpoint, Firewall) into:
- canonical_events (58,000 unified security events with 100% provenance)
- canonical_users (3,000 employee entity profiles)
- canonical_hosts (Unique host entity profiles)
- canonical_sessions (Session mapping with match confidence)
- canonical_relationships (Evidence-based relational edges)
"""

from pathlib import Path
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CLEANED_DIR = PROJECT_ROOT / "data" / "cleaned"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def build_canonical_events():
    print("[1/5] Building Canonical Security Events...")
    
    iam_df = pd.read_csv(CLEANED_DIR / "iam_cleaned.csv", low_memory=False)
    ep_df = pd.read_csv(CLEANED_DIR / "endpoint_cleaned.csv", low_memory=False)
    fw_df = pd.read_csv(CLEANED_DIR / "firewall_cleaned.csv", low_memory=False)
    id_df = pd.read_csv(CLEANED_DIR / "identity_cleaned.csv", low_memory=False)

    valid_user_ids = set(id_df['user_id'].dropna().unique())
    valid_hostnames = set(id_df['hostname'].dropna().unique())

    # --- IAM Events ---
    iam_events = pd.DataFrame({
        'event_id': iam_df['event_id'],
        'event_timestamp': iam_df['timestamp'],
        'event_type': iam_df['event_type'],
        'event_category': 'AUTHENTICATION',
        'user_id': iam_df['user_id'],
        'hostname': iam_df['hostname'],
        'device_id': iam_df['device_id'],
        'session_id': iam_df['session_id'],
        'source_ip': iam_df['source_ip'],
        'destination_ip': 'Unknown',
        'department': iam_df['department'],
        'severity': iam_df['risk_label'].replace({'Missing': 'Info', 'Invalid': 'Info'}),
        'action': iam_df['event_type'].str.upper(),
        'source_dataset': 'IAM',
        'source_record_id': iam_df['event_id'],
        'data_quality_status': iam_df['data_quality_status'],
        'resolution_confidence': np.where(iam_df['user_id'].isin(valid_user_ids), 'EXACT', 'UNMATCHED')
    })

    # --- Endpoint Events ---
    ep_events = pd.DataFrame({
        'event_id': ep_df['alert_id'],
        'event_timestamp': ep_df['detected_timestamp'],
        'event_type': ep_df['alert_name'],
        'event_category': 'ENDPOINT_ALERT',
        'user_id': ep_df['user_id'],
        'hostname': ep_df['hostname'],
        'device_id': 'Unknown',
        'session_id': 'Unknown',
        'source_ip': 'Unknown',
        'destination_ip': 'Unknown',
        'department': 'Unknown',
        'severity': ep_df['severity'],
        'action': 'ALERT_TRIGGERED',
        'source_dataset': 'Endpoint',
        'source_record_id': ep_df['alert_id'],
        'data_quality_status': np.where(ep_df['resolved_timestamp'] == 'Unknown', 'UNKNOWN', 'VALID'),
        'resolution_confidence': np.where(ep_df['user_id'].isin(valid_user_ids) & ep_df['hostname'].isin(valid_hostnames), 'EXACT', 'PROBABLE')
    })

    # --- Firewall Events ---
    fw_events = pd.DataFrame({
        'event_id': fw_df['log_id'],
        'event_timestamp': fw_df['timestamp'],
        'event_type': fw_df['protocol'].astype(str) + "_" + fw_df['action'].astype(str),
        'event_category': 'NETWORK_FLOW',
        'user_id': 'Unknown',
        'hostname': fw_df['hostname'],
        'device_id': 'Unknown',
        'session_id': fw_df['session_id'],
        'source_ip': fw_df['src_ip'],
        'destination_ip': fw_df['dst_ip'],
        'department': 'Unknown',
        'severity': np.where(fw_df['threat_flag'] == True, 'High', 'Low'),
        'action': fw_df['action'],
        'source_dataset': 'Firewall',
        'source_record_id': fw_df['log_id'],
        'data_quality_status': np.where(fw_df['timestamp'] == 'Unknown', 'UNKNOWN', 'VALID'),
        'resolution_confidence': np.where(fw_df['hostname'].isin(valid_hostnames), 'PROBABLE', 'UNMATCHED')
    })

    canonical_events = pd.concat([iam_events, ep_events, fw_events], ignore_index=True)
    
    # Export
    canonical_events.to_csv(PROCESSED_DIR / "canonical_events.csv", index=False)
    try:
        canonical_events.to_parquet(PROCESSED_DIR / "canonical_events.parquet", index=False)
    except Exception:
        pass

    print(f"Canonical Events generated: {len(canonical_events):,} rows (IAM: {len(iam_events)}, Endpoint: {len(ep_events)}, Firewall: {len(fw_events)})")
    return canonical_events


def build_canonical_users():
    print("[2/5] Building Canonical User Entities...")
    id_df = pd.read_csv(CLEANED_DIR / "identity_cleaned.csv", low_memory=False)
    iam_df = pd.read_csv(CLEANED_DIR / "iam_cleaned.csv", low_memory=False)
    ep_df = pd.read_csv(CLEANED_DIR / "endpoint_cleaned.csv", low_memory=False)

    iam_user = iam_df.groupby('user_id').agg(
        total_iam_events=('event_id', 'count'),
        failed_logins=('event_type', lambda x: (x == 'login_failed').sum()),
        avg_risk_score=('risk_score', 'mean')
    ).reset_index()

    ep_user = ep_df.groupby('user_id').agg(
        total_endpoint_alerts=('alert_id', 'count'),
        critical_alerts=('severity', lambda x: (x == 'Critical').sum()),
        high_alerts=('severity', lambda x: (x == 'High').sum())
    ).reset_index()

    user_master = pd.merge(id_df, iam_user, on='user_id', how='left').fillna(0)
    user_master = pd.merge(user_master, ep_user, on='user_id', how='left').fillna(0)

    # Insider Threat Composite Formula
    user_master['insider_threat_score'] = (
        (user_master['failed_logins'] * 2.0) +
        (user_master['critical_alerts'] * 5.0) +
        (user_master['high_alerts'] * 3.0) +
        (user_master['avg_risk_score'] * 0.5)
    )

    user_master.to_csv(PROCESSED_DIR / "canonical_users.csv", index=False)
    try:
        user_master.to_parquet(PROCESSED_DIR / "canonical_users.parquet", index=False)
    except Exception:
        pass

    print(f"Canonical Users generated: {len(user_master):,} rows")
    return user_master


def build_canonical_hosts():
    print("[3/5] Building Canonical Host Entities...")
    id_df = pd.read_csv(CLEANED_DIR / "identity_cleaned.csv", low_memory=False)
    fw_df = pd.read_csv(CLEANED_DIR / "firewall_cleaned.csv", low_memory=False)
    ep_df = pd.read_csv(CLEANED_DIR / "endpoint_cleaned.csv", low_memory=False)

    managed_hosts = set(id_df['hostname'].dropna().unique())

    all_hosts = set(id_df['hostname']).union(set(fw_df['hostname'])).union(set(ep_df['hostname']))
    all_hosts.discard('Unknown')

    fw_host = fw_df.groupby('hostname').agg(
        total_firewall_logs=('log_id', 'count'),
        firewall_denies=('action', lambda x: (x == 'DENY').sum()),
        threat_flags=('threat_flag', lambda x: (x == True).sum())
    ).reset_index()

    ep_host = ep_df.groupby('hostname').agg(
        endpoint_alerts=('alert_id', 'count')
    ).reset_index()

    host_df = pd.DataFrame({'hostname': list(all_hosts)})
    host_df = pd.merge(host_df, fw_host, on='hostname', how='left').fillna(0)
    host_df = pd.merge(host_df, ep_host, on='hostname', how='left').fillna(0)
    host_df['is_managed'] = host_df['hostname'].isin(managed_hosts)

    host_df.to_csv(PROCESSED_DIR / "canonical_hosts.csv", index=False)
    try:
        host_df.to_parquet(PROCESSED_DIR / "canonical_hosts.parquet", index=False)
    except Exception:
        pass

    print(f"Canonical Hosts generated: {len(host_df):,} rows")
    return host_df


def build_canonical_sessions():
    print("[4/5] Building Canonical Session Entities...")
    iam_df = pd.read_csv(CLEANED_DIR / "iam_cleaned.csv", low_memory=False)
    fw_df = pd.read_csv(CLEANED_DIR / "firewall_cleaned.csv", low_memory=False)

    iam_sessions = set(iam_df[iam_df['session_id'] != 'Unknown']['session_id'].unique())
    fw_sessions = set(fw_df[fw_df['session_id'] != 'Unknown']['session_id'].unique())

    all_sessions = iam_sessions.union(fw_sessions)

    session_rows = []
    for s in all_sessions:
        in_iam = s in iam_sessions
        in_fw = s in fw_sessions
        match_status = "EXACT" if (in_iam and in_fw) else "UNMATCHED"
        session_rows.append({
            'session_id': s,
            'present_in_iam': in_iam,
            'present_in_firewall': in_fw,
            'match_status': match_status
        })

    session_df = pd.DataFrame(session_rows)
    session_df.to_csv(PROCESSED_DIR / "canonical_sessions.csv", index=False)
    try:
        session_df.to_parquet(PROCESSED_DIR / "canonical_sessions.parquet", index=False)
    except Exception:
        pass

    print(f"Canonical Sessions generated: {len(session_df):,} rows (Exact Matched: {(session_df['match_status'] == 'EXACT').sum()})")
    return session_df


def build_canonical_relationships():
    print("[5/5] Building Canonical Relational Graph Edges...")
    id_df = pd.read_csv(CLEANED_DIR / "identity_cleaned.csv", low_memory=False)
    ep_df = pd.read_csv(CLEANED_DIR / "endpoint_cleaned.csv", low_memory=False)
    fw_df = pd.read_csv(CLEANED_DIR / "firewall_cleaned.csv", low_memory=False)

    edges = []

    # 1. User -> Host (Identity Master)
    for _, row in id_df.iterrows():
        if row['user_id'] != 'Unknown' and row['hostname'] != 'Unknown':
            edges.append({
                'source_node': row['user_id'],
                'source_type': 'USER',
                'relationship': 'OWN_DEVICE',
                'target_node': row['hostname'],
                'target_type': 'HOST',
                'confidence': 'EXACT',
                'provenance': 'Identity_Master'
            })

    # 2. User -> Alert (Endpoint Alerts)
    for _, row in ep_df.iterrows():
        if row['user_id'] != 'Unknown':
            edges.append({
                'source_node': row['user_id'],
                'source_type': 'USER',
                'relationship': 'TRIGGERED_ALERT',
                'target_node': row['alert_id'],
                'target_type': 'ALERT',
                'confidence': 'EXACT',
                'provenance': 'Endpoint_Alerts'
            })

    # 3. Host -> Destination IP (Firewall)
    for _, row in fw_df.iterrows():
        if row['hostname'] != 'Unknown' and row['dst_ip'] != 'Unknown':
            edges.append({
                'source_node': row['hostname'],
                'source_type': 'HOST',
                'relationship': 'COMMUNICATED_WITH',
                'target_node': row['dst_ip'],
                'target_type': 'IP',
                'confidence': 'PROBABLE',
                'provenance': 'Firewall_Logs'
            })

    rel_df = pd.DataFrame(edges)
    rel_df.to_csv(PROCESSED_DIR / "canonical_relationships.csv", index=False)
    try:
        rel_df.to_parquet(PROCESSED_DIR / "canonical_relationships.parquet", index=False)
    except Exception:
        pass

    print(f"Canonical Relationships generated: {len(rel_df):,} edges")
    return rel_df


def main():
    print("=" * 70)
    print("TRACEONE CANONICAL SECURITY MODEL PIPELINE")
    print("=" * 70)
    build_canonical_events()
    build_canonical_users()
    build_canonical_hosts()
    build_canonical_sessions()
    build_canonical_relationships()
    print("\n" + "=" * 70)
    print("CANONICAL MODEL GENERATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
