"""
TraceONE Behavioral Baselines & Self/Peer Deviation Engine
Phase E: Behavioral Baselines + Deviation Engine

Establishes entity-level and peer-group behavioral baselines (Median & MAD),
computes self-deviations, peer comparisons, multi-metric deviation signals,
and quality-aware confidence metadata without making prematurely biased threat conclusions.
"""

from pathlib import Path
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def calculate_mad(series):
    """Calculate Median Absolute Deviation (MAD) robustly."""
    median = series.median()
    return (series - median).abs().median()


def calculate_robust_zscore(val, median, mad):
    """
    Calculate Robust Z-score: (val - median) / (1.4826 * MAD + 1e-6)
    Handles zero MAD safely.
    """
    if pd.isna(val) or pd.isna(median):
        return 0.0
    scale = 1.4826 * mad
    if scale < 1e-6:
        # Zero dispersion fallback
        diff = val - median
        if diff == 0:
            return 0.0
        return float(np.clip(diff / 1.0, -10.0, 10.0))
    z = (val - median) / scale
    return float(np.clip(z, -20.0, 20.0))


def get_deviation_status(zscore):
    """Categorize deviation severity into neutral behavioral states."""
    if zscore < 1.5:
        return "NORMAL"
    elif zscore < 2.5:
        return "UNUSUAL"
    elif zscore < 4.0:
        return "ELEVATED"
    else:
        return "OUTLIER"


def build_user_baselines(events_df, users_df):
    """Compute eligibility, quality stats, and per-user/peer baselines."""
    print("Computing User Eligibility & Baseline Quality Metrics...")
    
    # Parse event timestamps
    events_df['valid_ts'] = pd.to_datetime(events_df['event_timestamp'].replace('Unknown', None), errors='coerce')
    events_df['date'] = events_df['valid_ts'].dt.date
    events_df['hour'] = events_df['valid_ts'].dt.hour
    
    # Aggregate event observations per user
    user_obs = events_df.groupby('user_id').agg(
        observation_count=('event_id', 'count'),
        valid_timestamp_count=('valid_ts', 'count'),
        distinct_active_days=('date', 'nunique'),
        distinct_active_hours=('hour', 'nunique'),
        min_ts=('valid_ts', 'min'),
        max_ts=('valid_ts', 'max')
    ).reset_index()
    
    user_obs['unknown_timestamp_count'] = user_obs['observation_count'] - user_obs['valid_timestamp_count']
    user_obs['historical_span_days'] = ((user_obs['max_ts'] - user_obs['min_ts']).dt.total_seconds() / 86400.0).fillna(0.0).round(2)
    user_obs['timestamp_quality_score'] = np.where(
        user_obs['observation_count'] > 0,
        user_obs['valid_timestamp_count'] / user_obs['observation_count'],
        0.0
    ).round(4)

    # Merge observation metrics with user security features
    user_base = pd.merge(users_df, user_obs, on='user_id', how='left')
    user_base['observation_count'] = user_base['observation_count'].fillna(0).astype(int)
    user_base['valid_timestamp_count'] = user_base['valid_timestamp_count'].fillna(0).astype(int)
    user_base['unknown_timestamp_count'] = user_base['unknown_timestamp_count'].fillna(0).astype(int)
    user_base['distinct_active_days'] = user_base['distinct_active_days'].fillna(0).astype(int)
    user_base['distinct_active_hours'] = user_base['distinct_active_hours'].fillna(0).astype(int)
    user_base['historical_span_days'] = user_base['historical_span_days'].fillna(0.0)
    user_base['timestamp_quality_score'] = user_base['timestamp_quality_score'].fillna(0.0)

    # Define eligibility status
    def user_eligibility(row):
        if row['observation_count'] < 5 or row['distinct_active_days'] < 2:
            return "INSUFFICIENT_HISTORY"
        elif row['timestamp_quality_score'] < 0.5:
            return "INSUFFICIENT_TIMESTAMP_QUALITY"
        else:
            return "SUFFICIENT_HISTORY"

    user_base['eligibility_status'] = user_base.apply(user_eligibility, axis=1)

    # Define baseline confidence level
    def user_confidence(row):
        if row['eligibility_status'] == "INSUFFICIENT_HISTORY":
            return "UNTRUSTED"
        elif row['eligibility_status'] == "INSUFFICIENT_TIMESTAMP_QUALITY":
            return "LOW"
        elif row['observation_count'] >= 10 and row['timestamp_quality_score'] >= 0.8:
            return "HIGH"
        else:
            return "MEDIUM"

    user_base['baseline_confidence'] = user_base.apply(user_confidence, axis=1)

    # Baseline metadata flags
    user_base['baseline_method'] = "median_mad"
    user_base['baseline_window'] = "full_historical_observation"

    # Compute department peer baselines
    print("Computing Department Peer Baselines...")
    dept_stats = user_base.groupby('department').agg(
        peer_group_size=('user_id', 'count'),
        peer_failed_login_median=('failed_login_count', 'median'),
        peer_failed_login_mad=('failed_login_count', lambda s: calculate_mad(s)),
        peer_auth_failure_rate_median=('authentication_failure_rate', 'median'),
        peer_auth_failure_rate_mad=('authentication_failure_rate', lambda s: calculate_mad(s)),
        peer_off_hours_median=('off_hours_activity_count', 'median'),
        peer_off_hours_mad=('off_hours_activity_count', lambda s: calculate_mad(s)),
        peer_endpoint_alert_median=('endpoint_alert_count', 'median'),
        peer_endpoint_alert_mad=('endpoint_alert_count', lambda s: calculate_mad(s)),
    ).reset_index()

    user_base = pd.merge(user_base, dept_stats, on='department', how='left')

    return user_base


def build_host_baselines(events_df, hosts_df):
    """Compute eligibility, quality stats, and host/population baselines."""
    print("Computing Host Eligibility & Baseline Quality Metrics...")
    
    events_df['valid_ts'] = pd.to_datetime(events_df['event_timestamp'].replace('Unknown', None), errors='coerce')
    events_df['date'] = events_df['valid_ts'].dt.date
    events_df['hour'] = events_df['valid_ts'].dt.hour

    host_obs = events_df.groupby('hostname').agg(
        observation_count=('event_id', 'count'),
        valid_timestamp_count=('valid_ts', 'count'),
        distinct_active_days=('date', 'nunique'),
        distinct_active_hours=('hour', 'nunique'),
        min_ts=('valid_ts', 'min'),
        max_ts=('valid_ts', 'max')
    ).reset_index()

    host_obs['unknown_timestamp_count'] = host_obs['observation_count'] - host_obs['valid_timestamp_count']
    host_obs['historical_span_days'] = ((host_obs['max_ts'] - host_obs['min_ts']).dt.total_seconds() / 86400.0).fillna(0.0).round(2)
    host_obs['timestamp_quality_score'] = np.where(
        host_obs['observation_count'] > 0,
        host_obs['valid_timestamp_count'] / host_obs['observation_count'],
        0.0
    ).round(4)

    host_base = pd.merge(hosts_df, host_obs, on='hostname', how='left')
    host_base['observation_count'] = host_base['observation_count'].fillna(0).astype(int)
    host_base['valid_timestamp_count'] = host_base['valid_timestamp_count'].fillna(0).astype(int)
    host_base['unknown_timestamp_count'] = host_base['unknown_timestamp_count'].fillna(0).astype(int)
    host_base['distinct_active_days'] = host_base['distinct_active_days'].fillna(0).astype(int)
    host_base['distinct_active_hours'] = host_base['distinct_active_hours'].fillna(0).astype(int)
    host_base['historical_span_days'] = host_base['historical_span_days'].fillna(0.0)
    host_base['timestamp_quality_score'] = host_base['timestamp_quality_score'].fillna(0.0)

    def host_eligibility(row):
        if row['observation_count'] < 5 or row['distinct_active_days'] < 2:
            return "INSUFFICIENT_HISTORY"
        elif row['timestamp_quality_score'] < 0.5:
            return "INSUFFICIENT_TIMESTAMP_QUALITY"
        else:
            return "SUFFICIENT_HISTORY"

    host_base['eligibility_status'] = host_base.apply(host_eligibility, axis=1)

    def host_confidence(row):
        if row['eligibility_status'] == "INSUFFICIENT_HISTORY":
            return "UNTRUSTED"
        elif row['eligibility_status'] == "INSUFFICIENT_TIMESTAMP_QUALITY":
            return "LOW"
        elif row['observation_count'] >= 10 and row['timestamp_quality_score'] >= 0.8:
            return "HIGH"
        else:
            return "MEDIUM"

    host_base['baseline_confidence'] = host_base.apply(host_confidence, axis=1)

    host_base['baseline_method'] = "median_mad"
    host_base['baseline_window'] = "full_historical_observation"

    # Population baselines for hosts
    host_base['population_deny_ratio_median'] = host_base['firewall_deny_ratio'].median()
    host_base['population_deny_ratio_mad'] = calculate_mad(host_base['firewall_deny_ratio'])
    host_base['population_endpoint_alert_median'] = host_base['endpoint_alert_count'].median()
    host_base['population_endpoint_alert_mad'] = calculate_mad(host_base['endpoint_alert_count'])

    return host_base


def build_user_deviations(user_base):
    """Calculate user self-deviations, peer deviations, robust Z-scores, and multi-signal count."""
    print("Computing User Behavioral Deviations & Multi-Signal Signals...")
    dev = user_base.copy()

    # Feature 1: Failed Login Count
    dev['failed_login_abs_dev'] = (dev['failed_login_count'] - dev['peer_failed_login_median']).clip(lower=0.0)
    dev['failed_login_rel_dev'] = (dev['failed_login_abs_dev'] / (dev['peer_failed_login_median'] + 1.0)).round(4)
    dev['failed_login_zscore'] = dev.apply(
        lambda r: calculate_robust_zscore(r['failed_login_count'], r['peer_failed_login_median'], r['peer_failed_login_mad']), axis=1
    ).round(4)

    # Feature 2: Auth Failure Rate
    dev['auth_failure_rate_abs_dev'] = (dev['authentication_failure_rate'] - dev['peer_auth_failure_rate_median']).clip(lower=0.0)
    dev['auth_failure_rate_rel_dev'] = (dev['auth_failure_rate_abs_dev'] / (dev['peer_auth_failure_rate_median'] + 1.0)).round(4)
    dev['auth_failure_rate_zscore'] = dev.apply(
        lambda r: calculate_robust_zscore(r['authentication_failure_rate'], r['peer_auth_failure_rate_median'], r['peer_auth_failure_rate_mad']), axis=1
    ).round(4)

    # Feature 3: Off Hours Activity Count
    dev['off_hours_abs_dev'] = (dev['off_hours_activity_count'] - dev['peer_off_hours_median']).clip(lower=0.0)
    dev['off_hours_rel_dev'] = (dev['off_hours_abs_dev'] / (dev['peer_off_hours_median'] + 1.0)).round(4)
    dev['off_hours_zscore'] = dev.apply(
        lambda r: calculate_robust_zscore(r['off_hours_activity_count'], r['peer_off_hours_median'], r['peer_off_hours_mad']), axis=1
    ).round(4)

    # Feature 4: Endpoint Alert Count
    dev['endpoint_alert_abs_dev'] = (dev['endpoint_alert_count'] - dev['peer_endpoint_alert_median']).clip(lower=0.0)
    dev['endpoint_alert_rel_dev'] = (dev['endpoint_alert_abs_dev'] / (dev['peer_endpoint_alert_median'] + 1.0)).round(4)
    dev['endpoint_alert_zscore'] = dev.apply(
        lambda r: calculate_robust_zscore(r['endpoint_alert_count'], r['peer_endpoint_alert_median'], r['peer_endpoint_alert_mad']), axis=1
    ).round(4)

    # Feature 5: Unique Source IPs & Unique Hosts z-scores (population baseline comparison)
    ip_med, ip_mad = dev['unique_source_ip_count'].median(), calculate_mad(dev['unique_source_ip_count'])
    host_med, host_mad = dev['unique_host_count'].median(), calculate_mad(dev['unique_host_count'])

    dev['unique_source_ip_zscore'] = dev['unique_source_ip_count'].apply(lambda x: calculate_robust_zscore(x, ip_med, ip_mad)).round(4)
    dev['unique_host_zscore'] = dev['unique_host_count'].apply(lambda x: calculate_robust_zscore(x, host_med, host_mad)).round(4)

    # Aggregate Anomaly Signals per Behavioral Dimension
    dev['authentication_deviation'] = dev[['failed_login_zscore', 'auth_failure_rate_zscore']].max(axis=1).clip(lower=0.0)
    dev['network_deviation'] = dev[['unique_source_ip_zscore', 'unique_host_zscore']].max(axis=1).clip(lower=0.0)
    dev['endpoint_deviation'] = dev['endpoint_alert_zscore'].clip(lower=0.0)
    dev['off_hours_deviation'] = dev['off_hours_zscore'].clip(lower=0.0)

    # Overall behavior deviation score (mean of 4 dimensions)
    dev['behavior_deviation_score'] = dev[['authentication_deviation', 'network_deviation', 'endpoint_deviation', 'off_hours_deviation']].mean(axis=1).round(4)

    # Dimension Status Classifications (Neutral Terminology)
    dev['authentication_deviation_status'] = dev['authentication_deviation'].apply(get_deviation_status)
    dev['network_deviation_status'] = dev['network_deviation'].apply(get_deviation_status)
    dev['endpoint_deviation_status'] = dev['endpoint_deviation'].apply(get_deviation_status)
    dev['off_hours_deviation_status'] = dev['off_hours_deviation'].apply(get_deviation_status)
    dev['overall_deviation_status'] = dev['behavior_deviation_score'].apply(get_deviation_status)

    # Multi-Signal Deviation Count (dimensions with Robust Z >= 2.5 i.e. ELEVATED or OUTLIER)
    def count_multi_signals(row):
        count = 0
        if row['authentication_deviation'] >= 2.5:
            count += 1
        if row['network_deviation'] >= 2.5:
            count += 1
        if row['endpoint_deviation'] >= 2.5:
            count += 1
        if row['off_hours_deviation'] >= 2.5:
            count += 1
        return count

    dev['multi_signal_deviation_count'] = dev.apply(count_multi_signals, axis=1)

    return dev


def build_host_deviations(host_base):
    """Calculate host self-deviations, robust Z-scores, and multi-signal count."""
    print("Computing Host Behavioral Deviations & Multi-Signal Signals...")
    dev = host_base.copy()

    # Population baselines for host metrics
    deny_med, deny_mad = dev['firewall_deny_count'].median(), calculate_mad(dev['firewall_deny_count'])
    ratio_med, ratio_mad = dev['firewall_deny_ratio'].median(), calculate_mad(dev['firewall_deny_ratio'])
    bytes_sent_med, bytes_sent_mad = dev['bytes_sent'].median(), calculate_mad(dev['bytes_sent'])
    bytes_recv_med, bytes_recv_mad = dev['bytes_received'].median(), calculate_mad(dev['bytes_received'])
    src_ip_med, src_ip_mad = dev['unique_source_ip_count'].median(), calculate_mad(dev['unique_source_ip_count'])
    dst_ip_med, dst_ip_mad = dev['unique_destination_ip_count'].median(), calculate_mad(dev['unique_destination_ip_count'])
    ep_med, ep_mad = dev['endpoint_alert_count'].median(), calculate_mad(dev['endpoint_alert_count'])

    # Self-deviations & Robust Z-scores
    dev['firewall_deny_abs_dev'] = (dev['firewall_deny_count'] - deny_med).clip(lower=0.0)
    dev['firewall_deny_rel_dev'] = (dev['firewall_deny_abs_dev'] / (deny_med + 1.0)).round(4)
    dev['firewall_deny_zscore'] = dev['firewall_deny_count'].apply(lambda x: calculate_robust_zscore(x, deny_med, deny_mad)).round(4)
    dev['firewall_deny_ratio_zscore'] = dev['firewall_deny_ratio'].apply(lambda x: calculate_robust_zscore(x, ratio_med, ratio_mad)).round(4)

    dev['bytes_sent_zscore'] = dev['bytes_sent'].apply(lambda x: calculate_robust_zscore(x, bytes_sent_med, bytes_sent_mad)).round(4)
    dev['bytes_received_zscore'] = dev['bytes_received'].apply(lambda x: calculate_robust_zscore(x, bytes_recv_med, bytes_recv_mad)).round(4)

    dev['unique_source_ip_zscore'] = dev['unique_source_ip_count'].apply(lambda x: calculate_robust_zscore(x, src_ip_med, src_ip_mad)).round(4)
    dev['unique_destination_ip_zscore'] = dev['unique_destination_ip_count'].apply(lambda x: calculate_robust_zscore(x, dst_ip_med, dst_ip_mad)).round(4)

    dev['endpoint_alert_zscore'] = dev['endpoint_alert_count'].apply(lambda x: calculate_robust_zscore(x, ep_med, ep_mad)).round(4)

    # Anomaly signal dimensions
    dev['network_deviation'] = dev[['firewall_deny_zscore', 'firewall_deny_ratio_zscore', 'unique_destination_ip_zscore']].max(axis=1).clip(lower=0.0)
    dev['endpoint_deviation'] = dev['endpoint_alert_zscore'].clip(lower=0.0)
    dev['volume_deviation'] = dev[['bytes_sent_zscore', 'bytes_received_zscore']].max(axis=1).clip(lower=0.0)

    dev['behavior_deviation_score'] = dev[['network_deviation', 'endpoint_deviation', 'volume_deviation']].mean(axis=1).round(4)

    # Dimension Statuses
    dev['network_deviation_status'] = dev['network_deviation'].apply(get_deviation_status)
    dev['endpoint_deviation_status'] = dev['endpoint_deviation'].apply(get_deviation_status)
    dev['volume_deviation_status'] = dev['volume_deviation'].apply(get_deviation_status)
    dev['overall_deviation_status'] = dev['behavior_deviation_score'].apply(get_deviation_status)

    # Multi-Signal Count
    def count_host_multi_signals(row):
        count = 0
        if row['network_deviation'] >= 2.5:
            count += 1
        if row['endpoint_deviation'] >= 2.5:
            count += 1
        if row['volume_deviation'] >= 2.5:
            count += 1
        return count

    dev['multi_signal_deviation_count'] = dev.apply(count_host_multi_signals, axis=1)

    return dev


def prepare_clustering_features(user_dev, host_dev):
    """Build a scaled, clean behavioral feature matrix for downstream clustering."""
    print("Preparing Scaled Clustering Feature Matrix...")
    
    user_feats = user_dev[[
        'user_id', 'failed_login_zscore', 'auth_failure_rate_zscore',
        'off_hours_zscore', 'endpoint_alert_zscore', 'unique_source_ip_zscore',
        'unique_host_zscore', 'behavior_deviation_score', 'multi_signal_deviation_count'
    ]].rename(columns={'user_id': 'entity_id'})
    user_feats['entity_type'] = 'USER'

    host_feats = host_dev[[
        'hostname', 'firewall_deny_zscore', 'firewall_deny_ratio_zscore',
        'bytes_sent_zscore', 'bytes_received_zscore', 'endpoint_alert_zscore',
        'behavior_deviation_score', 'multi_signal_deviation_count'
    ]].rename(columns={'hostname': 'entity_id'})
    host_feats['entity_type'] = 'HOST'

    combined = pd.concat([user_feats, host_feats], ignore_index=True)
    combined = combined.fillna(0.0)

    return combined


def main():
    print("=" * 70)
    print("TRACEONE BEHAVIORAL BASELINE & DEVIATION GENERATOR (PHASE E)")
    print("=" * 70)

    # Load canonical and feature datasets
    events_df = pd.read_csv(PROCESSED_DIR / "canonical_events.csv")
    users_df = pd.read_csv(PROCESSED_DIR / "user_security_features.csv")
    hosts_df = pd.read_csv(PROCESSED_DIR / "host_security_features.csv")

    # Step 1-4: Baselines
    user_base = build_user_baselines(events_df, users_df)
    host_base = build_host_baselines(events_df, hosts_df)

    # Step 5-9: Deviations & Multi-Signals
    user_dev = build_user_deviations(user_base)
    host_dev = build_host_deviations(host_base)

    # Step 10: Cluster Prep
    clustering_df = prepare_clustering_features(user_dev, host_dev)

    # Save output tables
    user_base.to_csv(PROCESSED_DIR / "user_behavior_baselines.csv", index=False)
    host_base.to_csv(PROCESSED_DIR / "host_behavior_baselines.csv", index=False)
    user_dev.to_csv(PROCESSED_DIR / "user_behavior_deviations.csv", index=False)
    host_dev.to_csv(PROCESSED_DIR / "host_behavior_deviations.csv", index=False)
    clustering_df.to_csv(PROCESSED_DIR / "clustering_prepared_features.csv", index=False)

    print("\nSaved output files to data/processed/:")
    print(" - user_behavior_baselines.csv")
    print(" - host_behavior_baselines.csv")
    print(" - user_behavior_deviations.csv")
    print(" - host_behavior_deviations.csv")
    print(" - clustering_prepared_features.csv")
    print("=" * 70)
    print("PHASE E GENERATION COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
