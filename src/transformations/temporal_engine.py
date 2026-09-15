"""
TraceONE Temporal Security Correlation Engine
Phase G: Temporal Security Correlation Engine

Detects evidence-backed event sequences across valid timestamps,
calculates sequence confidence and strength, discovers pattern repeat frequencies,
and outputs normalized temporal sequence tables without overwriting Phase F risk scores.
"""

from pathlib import Path
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def calculate_sequence_confidence(ts_quality, num_sources, event_count):
    """Calculate sequence confidence score bounded [0.0, 1.0]."""
    cross_source_factor = 1.0 if num_sources >= 2 else 0.5
    obs_factor = min(1.0, float(event_count) / 5.0)
    ts_factor = float(ts_quality) if pd.notna(ts_quality) else 0.8
    
    conf = 0.5 * ts_factor + 0.3 * cross_source_factor + 0.2 * obs_factor
    return round(float(np.clip(conf, 0.0, 1.0)), 4)


def calculate_sequence_strength(num_sources, num_categories, event_count, is_cross_source):
    """Calculate neutral sequence strength index bounded [0.0, 100.0]."""
    strength = (25.0 * num_sources + 
                20.0 * num_categories + 
                15.0 * min(5, event_count) + 
                20.0 * (1.0 if is_cross_source else 0.0))
    return round(float(np.clip(strength, 0.0, 100.0)), 2)


def detect_user_sequences(events_df):
    """Detect evidence-backed chronological event sequences for users."""
    print("Detecting User Temporal Sequences...")
    
    # Filter valid timestamps and sort deterministically
    valid_events = events_df[events_df['event_timestamp'] != 'Unknown'].copy()
    valid_events['valid_ts'] = pd.to_datetime(valid_events['event_timestamp'], format='mixed', utc=True)
    valid_events = valid_events.sort_values(['user_id', 'valid_ts', 'event_id'])

    sequences = []
    evidence_rows = []

    seq_counter = 1000

    grouped = valid_events.groupby('user_id')

    for uid, group in grouped:
        if len(group) < 2:
            continue

        events_list = group.to_dict('records')
        n = len(events_list)
        
        i = 0
        while i < n - 1:
            curr = events_list[i]
            # Form window sequence (events within 1 hour = 3600 seconds)
            window_events = [curr]
            j = i + 1
            while j < n:
                delta = (events_list[j]['valid_ts'] - curr['valid_ts']).total_seconds()
                if delta <= 3600:
                    window_events.append(events_list[j])
                    j += 1
                else:
                    break

            if len(window_events) >= 2:
                seq_id = f"SEQ-USR-{seq_counter}"
                seq_counter += 1

                start_ts = window_events[0]['valid_ts']
                end_ts = window_events[-1]['valid_ts']
                duration_sec = int((end_ts - start_ts).total_seconds())

                event_ids = [e['event_id'] for e in window_events]
                categories = list(set(e['event_category'] for e in window_events))
                sources = list(set(e['source_dataset'] for e in window_events))
                actions = [e['action'] for e in window_events]

                # Determine sequence pattern type
                seq_type = "GENERAL_ACTIVITY_SEQUENCE"
                if "FAILED_LOGIN" in actions and "LOGIN_SUCCESS" in actions:
                    seq_type = "FAILED_AUTH_TO_SUCCESS"
                elif actions.count("FAILED_LOGIN") >= 2:
                    seq_type = "FAILED_LOGIN_SERIES"
                elif "AUTHENTICATION" in categories and "ENDPOINT_ALERT" in categories:
                    seq_type = "AUTH_TO_ENDPOINT_ALERT"
                elif "AUTHENTICATION" in categories and "NETWORK_FLOW" in categories:
                    seq_type = "AUTH_TO_FIREWALL_DENY"
                elif len(sources) >= 2:
                    seq_type = "CROSS_SOURCE_SESSION_CHAIN"

                num_sources = len(sources)
                num_categories = len(categories)
                is_cross = num_sources >= 2

                seq_conf = calculate_sequence_confidence(1.0, num_sources, len(window_events))
                seq_strength = calculate_sequence_strength(num_sources, num_categories, len(window_events), is_cross)

                # Counter-evidence
                counter_ev = []
                if not is_cross:
                    counter_ev.append("SINGLE_SOURCE_ONLY")
                if duration_sec == 0:
                    counter_ev.append("IDENTICAL_TIMESTAMP_WINDOW")
                counter_ev_str = "; ".join(counter_ev) if counter_ev else "NONE_OBSERVED"

                sequences.append({
                    'sequence_id': seq_id,
                    'entity_id': uid,
                    'entity_type': 'USER',
                    'sequence_type': seq_type,
                    'start_time': str(start_ts),
                    'end_time': str(end_ts),
                    'duration_seconds': duration_sec,
                    'event_count': len(window_events),
                    'event_ids': "; ".join(event_ids),
                    'source_datasets': "; ".join(sources),
                    'temporal_window_minutes': 60,
                    'sequence_confidence': seq_conf,
                    'sequence_strength': seq_strength,
                    'counter_evidence': counter_ev_str
                })

                for rank, e in enumerate(window_events, start=1):
                    evidence_rows.append({
                        'sequence_id': seq_id,
                        'entity_id': uid,
                        'entity_type': 'USER',
                        'event_id': e['event_id'],
                        'source_dataset': e['source_dataset'],
                        'source_record_id': e['source_record_id'],
                        'event_timestamp': str(e['valid_ts']),
                        'event_category': e['event_category'],
                        'role_in_sequence': f"step_{rank}"
                    })

                i = j  # Move pointer forward
            else:
                i += 1

    return pd.DataFrame(sequences), pd.DataFrame(evidence_rows)


def detect_host_sequences(events_df):
    """Detect evidence-backed chronological event sequences for hosts."""
    print("Detecting Host Temporal Sequences...")
    
    valid_events = events_df[(events_df['event_timestamp'] != 'Unknown') & (events_df['hostname'] != 'Unknown')].copy()
    valid_events['valid_ts'] = pd.to_datetime(valid_events['event_timestamp'], format='mixed', utc=True)
    valid_events = valid_events.sort_values(['hostname', 'valid_ts', 'event_id'])

    sequences = []
    evidence_rows = []

    seq_counter = 1000

    grouped = valid_events.groupby('hostname')

    for host, group in grouped:
        if len(group) < 2:
            continue

        events_list = group.to_dict('records')
        n = len(events_list)

        i = 0
        while i < n - 1:
            curr = events_list[i]
            window_events = [curr]
            j = i + 1
            while j < n:
                delta = (events_list[j]['valid_ts'] - curr['valid_ts']).total_seconds()
                if delta <= 3600:
                    window_events.append(events_list[j])
                    j += 1
                else:
                    break

            if len(window_events) >= 2:
                seq_id = f"SEQ-HST-{seq_counter}"
                seq_counter += 1

                start_ts = window_events[0]['valid_ts']
                end_ts = window_events[-1]['valid_ts']
                duration_sec = int((end_ts - start_ts).total_seconds())

                event_ids = [e['event_id'] for e in window_events]
                categories = list(set(e['event_category'] for e in window_events))
                sources = list(set(e['source_dataset'] for e in window_events))
                actions = [e['action'] for e in window_events]

                seq_type = "HOST_ACTIVITY_SEQUENCE"
                if actions.count("DENY") >= 3:
                    seq_type = "FIREWALL_DENY_SPIKE"
                elif categories.count("ENDPOINT_ALERT") >= 2:
                    seq_type = "ENDPOINT_ALERT_BURST"
                elif "NETWORK_FLOW" in categories and "ENDPOINT_ALERT" in categories:
                    seq_type = "FIREWALL_DENY_TO_ENDPOINT_ALERT"
                elif len(sources) >= 2:
                    seq_type = "CROSS_SOURCE_HOST_CHAIN"

                num_sources = len(sources)
                num_categories = len(categories)
                is_cross = num_sources >= 2

                seq_conf = calculate_sequence_confidence(1.0, num_sources, len(window_events))
                seq_strength = calculate_sequence_strength(num_sources, num_categories, len(window_events), is_cross)

                counter_ev = []
                if not is_cross:
                    counter_ev.append("SINGLE_SOURCE_ONLY")
                if duration_sec == 0:
                    counter_ev.append("IDENTICAL_TIMESTAMP_WINDOW")
                counter_ev_str = "; ".join(counter_ev) if counter_ev else "NONE_OBSERVED"

                sequences.append({
                    'sequence_id': seq_id,
                    'entity_id': host,
                    'entity_type': 'HOST',
                    'sequence_type': seq_type,
                    'start_time': str(start_ts),
                    'end_time': str(end_ts),
                    'duration_seconds': duration_sec,
                    'event_count': len(window_events),
                    'event_ids': "; ".join(event_ids),
                    'source_datasets': "; ".join(sources),
                    'temporal_window_minutes': 60,
                    'sequence_confidence': seq_conf,
                    'sequence_strength': seq_strength,
                    'counter_evidence': counter_ev_str
                })

                for rank, e in enumerate(window_events, start=1):
                    evidence_rows.append({
                        'sequence_id': seq_id,
                        'entity_id': host,
                        'entity_type': 'HOST',
                        'event_id': e['event_id'],
                        'source_dataset': e['source_dataset'],
                        'source_record_id': e['source_record_id'],
                        'event_timestamp': str(e['valid_ts']),
                        'event_category': e['event_category'],
                        'role_in_sequence': f"step_{rank}"
                    })

                i = j
            else:
                i += 1

    return pd.DataFrame(sequences), pd.DataFrame(evidence_rows)


def build_pattern_frequency_table(seq_df):
    """Categorize sequence pattern repeat frequency into COMMON, UNUSUAL, or RARE."""
    print("Analyzing Repeat Sequence Patterns & Frequencies...")
    freq = seq_df.groupby('sequence_type').agg(
        pattern_occurrence_count=('sequence_id', 'count'),
        unique_entities=('entity_id', 'nunique'),
        avg_event_count=('event_count', 'mean'),
        avg_duration_sec=('duration_seconds', 'mean')
    ).reset_index()

    def get_pattern_rarity(count):
        if count > 50:
            return "COMMON"
        elif count >= 10:
            return "UNUSUAL"
        else:
            return "RARE"

    freq['rarity_category'] = freq['pattern_occurrence_count'].apply(get_pattern_rarity)
    freq['avg_event_count'] = freq['avg_event_count'].round(2)
    freq['avg_duration_sec'] = freq['avg_duration_sec'].round(2)

    return freq


def build_temporal_signal_outputs(seq_df, users_df, hosts_df):
    """Generate standalone temporal signals for users and hosts without altering Phase F risk scores."""
    print("Generating Standalone Temporal Signals...")
    
    # User temporal signals
    u_seq = seq_df[seq_df['entity_type'] == 'USER']
    u_sig = u_seq.groupby('entity_id').agg(
        temporal_sequence_count=('sequence_id', 'count'),
        strongest_sequence_strength=('sequence_strength', 'max'),
        temporal_evidence_count=('event_count', 'sum'),
        temporal_confidence=('sequence_confidence', 'max')
    ).reset_index().rename(columns={'entity_id': 'user_id'})

    user_signals = pd.merge(users_df[['user_id', 'username']], u_sig, on='user_id', how='left')
    user_signals['temporal_sequence_count'] = user_signals['temporal_sequence_count'].fillna(0).astype(int)
    user_signals['strongest_sequence_strength'] = user_signals['strongest_sequence_strength'].fillna(0.0)
    user_signals['temporal_evidence_count'] = user_signals['temporal_evidence_count'].fillna(0).astype(int)
    user_signals['temporal_confidence'] = user_signals['temporal_confidence'].fillna(0.0)
    user_signals['temporal_signal_present'] = user_signals['temporal_sequence_count'] > 0

    # Host temporal signals
    h_seq = seq_df[seq_df['entity_type'] == 'HOST']
    h_sig = h_seq.groupby('entity_id').agg(
        temporal_sequence_count=('sequence_id', 'count'),
        strongest_sequence_strength=('sequence_strength', 'max'),
        temporal_evidence_count=('event_count', 'sum'),
        temporal_confidence=('sequence_confidence', 'max')
    ).reset_index().rename(columns={'entity_id': 'hostname'})

    host_signals = pd.merge(hosts_df[['hostname']], h_sig, on='hostname', how='left')
    host_signals['temporal_sequence_count'] = host_signals['temporal_sequence_count'].fillna(0).astype(int)
    host_signals['strongest_sequence_strength'] = host_signals['strongest_sequence_strength'].fillna(0.0)
    host_signals['temporal_evidence_count'] = host_signals['temporal_evidence_count'].fillna(0).astype(int)
    host_signals['temporal_confidence'] = host_signals['temporal_confidence'].fillna(0.0)
    host_signals['temporal_signal_present'] = host_signals['temporal_sequence_count'] > 0

    return user_signals, host_signals


def main():
    print("=" * 70)
    print("TRACEONE TEMPORAL SECURITY CORRELATION ENGINE (PHASE G)")
    print("=" * 70)

    events_df = pd.read_csv(PROCESSED_DIR / "canonical_events.csv")
    users_df = pd.read_csv(PROCESSED_DIR / "canonical_users.csv")
    hosts_df = pd.read_csv(PROCESSED_DIR / "canonical_hosts.csv")

    # Step 4 - 6: Detect User & Host Sequences
    u_seq, u_ev = detect_user_sequences(events_df)
    h_seq, h_ev = detect_host_sequences(events_df)

    combined_seq = pd.concat([u_seq, h_seq], ignore_index=True)
    combined_ev = pd.concat([u_ev, h_ev], ignore_index=True)

    # Step 12: Repeat Pattern Discovery
    pattern_freq = build_pattern_frequency_table(combined_seq)

    # Step 9: Standalone Temporal Signals
    user_signals, host_signals = build_temporal_signal_outputs(combined_seq, users_df, hosts_df)

    # Save Output CSV Tables
    combined_seq.to_csv(PROCESSED_DIR / "temporal_sequences.csv", index=False)
    combined_ev.to_csv(PROCESSED_DIR / "temporal_evidence.csv", index=False)
    pattern_freq.to_csv(PROCESSED_DIR / "sequence_pattern_frequency.csv", index=False)
    user_signals.to_csv(PROCESSED_DIR / "user_temporal_signals.csv", index=False)
    host_signals.to_csv(PROCESSED_DIR / "host_temporal_signals.csv", index=False)

    print("\nSaved output files to data/processed/:")
    print(" - temporal_sequences.csv")
    print(" - temporal_evidence.csv")
    print(" - sequence_pattern_frequency.csv")
    print(" - user_temporal_signals.csv")
    print(" - host_temporal_signals.csv")
    print("=" * 70)
    print("PHASE G TEMPORAL ENGINE EXECUTION COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
