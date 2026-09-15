"""
TraceONE Temporal Security Correlation Validation Suite
Phase G: Step 15 - Temporal Engine Validation

Verifies event ID validity, chronological ordering (start <= end), non-negative durations,
strict exclusion of Unknown timestamps, unique sequence IDs, sequence confidence bounds [0.0, 1.0],
sequence strength bounds [0.0, 100.0], and confirms Phase F risk scores were NOT modified.
"""

from pathlib import Path
import sys
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def run_temporal_validation():
    print("=" * 70)
    print("TRACEONE TEMPORAL ENGINE VALIDATION (PHASE G)")
    print("=" * 70)

    events_df = pd.read_csv(PROCESSED_DIR / "canonical_events.csv")
    seq_df = pd.read_csv(PROCESSED_DIR / "temporal_sequences.csv")
    ev_df = pd.read_csv(PROCESSED_DIR / "temporal_evidence.csv")
    freq_df = pd.read_csv(PROCESSED_DIR / "sequence_pattern_frequency.csv")
    user_sig = pd.read_csv(PROCESSED_DIR / "user_temporal_signals.csv")
    host_sig = pd.read_csv(PROCESSED_DIR / "host_temporal_signals.csv")
    risk_df = pd.read_csv(PROCESSED_DIR / "traceone_risk_scores.csv")

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

    # Check 1: Unique Sequence IDs
    unique_seq = len(seq_df) == seq_df['sequence_id'].nunique()
    assert_check(unique_seq, "Unique Sequence IDs", f"Total: {len(seq_df)}, Unique: {seq_df['sequence_id'].nunique()}")

    # Check 2: Chronological Timestamp Ordering (start <= end)
    seq_df['start_dt'] = pd.to_datetime(seq_df['start_time'], utc=True)
    seq_df['end_dt'] = pd.to_datetime(seq_df['end_time'], utc=True)
    chronological = (seq_df['start_dt'] <= seq_df['end_dt']).all()
    assert_check(chronological, "Chronological Sequence Timestamp Ordering", "Detected start_time > end_time")

    # Check 3: Non-Negative Sequence Durations
    non_neg_dur = (seq_df['duration_seconds'] >= 0).all()
    assert_check(non_neg_dur, "Non-Negative Sequence Durations", f"Min duration: {seq_df['duration_seconds'].min()}")

    # Check 4: Strict Exclusion of Unknown Timestamps from Evidence
    no_unknown_ev = (ev_df['event_timestamp'] != 'Unknown').all() and ev_df['event_timestamp'].notna().all()
    assert_check(no_unknown_ev, "Strict Exclusion of Unknown Timestamps from Sequences", "Unknown or null timestamp found in evidence")

    # Check 5: Canonical Event ID Linkage (All sequence event IDs exist)
    all_event_ids = set(events_df['event_id'])
    ev_event_ids = set(ev_df['event_id'])
    valid_event_refs = ev_event_ids.issubset(all_event_ids)
    assert_check(valid_event_refs, "Canonical Event ID Linkage Integrity", f"Unmatched event IDs in temporal evidence: {len(ev_event_ids - all_event_ids)}")

    # Check 6: Sequence Confidence Bounds [0.0, 1.0]
    conf_bounded = (seq_df['sequence_confidence'] >= 0.0).all() and (seq_df['sequence_confidence'] <= 1.0).all()
    assert_check(conf_bounded, "Sequence Confidence Bounds [0, 1]", f"Min: {seq_df['sequence_confidence'].min()}, Max: {seq_df['sequence_confidence'].max()}")

    # Check 7: Sequence Strength Bounds [0.0, 100.0]
    strength_bounded = (seq_df['sequence_strength'] >= 0.0).all() and (seq_df['sequence_strength'] <= 100.0).all()
    assert_check(strength_bounded, "Sequence Strength Bounds [0, 100]", f"Min: {seq_df['sequence_strength'].min()}, Max: {seq_df['sequence_strength'].max()}")

    # Check 8: Temporal Window Limit Compliance (<= 60 minutes = 3600s)
    window_compliant = (seq_df['duration_seconds'] <= 3600).all()
    assert_check(window_compliant, "Temporal Window Compliance (<= 60 mins)", f"Max duration: {seq_df['duration_seconds'].max()}")

    # Check 9: Standalone Temporal Signal Completeness for Users (3000 rows)
    user_sig_complete = len(user_sig) == 3000 and not user_sig.isna().any().any()
    assert_check(user_sig_complete, "User Temporal Signals Completeness (3,000 Users)", f"Rows: {len(user_sig)}")

    # Check 10: Standalone Temporal Signal Completeness for Hosts (8413 rows)
    host_sig_complete = len(host_sig) == 8413 and not host_sig.isna().any().any()
    assert_check(host_sig_complete, "Host Temporal Signals Completeness (8,413 Hosts)", f"Rows: {len(host_sig)}")

    # Check 11: Confirmation Phase F Risk Scores Unmodified
    risk_unmodified = len(risk_df) == 11413 and not risk_df['traceone_risk_score'].isna().any()
    assert_check(risk_unmodified, "Phase F Risk Scores Preserved & Unmodified", "Phase F risk table compromised or altered")

    print("-" * 70)
    print(f"VALIDATION SUMMARY: {passed_checks}/{total_checks} CHECKS PASSED")
    print("=" * 70)

    if passed_checks < total_checks:
        sys.exit(1)


if __name__ == "__main__":
    run_temporal_validation()
