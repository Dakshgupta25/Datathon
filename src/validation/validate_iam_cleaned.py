from pathlib import Path
import ipaddress
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_PATH = PROJECT_ROOT / "data" / "raw" / "track2_iam_audit_trail.json"
CLEAN_PATH = PROJECT_ROOT / "data" / "cleaned" / "iam_cleaned.csv"


# ============================================================
# HELPERS
# ============================================================

def is_valid_ip(value):
    if pd.isna(value) or str(value).strip() == "":
        return False

    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_valid_user_id(value):
    if pd.isna(value):
        return False

    return bool(re.fullmatch(r"EMP\d+", str(value).strip()))


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print("IAM CLEANED DATA VALIDATION")
    print("=" * 65)

    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    print("\n[1/7] Loading raw and cleaned data...")

    raw = pd.read_json(RAW_PATH)
    clean = pd.read_csv(CLEAN_PATH)

    print(f"Raw rows     : {len(raw):,}")
    print(f"Cleaned rows : {len(clean):,}")

    # --------------------------------------------------------
    # DUPLICATES
    # --------------------------------------------------------

    print("\n[2/7] Checking duplicates...")

    duplicate_rows = int(clean.duplicated().sum())

    duplicate_event_ids = int(
        clean["event_id"].duplicated().sum()
    )

    print(f"Exact duplicate rows remaining : {duplicate_rows:,}")
    print(f"Duplicate event IDs remaining  : {duplicate_event_ids:,}")

    # --------------------------------------------------------
    # USER IDs
    # --------------------------------------------------------

    print("\n[3/7] Validating user IDs...")

    invalid_user_ids = (
        ~clean["user_id_clean"].apply(is_valid_user_id)
    ).sum()

    missing_user_ids = clean["user_id_clean"].isna().sum()

    print(f"Invalid user IDs : {invalid_user_ids:,}")
    print(f"Missing user IDs : {missing_user_ids:,}")

    # --------------------------------------------------------
    # DEPARTMENTS
    # --------------------------------------------------------

    print("\n[4/7] Checking department standardization...")

    department_status_counts = (
        clean["department_status"]
        .value_counts(dropna=False)
    )

    print("\nDepartment status:")
    print(department_status_counts.to_string())

    print("\nRemaining raw department values:")
    print(
        clean.loc[
            clean["department_status"] != "mapped",
            "department_raw"
        ]
        .value_counts(dropna=False)
        .head(20)
        .to_string()
    )

    # --------------------------------------------------------
    # EVENT TYPES
    # --------------------------------------------------------

    print("\n[5/7] Investigating event type mappings...")

    print("\nEvent type status:")
    print(
        clean["event_type_status"]
        .value_counts(dropna=False)
        .to_string()
    )

    print("\nUnmapped event type RAW values:")

    unmapped_events = (
        clean.loc[
            clean["event_type_status"] == "unmapped",
            "event_type_raw"
        ]
        .value_counts(dropna=False)
    )

    print(unmapped_events.to_string())

    # --------------------------------------------------------
    # MFA + IP
    # --------------------------------------------------------

    print("\n[6/7] Validating MFA and source IP...")

    print("\nMFA cleaned values:")
    print(
        clean["mfa_passed_clean"]
        .value_counts(dropna=False)
        .to_string()
    )

    missing_ip = clean["source_ip_clean"].isna().sum()

    valid_clean_ips = (
        clean["source_ip_clean"]
        .apply(is_valid_ip)
        .sum()
    )

    print(f"\nValid cleaned IPs   : {valid_clean_ips:,}")
    print(f"Missing clean IPs   : {missing_ip:,}")

    # --------------------------------------------------------
    # RISK + TIMESTAMP
    # --------------------------------------------------------

    print("\n[7/7] Validating risk scores and timestamps...")

    print("\nRisk score status:")
    print(
        clean["risk_score_status"]
        .value_counts(dropna=False)
        .to_string()
    )

    print("\nRisk anomaly reasons:")
    print(
        clean["risk_anomaly_reason"]
        .value_counts(dropna=False)
        .to_string()
    )

    print("\nTimestamp validity:")
    print(
        clean["timestamp_valid"]
        .value_counts(dropna=False)
        .to_string()
    )

    # Numeric risk range check
    numeric_risk = pd.to_numeric(
        clean["risk_score_numeric"],
        errors="coerce"
    )

    outside_range = (
        numeric_risk.notna()
        & (
            (numeric_risk < 0)
            | (numeric_risk > 100)
        )
    ).sum()

    print(f"\nNumeric risk scores outside 0-100: {outside_range:,}")

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print("\n" + "=" * 65)
    print("IAM VALIDATION SUMMARY")
    print("=" * 65)

    print(f"Raw rows                    : {len(raw):,}")
    print(f"Cleaned rows                : {len(clean):,}")
    print(f"Exact duplicates remaining  : {duplicate_rows:,}")
    print(f"Duplicate event IDs         : {duplicate_event_ids:,}")
    print(f"Invalid user IDs            : {invalid_user_ids:,}")
    print(f"Missing user IDs            : {missing_user_ids:,}")
    print(f"Cleaned IPs that are valid  : {valid_clean_ips:,}")
    print(f"Risk values outside range  : {outside_range:,}")

    print("\nValidation complete.")


if __name__ == "__main__":
    main()