from pathlib import Path
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = ROOT / "data" / "raw" / "track2_endpoint_alerts.xlsx"
CLEAN_FILE = ROOT / "data" / "cleaned" / "endpoint_cleaned.csv"

REPORT_DIR = ROOT / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

VALIDATION_REPORT = REPORT_DIR / "endpoint_validation_report.csv"


# ============================================================
# EXPECTED CANONICAL VALUES
# ============================================================

EXPECTED_SEVERITIES = {
    "Critical",
    "High",
    "Medium",
    "Low",
}

EXPECTED_STATUSES = {
    "New",
    "Open",
    "In Progress",
    "Investigating",
    "Resolved",
    "Closed",
    "False Positive",
    "Unassigned",
}

EXPECTED_DEVICE_CRITICALITY = {
    "Critical",
    "High",
    "Medium",
    "Low",
}


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 60)
print("ENDPOINT CLEANED DATA VALIDATION")
print("=" * 60)

print("\n[1/8] Loading raw and cleaned data...")

raw = pd.read_excel(RAW_FILE)
clean = pd.read_csv(CLEAN_FILE)

print(f"Raw rows     : {len(raw):,}")
print(f"Cleaned rows : {len(clean):,}")


# ============================================================
# 1. ROW COUNT / DUPLICATES
# ============================================================

print("\n[2/8] Checking duplicates...")

exact_duplicates = int(
    clean.duplicated().sum()
)

duplicate_alert_ids = int(
    clean["alert_id"].duplicated().sum()
)

print(
    f"Exact duplicate rows remaining : "
    f"{exact_duplicates:,}"
)

print(
    f"Duplicate alert IDs remaining  : "
    f"{duplicate_alert_ids:,}"
)


# ============================================================
# 2. USER ID VALIDATION
# ============================================================

print("\n[3/8] Validating user IDs...")


def valid_user_id(value):
    if pd.isna(value):
        return False

    return bool(
        re.fullmatch(
            r"EMP\d+",
            str(value).strip().upper()
        )
    )


user_id_invalid = int(
    (
        clean["user_id_clean"]
        .notna()
        & ~clean["user_id_clean"].apply(valid_user_id)
    ).sum()
)

user_id_missing = int(
    clean["user_id_clean"].isna().sum()
)

print(f"Invalid user IDs : {user_id_invalid:,}")
print(f"Missing user IDs : {user_id_missing:,}")


# ============================================================
# 3. CATEGORICAL VALIDATION
# ============================================================

print("\n[4/8] Validating categorical standardization...")

severity_invalid = int(
    (
        clean["severity_clean"].notna()
        & ~clean["severity_clean"].isin(
            EXPECTED_SEVERITIES
        )
    ).sum()
)

severity_missing = int(
    clean["severity_clean"].isna().sum()
)


status_invalid = int(
    (
        clean["status_clean"].notna()
        & ~clean["status_clean"].isin(
            EXPECTED_STATUSES
        )
    ).sum()
)

status_missing = int(
    clean["status_clean"].isna().sum()
)


device_invalid = int(
    (
        clean["device_criticality_clean"].notna()
        & ~clean["device_criticality_clean"].isin(
            EXPECTED_DEVICE_CRITICALITY
        )
    ).sum()
)

device_missing = int(
    clean["device_criticality_clean"].isna().sum()
)


print(f"Invalid severity values           : {severity_invalid:,}")
print(f"Missing severity values           : {severity_missing:,}")

print(f"Invalid status values             : {status_invalid:,}")
print(f"Missing status values             : {status_missing:,}")

print(
    f"Invalid device criticality values : "
    f"{device_invalid:,}"
)

print(
    f"Missing device criticality values : "
    f"{device_missing:,}"
)


# ============================================================
# 4. TIMESTAMP VALIDATION
# ============================================================

print("\n[5/8] Validating timestamps...")

detected_invalid = int(
    (
        clean["detected_timestamp_raw"].notna()
        & clean["detected_timestamp_clean"].isna()
    ).sum()
)

resolved_invalid = int(
    (
        clean["resolved_timestamp_raw"].notna()
        & clean["resolved_timestamp_clean"].isna()
    ).sum()
)

chronology_issues = int(
    clean["chronology_issue"].sum()
)

print(
    f"Invalid detected timestamps : "
    f"{detected_invalid:,}"
)

print(
    f"Invalid resolved timestamps : "
    f"{resolved_invalid:,}"
)

print(
    f"Chronology issues           : "
    f"{chronology_issues:,}"
)


# ============================================================
# 5. SHA-256 VALIDATION
# ============================================================

print("\n[6/8] Validating SHA-256 values...")


def valid_sha256(value):
    if pd.isna(value):
        return False

    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{64}",
            str(value).strip()
        )
    )


sha_invalid = int(
    (
        clean["sha256_clean"].notna()
        & ~clean["sha256_clean"].apply(valid_sha256)
    ).sum()
)

sha_valid = int(
    clean["sha256_validation"].eq("valid").sum()
)

sha_missing = int(
    clean["sha256_validation"].eq("missing").sum()
)

sha_invalid_length = int(
    clean["sha256_validation"].eq(
        "invalid_length"
    ).sum()
)

sha_invalid_characters = int(
    clean["sha256_validation"].eq(
        "invalid_characters"
    ).sum()
)

print(f"Valid SHA-256 values       : {sha_valid:,}")
print(f"Missing SHA-256 values     : {sha_missing:,}")
print(f"Invalid-length SHA-256     : {sha_invalid_length:,}")
print(
    f"Invalid-character SHA-256 : "
    f"{sha_invalid_characters:,}"
)

print(
    f"Invalid clean SHA-256     : "
    f"{sha_invalid:,}"
)


# ============================================================
# 6. RAW DATA PRESERVATION
# ============================================================

print("\n[7/8] Checking raw-value preservation...")

raw_columns = [
    "user_id_raw",
    "severity_raw",
    "status_raw",
    "device_criticality_raw",
    "detected_timestamp_raw",
    "resolved_timestamp_raw",
    "hostname_raw",
    "sha256_raw",
]

missing_raw_columns = [
    column
    for column in raw_columns
    if column not in clean.columns
]

print(
    "Missing raw-preservation columns:",
    len(missing_raw_columns)
)

if missing_raw_columns:
    print(missing_raw_columns)


# ============================================================
# 7. BUILD VALIDATION REPORT
# ============================================================

print("\n[8/8] Building validation report...")

checks = [
    {
        "check": "cleaned_row_count",
        "value": len(clean),
        "expected": 8000,
        "status": "PASS"
        if len(clean) == 8000
        else "FAIL",
    },
    {
        "check": "exact_duplicate_rows",
        "value": exact_duplicates,
        "expected": 0,
        "status": "PASS"
        if exact_duplicates == 0
        else "FAIL",
    },
    {
        "check": "duplicate_alert_ids",
        "value": duplicate_alert_ids,
        "expected": 0,
        "status": "PASS"
        if duplicate_alert_ids == 0
        else "FAIL",
    },
    {
        "check": "invalid_user_ids",
        "value": user_id_invalid,
        "expected": 0,
        "status": "PASS"
        if user_id_invalid == 0
        else "FAIL",
    },
    {
        "check": "invalid_severity_values",
        "value": severity_invalid,
        "expected": 0,
        "status": "PASS"
        if severity_invalid == 0
        else "FAIL",
    },
    {
        "check": "invalid_status_values",
        "value": status_invalid,
        "expected": 0,
        "status": "PASS"
        if status_invalid == 0
        else "FAIL",
    },
    {
        "check": "invalid_device_criticality_values",
        "value": device_invalid,
        "expected": 0,
        "status": "PASS"
        if device_invalid == 0
        else "FAIL",
    },
    {
        "check": "invalid_detected_timestamps",
        "value": detected_invalid,
        "expected": 0,
        "status": "PASS"
        if detected_invalid == 0
        else "FAIL",
    },
    {
        "check": "invalid_resolved_timestamps",
        "value": resolved_invalid,
        "expected": 0,
        "status": "PASS"
        if resolved_invalid == 0
        else "FAIL",
    },
    {
        "check": "chronology_anomalies",
        "value": chronology_issues,
        "expected": "flagged_only",
        "status": "PASS"
        if chronology_issues >= 0
        else "FAIL",
    },
    {
        "check": "invalid_clean_sha256",
        "value": sha_invalid,
        "expected": 0,
        "status": "PASS"
        if sha_invalid == 0
        else "FAIL",
    },
    {
        "check": "raw_columns_preserved",
        "value": len(missing_raw_columns),
        "expected": 0,
        "status": "PASS"
        if len(missing_raw_columns) == 0
        else "FAIL",
    },
]


validation_df = pd.DataFrame(checks)

validation_df.to_csv(
    VALIDATION_REPORT,
    index=False
)


# ============================================================
# FINAL RESULT
# ============================================================

print("\n" + "=" * 60)
print("ENDPOINT VALIDATION COMPLETE")
print("=" * 60)

print(
    f"PASS checks : "
    f"{(validation_df['status'] == 'PASS').sum()}"
)

print(
    f"FAIL checks : "
    f"{(validation_df['status'] == 'FAIL').sum()}"
)

print("\nValidation results:")

print(
    validation_df[
        ["check", "value", "expected", "status"]
    ].to_string(index=False)
)

print("\nGenerated:")
print(f"  {VALIDATION_REPORT}")
