"""
Endpoint Cleaned Data Validation
Track 2 — Zero-Trust Telemetry & Insider Threat Logs

Validates the FINAL 17-column analytical Endpoint dataset.

The validator checks:
    - expected row count
    - final schema
    - duplicate rows
    - duplicate alert IDs
    - user IDs
    - severity
    - status
    - device criticality
    - timestamps
    - chronology anomalies
    - SHA-256 values
    - resolution duration
    - zero missing cells
"""

from pathlib import Path
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = (
    ROOT
    / "data"
    / "raw"
    / "track2_endpoint_alerts.xlsx"
)

CLEAN_FILE = (
    ROOT
    / "data"
    / "cleaned"
    / "endpoint_cleaned.csv"
)

REPORT_DIR = ROOT / "reports"
REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

VALIDATION_REPORT = (
    REPORT_DIR
    / "endpoint_validation_report.csv"
)


# ============================================================
# EXPECTED FINAL SCHEMA
# ============================================================

EXPECTED_COLUMNS = [
    "alert_id",
    "detected_timestamp",
    "resolved_timestamp",
    "hostname",
    "user_id",
    "endpoint_product",
    "alert_name",
    "severity",
    "status",
    "description",
    "file_path",
    "process_name",
    "sha256",
    "assigned_to",
    "device_criticality",
    "severity_rank",
    "resolution_duration_hours",
]


EXPECTED_SEVERITIES = {
    "Critical",
    "High",
    "Medium",
    "Low",
    "Unknown",
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
    "Unknown",
}


EXPECTED_DEVICE_CRITICALITY = {
    "Critical",
    "High",
    "Medium",
    "Low",
    "Unknown",
}


EXPECTED_SEVERITY_RANKS = {
    1,
    2,
    3,
    4,
}


# ============================================================
# HELPERS
# ============================================================

def valid_user_id(value):
    """Validate canonical employee ID."""

    if pd.isna(value):
        return False

    value = str(value).strip()

    if value == "Unknown":
        return True

    return bool(
        re.fullmatch(
            r"EMP\d+",
            value.upper(),
        )
    )


def valid_sha256(value):
    """
    Validate final SHA-256 values.

    'Unknown' is allowed because invalid/missing source hashes
    are represented semantically in the final analytical data.
    """

    if pd.isna(value):
        return False

    value = str(value).strip()

    if value == "Unknown":
        return True

    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{64}",
            value,
        )
    )


def valid_timestamp(value):
    """Validate final timestamp representation."""

    if pd.isna(value):
        return False

    value = str(value).strip()

    if value == "Unknown":
        return True

    parsed = pd.to_datetime(
        value,
        errors="coerce",
    )

    return not pd.isna(parsed)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 60)
print("ENDPOINT CLEANED DATA VALIDATION")
print("=" * 60)

print("\n[1/10] Loading raw and cleaned data...")

if not RAW_FILE.exists():
    raise FileNotFoundError(
        f"Raw Endpoint file not found: {RAW_FILE}"
    )

if not CLEAN_FILE.exists():
    raise FileNotFoundError(
        f"Cleaned Endpoint file not found: {CLEAN_FILE}"
    )


raw = pd.read_excel(
    RAW_FILE
)

clean = pd.read_csv(
    CLEAN_FILE,
    keep_default_na=False,
)

print(
    f"Raw rows     : {len(raw):,}"
)

print(
    f"Cleaned rows : {len(clean):,}"
)


# ============================================================
# 2. ROW COUNT
# ============================================================

print("\n[2/10] Checking row count...")

EXPECTED_CLEANED_ROWS = (
    len(raw)
    - int(raw.duplicated().sum())
)

row_count_correct = (
    len(clean)
    == EXPECTED_CLEANED_ROWS
)

print(
    f"Expected cleaned rows : "
    f"{EXPECTED_CLEANED_ROWS:,}"
)

print(
    f"Actual cleaned rows   : "
    f"{len(clean):,}"
)

print(
    "Row count status      : "
    f"{'PASS' if row_count_correct else 'FAIL'}"
)


# ============================================================
# 3. FINAL SCHEMA
# ============================================================

print(
    "\n[3/10] Checking final analytical schema..."
)

missing_columns = [
    column
    for column in EXPECTED_COLUMNS
    if column not in clean.columns
]

unexpected_columns = [
    column
    for column in clean.columns
    if column not in EXPECTED_COLUMNS
]

schema_correct = (
    len(clean.columns)
    == len(EXPECTED_COLUMNS)
    and not missing_columns
    and not unexpected_columns
)

print(
    f"Expected columns : "
    f"{len(EXPECTED_COLUMNS)}"
)

print(
    f"Actual columns   : "
    f"{len(clean.columns)}"
)

print(
    f"Missing columns  : "
    f"{missing_columns if missing_columns else 'None'}"
)

print(
    f"Unexpected columns: "
    f"{unexpected_columns if unexpected_columns else 'None'}"
)


# ============================================================
# 4. DUPLICATES
# ============================================================

print("\n[4/10] Checking duplicates...")

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
# 5. USER IDS
# ============================================================

print("\n[5/10] Validating user IDs...")

invalid_user_ids = int(
    (
        ~clean["user_id"].apply(
            valid_user_id
        )
    ).sum()
)

unknown_user_ids = int(
    clean["user_id"].eq("Unknown").sum()
)

print(
    f"Invalid user IDs : "
    f"{invalid_user_ids:,}"
)

print(
    f"Unknown user IDs : "
    f"{unknown_user_ids:,}"
)


# ============================================================
# 6. CATEGORICAL VALUES
# ============================================================

print(
    "\n[6/10] Validating categorical standardization..."
)

invalid_severity = int(
    (
        ~clean["severity"].isin(
            EXPECTED_SEVERITIES
        )
    ).sum()
)

invalid_status = int(
    (
        ~clean["status"].isin(
            EXPECTED_STATUSES
        )
    ).sum()
)

invalid_device_criticality = int(
    (
        ~clean["device_criticality"].isin(
            EXPECTED_DEVICE_CRITICALITY
        )
    ).sum()
)

invalid_severity_rank = int(
    (
        ~clean["severity_rank"].isin(
            EXPECTED_SEVERITY_RANKS
        )
    ).sum()
)

print(
    f"Invalid severity values           : "
    f"{invalid_severity:,}"
)

print(
    f"Invalid status values             : "
    f"{invalid_status:,}"
)

print(
    f"Invalid device criticality values : "
    f"{invalid_device_criticality:,}"
)

print(
    f"Invalid severity ranks             : "
    f"{invalid_severity_rank:,}"
)


# ============================================================
# 7. TIMESTAMPS + CHRONOLOGY
# ============================================================

print(
    "\n[7/10] Validating timestamps..."
)

detected_timestamp_invalid = int(
    (
        ~clean["detected_timestamp"].apply(
            valid_timestamp
        )
    ).sum()
)

resolved_timestamp_invalid = int(
    (
        ~clean["resolved_timestamp"].apply(
            valid_timestamp
        )
    ).sum()
)

# Validate chronology only where both timestamps
# are actual timestamps.
detected = pd.to_datetime(
    clean["detected_timestamp"].replace(
        "Unknown",
        pd.NaT,
    ),
    errors="coerce",
)

resolved = pd.to_datetime(
    clean["resolved_timestamp"].replace(
        "Unknown",
        pd.NaT,
    ),
    errors="coerce",
)

chronology_issues = int(
    (
        detected.notna()
        & resolved.notna()
        & (resolved < detected)
    ).sum()
)

print(
    f"Invalid detected timestamps : "
    f"{detected_timestamp_invalid:,}"
)

print(
    f"Invalid resolved timestamps : "
    f"{resolved_timestamp_invalid:,}"
)

print(
    f"Chronology anomalies flagged : "
    f"{chronology_issues:,}"
)


# ============================================================
# 8. SHA-256
# ============================================================

print(
    "\n[8/10] Validating SHA-256 values..."
)

invalid_sha256 = int(
    (
        ~clean["sha256"].apply(
            valid_sha256
        )
    ).sum()
)

valid_sha256_count = int(
    clean["sha256"].apply(
        lambda x:
        str(x).strip() != "Unknown"
        and valid_sha256(x)
    ).sum()
)

unknown_sha256_count = int(
    clean["sha256"].eq("Unknown").sum()
)

print(
    f"Valid SHA-256 values   : "
    f"{valid_sha256_count:,}"
)

print(
    f"Unknown SHA-256 values : "
    f"{unknown_sha256_count:,}"
)

print(
    f"Invalid SHA-256 values : "
    f"{invalid_sha256:,}"
)


# ============================================================
# 9. DURATION + COMPLETENESS
# ============================================================

print(
    "\n[9/10] Validating resolution duration "
    "and completeness..."
)

clean["resolution_duration_hours"] = pd.to_numeric(
    clean["resolution_duration_hours"],
    errors="coerce",
)

invalid_duration = int(
    (
        clean["resolution_duration_hours"]
        .isna()
        |
        (clean["resolution_duration_hours"] < 0)
    ).sum()
)

missing_cells = int(
    clean.isna().sum().sum()
)

empty_string_cells = int(
    (
        clean.astype(str)
        .apply(
            lambda column:
            column.str.strip().eq("")
        )
        .sum()
        .sum()
    )
)

print(
    f"Invalid resolution durations : "
    f"{invalid_duration:,}"
)

print(
    f"Final missing cells          : "
    f"{missing_cells:,}"
)

print(
    f"Empty string cells           : "
    f"{empty_string_cells:,}"
)


# ============================================================
# 10. BUILD VALIDATION REPORT
# ============================================================

print(
    "\n[10/10] Building validation report..."
)


checks = [
    {
        "check": "cleaned_row_count",
        "value": len(clean),
        "expected": EXPECTED_CLEANED_ROWS,
        "status": (
            "PASS"
            if row_count_correct
            else "FAIL"
        ),
    },
    {
        "check": "final_schema",
        "value": len(clean.columns),
        "expected": len(EXPECTED_COLUMNS),
        "status": (
            "PASS"
            if schema_correct
            else "FAIL"
        ),
    },
    {
        "check": "exact_duplicate_rows",
        "value": exact_duplicates,
        "expected": 0,
        "status": (
            "PASS"
            if exact_duplicates == 0
            else "FAIL"
        ),
    },
    {
        "check": "duplicate_alert_ids",
        "value": duplicate_alert_ids,
        "expected": 0,
        "status": (
            "PASS"
            if duplicate_alert_ids == 0
            else "FAIL"
        ),
    },
    {
        "check": "invalid_user_ids",
        "value": invalid_user_ids,
        "expected": 0,
        "status": (
            "PASS"
            if invalid_user_ids == 0
            else "FAIL"
        ),
    },
    {
        "check": "invalid_severity_values",
        "value": invalid_severity,
        "expected": 0,
        "status": (
            "PASS"
            if invalid_severity == 0
            else "FAIL"
        ),
    },
    {
        "check": "invalid_status_values",
        "value": invalid_status,
        "expected": 0,
        "status": (
            "PASS"
            if invalid_status == 0
            else "FAIL"
        ),
    },
    {
        "check": "invalid_device_criticality",
        "value": invalid_device_criticality,
        "expected": 0,
        "status": (
            "PASS"
            if invalid_device_criticality == 0
            else "FAIL"
        ),
    },
    {
        "check": "invalid_severity_rank",
        "value": invalid_severity_rank,
        "expected": 0,
        "status": (
            "PASS"
            if invalid_severity_rank == 0
            else "FAIL"
        ),
    },
    {
        "check": "invalid_detected_timestamps",
        "value": detected_timestamp_invalid,
        "expected": 0,
        "status": (
            "PASS"
            if detected_timestamp_invalid == 0
            else "FAIL"
        ),
    },
    {
        "check": "invalid_resolved_timestamps",
        "value": resolved_timestamp_invalid,
        "expected": 0,
        "status": (
            "PASS"
            if resolved_timestamp_invalid == 0
            else "FAIL"
        ),
    },
    {
        "check": "chronology_anomalies",
        "value": chronology_issues,
        "expected": "flagged_only",
        "status": "PASS",
    },
    {
        "check": "invalid_sha256",
        "value": invalid_sha256,
        "expected": 0,
        "status": (
            "PASS"
            if invalid_sha256 == 0
            else "FAIL"
        ),
    },
    {
        "check": "invalid_resolution_duration",
        "value": invalid_duration,
        "expected": 0,
        "status": (
            "PASS"
            if invalid_duration == 0
            else "FAIL"
        ),
    },
    {
        "check": "final_missing_cells",
        "value": missing_cells,
        "expected": 0,
        "status": (
            "PASS"
            if missing_cells == 0
            else "FAIL"
        ),
    },
    {
        "check": "empty_string_cells",
        "value": empty_string_cells,
        "expected": 0,
        "status": (
            "PASS"
            if empty_string_cells == 0
            else "FAIL"
        ),
    },
]


validation_df = pd.DataFrame(
    checks
)

validation_df.to_csv(
    VALIDATION_REPORT,
    index=False,
)


# ============================================================
# FINAL RESULT
# ============================================================

print("\n" + "=" * 60)
print("ENDPOINT VALIDATION SUMMARY")
print("=" * 60)

pass_count = int(
    (
        validation_df["status"]
        == "PASS"
    ).sum()
)

fail_count = int(
    (
        validation_df["status"]
        == "FAIL"
    ).sum()
)

print(
    f"PASS checks : {pass_count}"
)

print(
    f"FAIL checks : {fail_count}"
)

print("\nValidation results:")

print(
    validation_df[
        [
            "check",
            "value",
            "expected",
            "status",
        ]
    ].to_string(
        index=False
    )
)

print("\nGenerated:")
print(
    f"  {VALIDATION_REPORT}"
)

print("\n" + "=" * 60)

if fail_count == 0:
    print(
        "RESULT: ALL ENDPOINT VALIDATION CHECKS PASSED"
    )
else:
    print(
        "RESULT: ENDPOINT VALIDATION FAILURES FOUND"
    )

print("=" * 60)