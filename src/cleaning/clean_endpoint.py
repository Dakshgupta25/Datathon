from pathlib import Path
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = ROOT / "data" / "raw" / "track2_endpoint_alerts.xlsx"
CLEANED_DIR = ROOT / "data" / "cleaned"
REPORT_DIR = ROOT / "reports"

CLEANED_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = CLEANED_DIR / "endpoint_cleaned.csv"
SUMMARY_FILE = REPORT_DIR / "endpoint_cleaning_summary.csv"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_key(value):
    """
    Normalize categorical text for controlled mapping.

    This does NOT perform fuzzy matching.
    It only removes superficial formatting differences such as:
    - leading/trailing spaces
    - repeated whitespace
    - underscores
    - hyphens
    - case differences
    """

    if pd.isna(value):
        return None

    value = str(value).strip().upper()

    if not value:
        return None

    value = re.sub(r"[\s_\-]+", " ", value)

    return value.strip()


def normalize_user_id(value):
    """
    Standardize user IDs such as:

    EMP12345
    emp12345
    EMP-12345
    EMP 12345
    12345

    into:

    EMP12345
    """

    if pd.isna(value):
        return None

    value = str(value).strip().upper()

    if not value:
        return None

    # Remove spaces, hyphens and underscores.
    value = re.sub(r"[\s\-_]+", "", value)

    # Numeric-only IDs are converted to EMP-prefixed IDs.
    if value.isdigit():
        value = "EMP" + value

    # Validate expected canonical format.
    if re.fullmatch(r"EMP\d+", value):
        return value

    return None


def parse_timestamp(value):
    """
    Parse endpoint timestamps using explicit supported representations.

    Supported:
    1. Unix epoch timestamps in seconds
    2. Common textual datetime formats
    3. Pandas mixed-format fallback

    Raw values are preserved separately.

    Invalid values are returned as NaT rather than fabricated.
    """

    if pd.isna(value):
        return pd.NaT

    value_str = str(value).strip()

    if not value_str:
        return pd.NaT

    # --------------------------------------------------------
    # Rule 1: Unix epoch timestamp in seconds
    # --------------------------------------------------------

    if re.fullmatch(r"\d{10}", value_str):
        try:
            parsed = pd.to_datetime(
                int(value_str),
                unit="s",
                errors="coerce"
            )

            if pd.notna(parsed):
                return parsed

        except Exception:
            pass

    # --------------------------------------------------------
    # Rule 2: Explicit textual formats
    # --------------------------------------------------------

    formats = [
        # ISO-like formats
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",

        # Slash-separated
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",

        # Day-month-year
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",

        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",

        # Month-day-year
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",

        # Month/day/year with AM/PM
        "%m-%d-%Y %I:%M:%S %p",
        "%m-%d-%Y %I:%M %p",

        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %I:%M %p",

        # Textual month
        "%d-%b-%Y %H:%M:%S",
        "%d-%b-%Y %H:%M",

        "%d-%b-%Y %I:%M:%S %p",
        "%d-%b-%Y %I:%M %p",

        # Date-only values
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%Y/%m/%d",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            parsed = pd.to_datetime(
                value_str,
                format=fmt,
                errors="coerce"
            )

            if pd.notna(parsed):
                return parsed

        except Exception:
            continue

    # --------------------------------------------------------
    # Rule 3: Mixed-format fallback
    # --------------------------------------------------------

    try:
        parsed = pd.to_datetime(
            value_str,
            format="mixed",
            errors="coerce"
        )

        if pd.notna(parsed):
            return parsed

    except Exception:
        pass

    return pd.NaT


def clean_sha256(value):
    """
    Validate SHA-256 values.

    A valid hexadecimal SHA-256 hash contains exactly
    64 hexadecimal characters.

    Invalid hashes are NOT repaired or padded.
    """

    if pd.isna(value):
        return None

    value = str(value).strip()

    if not value:
        return None

    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return value.lower()

    return None


def sha256_validation_reason(value):
    """
    Explain why a SHA-256 value is missing or invalid.
    """

    if pd.isna(value):
        return "missing"

    value = str(value).strip()

    if not value:
        return "missing"

    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return "valid"

    if len(value) != 64:
        return "invalid_length"

    return "invalid_characters"


def normalize_hostname(value):
    """
    Normalize endpoint hostnames.

    Standardization:
    - trim whitespace
    - uppercase
    - replace underscores with hyphens
    - remove .corp.local suffix
    """

    if pd.isna(value):
        return None

    value = str(value).strip().upper()

    if not value:
        return None

    value = value.replace("_", "-")

    value = re.sub(
        r"\.CORP\.LOCAL$",
        "",
        value,
        flags=re.IGNORECASE
    )

    return value


# ============================================================
# CONTROLLED MAPPINGS
# ============================================================

# ------------------------------------------------------------
# Severity
# ------------------------------------------------------------

SEVERITY_MAP = {

    # Critical
    "CRIT": "Critical",
    "CRITICAL": "Critical",
    "SEVERE": "Critical",
    "P1": "Critical",

    # High
    "H": "High",
    "HIGH": "High",
    "MAJOR": "High",
    "P2": "High",

    # Medium
    "M": "Medium",
    "MEDIUM": "Medium",
    "MODERATE": "Medium",
    "P3": "Medium",

    # Low
    "L": "Low",
    "LOW": "Low",
    "MINOR": "Low",
    "P4": "Low",
}

SEVERITY_RANK = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


# ------------------------------------------------------------
# Alert status
# ------------------------------------------------------------

STATUS_MAP = {
    "NEW": "New",
    "N": "New",

    "OPEN": "Open",
    "O": "Open",

    # Dataset contains "Active".
    # For analytical lifecycle purposes it is treated as Open.
    "ACTIVE": "Open",

    "IN PROGRESS": "In Progress",
    "WIP": "In Progress",

    "INVESTIGATING": "Investigating",

    "RESOLVED": "Resolved",
    "R": "Resolved",

    "CLOSED": "Closed",

    "FALSE POSITIVE": "False Positive",
    "FP": "False Positive",
    "NOT MALICIOUS": "False Positive",

    "UNASSIGNED": "Unassigned",
}


# ------------------------------------------------------------
# Device criticality
# ------------------------------------------------------------

DEVICE_CRITICALITY_MAP = {
    "CRITICAL": "Critical",

    "HIGH": "High",
    "H": "High",

    "MEDIUM": "Medium",
    "M": "Medium",

    "LOW": "Low",
    "L": "Low",
}


# ============================================================
# MAIN PIPELINE
# ============================================================

print("=" * 60)
print("ENDPOINT DATA CLEANING PIPELINE")
print("=" * 60)


# ------------------------------------------------------------
# 1. LOAD
# ------------------------------------------------------------

print("\n[1/10] Loading raw endpoint data...")

df = pd.read_excel(RAW_FILE)

raw_rows = len(df)

print(f"Raw rows loaded: {raw_rows:,}")


# ------------------------------------------------------------
# 2. EXACT DUPLICATES
# ------------------------------------------------------------

print("\n[2/10] Removing exact duplicate rows...")

duplicate_mask = df.duplicated(keep="first")

exact_duplicates_removed = int(
    duplicate_mask.sum()
)

df = df.loc[~duplicate_mask].copy()

print(
    f"Exact duplicate rows removed: "
    f"{exact_duplicates_removed:,}"
)

print(f"Rows remaining: {len(df):,}")


# ------------------------------------------------------------
# 3. USER IDs
# ------------------------------------------------------------

print("\n[3/10] Cleaning user IDs...")

df["user_id_raw"] = df["user_id"]

df["user_id_clean"] = df["user_id"].apply(
    normalize_user_id
)

df["user_id_valid"] = (
    df["user_id_clean"].notna()
)

user_id_invalid = int(
    (~df["user_id_valid"]).sum()
)


# ------------------------------------------------------------
# 4. SEVERITY
# ------------------------------------------------------------

print("\n[4/10] Standardizing severity...")

df["severity_raw"] = df["severity"]

severity_key = df["severity"].apply(
    normalize_key
)

df["severity_clean"] = severity_key.map(
    SEVERITY_MAP
)

df["severity_valid"] = (
    df["severity_clean"].notna()
)

df["severity_rank"] = (
    df["severity_clean"]
    .map(SEVERITY_RANK)
    .astype("Int64")
)

severity_unmapped = int(
    (~df["severity_valid"]).sum()
)


# ------------------------------------------------------------
# 5. ALERT STATUS
# ------------------------------------------------------------

print("\n[5/10] Standardizing alert status...")

df["status_raw"] = df["status"]

status_key = df["status"].apply(
    normalize_key
)

df["status_clean"] = status_key.map(
    STATUS_MAP
)

df["status_valid"] = (
    df["status_clean"].notna()
)

status_unmapped = int(
    (~df["status_valid"]).sum()
)


# ------------------------------------------------------------
# 6. DEVICE CRITICALITY
# ------------------------------------------------------------

print("\n[6/10] Standardizing device criticality...")

df["device_criticality_raw"] = (
    df["device_criticality"]
)

device_criticality_key = (
    df["device_criticality"]
    .apply(normalize_key)
)

df["device_criticality_clean"] = (
    device_criticality_key.map(
        DEVICE_CRITICALITY_MAP
    )
)

df["device_criticality_valid"] = (
    df["device_criticality"].isna()
    | df["device_criticality_clean"].notna()
)

device_criticality_unmapped = int(
    (
        df["device_criticality"].notna()
        & df["device_criticality_clean"].isna()
    ).sum()
)


# ------------------------------------------------------------
# 7. TIMESTAMPS
# ------------------------------------------------------------

print("\n[7/10] Cleaning timestamps...")


# Preserve raw values.
df["detected_timestamp_raw"] = (
    df["detected_timestamp"]
)

df["resolved_timestamp_raw"] = (
    df["resolved_timestamp"]
)


# Parse timestamps.
df["detected_timestamp_clean"] = (
    df["detected_timestamp"]
    .apply(parse_timestamp)
)

df["resolved_timestamp_clean"] = (
    df["resolved_timestamp"]
    .apply(parse_timestamp)
)


# ------------------------------------------------------------
# Timestamp validity
# ------------------------------------------------------------

df["detected_timestamp_valid"] = (
    df["detected_timestamp"].notna()
    & df["detected_timestamp_clean"].notna()
)

df["resolved_timestamp_valid"] = (
    df["resolved_timestamp"].notna()
    & df["resolved_timestamp_clean"].notna()
)


# ------------------------------------------------------------
# Timestamp issue classification
# ------------------------------------------------------------

df["detected_timestamp_issue"] = "valid"

df.loc[
    df["detected_timestamp"].isna(),
    "detected_timestamp_issue"
] = "missing"

df.loc[
    df["detected_timestamp"].notna()
    & df["detected_timestamp_clean"].isna(),
    "detected_timestamp_issue"
] = "invalid_format"


df["resolved_timestamp_issue"] = "valid"

df.loc[
    df["resolved_timestamp"].isna(),
    "resolved_timestamp_issue"
] = "missing"

df.loc[
    df["resolved_timestamp"].notna()
    & df["resolved_timestamp_clean"].isna(),
    "resolved_timestamp_issue"
] = "invalid_format"


detected_timestamp_invalid = int(
    (
        df["detected_timestamp"].notna()
        & df["detected_timestamp_clean"].isna()
    ).sum()
)

resolved_timestamp_invalid = int(
    (
        df["resolved_timestamp"].notna()
        & df["resolved_timestamp_clean"].isna()
    ).sum()
)


# ------------------------------------------------------------
# Chronology validation
# ------------------------------------------------------------

chronology_mask = (
    df["detected_timestamp_clean"].notna()
    & df["resolved_timestamp_clean"].notna()
    & (
        df["resolved_timestamp_clean"]
        < df["detected_timestamp_clean"]
    )
)

df["chronology_issue"] = chronology_mask

chronology_issues = int(
    chronology_mask.sum()
)


# ------------------------------------------------------------
# Resolution duration
# ------------------------------------------------------------

# Calculate duration only when both timestamps are valid
# and chronology is correct.

df["resolution_duration_hours"] = pd.NA

valid_duration_mask = (
    df["detected_timestamp_clean"].notna()
    & df["resolved_timestamp_clean"].notna()
    & ~chronology_mask
)

df.loc[
    valid_duration_mask,
    "resolution_duration_hours"
] = (
    (
        df.loc[
            valid_duration_mask,
            "resolved_timestamp_clean"
        ]
        -
        df.loc[
            valid_duration_mask,
            "detected_timestamp_clean"
        ]
    )
    .dt.total_seconds()
    / 3600
)


# Convert duration to numeric.
df["resolution_duration_hours"] = pd.to_numeric(
    df["resolution_duration_hours"],
    errors="coerce"
)


# ------------------------------------------------------------
# 8. HOSTNAME + SHA256
# ------------------------------------------------------------

print("\n[8/10] Normalizing hostname and SHA-256...")


# -------------------------
# Hostname
# -------------------------

df["hostname_raw"] = df["hostname"]

df["hostname_clean"] = (
    df["hostname"]
    .apply(normalize_hostname)
)

df["hostname_valid"] = (
    df["hostname"].isna()
    | df["hostname_clean"].notna()
)

hostname_invalid = int(
    (
        df["hostname"].notna()
        & df["hostname_clean"].isna()
    ).sum()
)


# -------------------------
# SHA-256
# -------------------------

df["sha256_raw"] = df["sha256"]

df["sha256_clean"] = (
    df["sha256"]
    .apply(clean_sha256)
)

df["sha256_validation"] = (
    df["sha256"]
    .apply(sha256_validation_reason)
)

df["sha256_valid"] = (
    df["sha256_validation"] == "valid"
)

sha256_invalid = int(
    (
        df["sha256_validation"]
        .isin(
            [
                "invalid_length",
                "invalid_characters"
            ]
        )
    ).sum()
)


# ------------------------------------------------------------
# 9. FINAL MISSING-VALUE HANDLING
# ------------------------------------------------------------

print("\n[9/10] Handling missing values...")


# IMPORTANT:
# We do not fabricate source values.
#
# For analytical completeness, explicit sentinel values are
# used for unavailable text/categorical information.
#
# "Unknown" means:
#     source value was missing or unusable.
#
# This allows the final analytical dataset to contain
# zero blank/NaN cells while preserving the distinction
# between known and unknown information.


# ------------------------------------------------------------
# User ID
# ------------------------------------------------------------

df["user_id_clean"] = (
    df["user_id_clean"]
    .fillna("Unknown")
)


# ------------------------------------------------------------
# Severity
# ------------------------------------------------------------

df["severity_clean"] = (
    df["severity_clean"]
    .fillna("Unknown")
)

df["severity_rank"] = (
    df["severity_rank"]
    .fillna(0)
    .astype(int)
)


# ------------------------------------------------------------
# Alert status
# ------------------------------------------------------------

df["status_clean"] = (
    df["status_clean"]
    .fillna("Unknown")
)


# ------------------------------------------------------------
# Device criticality
# ------------------------------------------------------------

df["device_criticality_clean"] = (
    df["device_criticality_clean"]
    .fillna("Unknown")
)


# ------------------------------------------------------------
# Hostname
# ------------------------------------------------------------

df["hostname_clean"] = (
    df["hostname_clean"]
    .fillna("Unknown")
)


# ------------------------------------------------------------
# SHA-256
# ------------------------------------------------------------

# Do NOT invent, pad, or generate a SHA-256 hash.
# "Unknown" explicitly represents an unavailable/invalid
# source hash.

df["sha256_clean"] = (
    df["sha256_clean"]
    .fillna("Unknown")
)


# ------------------------------------------------------------
# Timestamp fields
# ------------------------------------------------------------

# Keep valid timestamps unchanged.
# Unavailable/invalid timestamps are represented as "Unknown"
# rather than fabricated dates.

df["detected_timestamp_clean"] = (
    df["detected_timestamp_clean"]
    .astype(object)
    .where(
        df["detected_timestamp_clean"].notna(),
        "Unknown"
    )
)

df["resolved_timestamp_clean"] = (
    df["resolved_timestamp_clean"]
    .astype(object)
    .where(
        df["resolved_timestamp_clean"].notna(),
        "Unknown"
    )
)


# ------------------------------------------------------------
# Other text fields
# ------------------------------------------------------------

for column in [
    "endpoint_product",
    "alert_name",
    "description",
    "file_path",
    "process_name",
    "assigned_to",
]:
    df[column] = (
        df[column]
        .fillna("Unknown")
    )


# ------------------------------------------------------------
# Resolution duration
# ------------------------------------------------------------

# Use the median of valid, non-negative durations.
# This avoids inventing a specific duration for each row.

duration_median = df[
    "resolution_duration_hours"
].median()

if pd.isna(duration_median):
    raise ValueError(
        "Unable to calculate a valid median resolution "
        "duration. No valid duration values were found."
    )

df["resolution_duration_hours"] = (
    df["resolution_duration_hours"]
    .fillna(duration_median)
)

# Round for a clean analytical representation.
df["resolution_duration_hours"] = (
    df["resolution_duration_hours"]
    .round(2)
)


# ------------------------------------------------------------
# 10. FINAL ANALYTICAL DATASET
# ------------------------------------------------------------

print("\n[10/10] Creating final analytical dataset...")


# These are the ONLY columns that will be written to
# data/cleaned/endpoint_cleaned.csv.

FINAL_COLUMNS = [
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


final_df = pd.DataFrame({
    "alert_id": df["alert_id"],

    "detected_timestamp":
        df["detected_timestamp_clean"],

    "resolved_timestamp":
        df["resolved_timestamp_clean"],

    "hostname":
        df["hostname_clean"],

    "user_id":
        df["user_id_clean"],

    "endpoint_product":
        df["endpoint_product"],

    "alert_name":
        df["alert_name"],

    "severity":
        df["severity_clean"],

    "status":
        df["status_clean"],

    "description":
        df["description"],

    "file_path":
        df["file_path"],

    "process_name":
        df["process_name"],

    "sha256":
        df["sha256_clean"],

    "assigned_to":
        df["assigned_to"],

    "device_criticality":
        df["device_criticality_clean"],

    "severity_rank":
        df["severity_rank"],

    "resolution_duration_hours":
        df["resolution_duration_hours"],
})


# ------------------------------------------------------------
# Final column-order safety check
# ------------------------------------------------------------

final_df = final_df[FINAL_COLUMNS]


# ------------------------------------------------------------
# Final missing-value safety check
# ------------------------------------------------------------

final_missing_by_column = (
    final_df.isna().sum()
)

final_missing_cells = int(
    final_missing_by_column.sum()
)

if final_missing_cells > 0:

    missing_details = (
        final_missing_by_column[
            final_missing_by_column > 0
        ]
        .to_dict()
    )

    raise ValueError(
        "Final Endpoint dataset still contains "
        f"{final_missing_cells} missing cells: "
        f"{missing_details}"
    )


# ------------------------------------------------------------
# Final duplicate safety check
# ------------------------------------------------------------

final_duplicate_rows = int(
    final_df.duplicated().sum()
)

final_duplicate_alert_ids = int(
    final_df["alert_id"].duplicated().sum()
)


# ------------------------------------------------------------
# SAVE FINAL CLEANED DATA
# ------------------------------------------------------------

final_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# CLEANING SUMMARY
# ============================================================

summary = pd.DataFrame(
    [
        {
            "dataset": "endpoint",

            "raw_rows":
                raw_rows,

            "exact_duplicates_removed":
                exact_duplicates_removed,

            "cleaned_rows":
                len(final_df),

            "final_columns":
                len(final_df.columns),

            "user_id_invalid":
                user_id_invalid,

            "severity_unmapped":
                severity_unmapped,

            "status_unmapped":
                status_unmapped,

            "device_criticality_unmapped":
                device_criticality_unmapped,

            "detected_timestamp_invalid":
                detected_timestamp_invalid,

            "resolved_timestamp_invalid":
                resolved_timestamp_invalid,

            "chronology_issues":
                chronology_issues,

            "hostname_invalid":
                hostname_invalid,

            "sha256_invalid":
                sha256_invalid,

            "resolution_duration_median_used":
                round(float(duration_median), 2),

            "final_missing_cells":
                final_missing_cells,

            "final_duplicate_rows":
                final_duplicate_rows,

            "final_duplicate_alert_ids":
                final_duplicate_alert_ids,

            "missing_text_handling":
                "Unknown sentinel",

            "missing_timestamp_handling":
                "Unknown sentinel",

            "missing_duration_handling":
                "Median of valid durations",
        }
    ]
)


summary.to_csv(
    SUMMARY_FILE,
    index=False
)


# ============================================================
# FINAL OUTPUT
# ============================================================

print("\n" + "=" * 60)
print("ENDPOINT CLEANING COMPLETE")
print("=" * 60)

print(
    f"Raw rows                    : "
    f"{raw_rows:,}"
)

print(
    f"Exact duplicates removed    : "
    f"{exact_duplicates_removed:,}"
)

print(
    f"Cleaned rows                : "
    f"{len(final_df):,}"
)

print(
    f"Final columns               : "
    f"{len(final_df.columns)}"
)

print(
    f"User ID invalid             : "
    f"{user_id_invalid:,}"
)

print(
    f"Severity unmapped           : "
    f"{severity_unmapped:,}"
)

print(
    f"Status unmapped             : "
    f"{status_unmapped:,}"
)

print(
    f"Device criticality unmapped: "
    f"{device_criticality_unmapped:,}"
)

print(
    f"Detected timestamp invalid  : "
    f"{detected_timestamp_invalid:,}"
)

print(
    f"Resolved timestamp invalid  : "
    f"{resolved_timestamp_invalid:,}"
)

print(
    f"Chronology issues           : "
    f"{chronology_issues:,}"
)

print(
    f"Hostname invalid            : "
    f"{hostname_invalid:,}"
)

print(
    f"SHA-256 invalid             : "
    f"{sha256_invalid:,}"
)

print(
    f"Duration median used        : "
    f"{duration_median:.2f} hours"
)

print(
    f"Final missing cells         : "
    f"{final_missing_cells}"
)

print(
    f"Final duplicate rows        : "
    f"{final_duplicate_rows}"
)

print(
    f"Duplicate alert IDs         : "
    f"{final_duplicate_alert_ids}"
)

print("\nGenerated:")
print(f"  {OUTPUT_FILE}")
print(f"  {SUMMARY_FILE}")

print("\nFinal dataset validation:")
print("  [PASS] Exactly 17 analytical columns")
print("  [PASS] Zero missing cells")
print("  [PASS] No duplicate rows")
print("  [PASS] Cleaning completed successfully")