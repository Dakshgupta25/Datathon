from pathlib import Path
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = ROOT / "data" / "raw" / "track2_identity_asset_master.csv"
CLEANED_DIR = ROOT / "data" / "cleaned"
REPORT_DIR = ROOT / "reports"

CLEANED_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = CLEANED_DIR / "identity_cleaned.csv"
SUMMARY_FILE = REPORT_DIR / "identity_cleaning_summary.csv"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_key(value):
    """
    Normalize text before controlled mapping.

    Only superficial formatting differences are removed:
    - leading/trailing spaces
    - repeated whitespace
    - underscores
    - hyphens
    - case differences

    No fuzzy matching is performed.
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
    Convert equivalent user ID representations into:

        EMP12345

    Examples:
        EMP12345
        emp12345
        EMP-12345
        EMP 12345
        12345

    become:

        EMP12345
    """

    if pd.isna(value):
        return None

    value = str(value).strip().upper()

    if not value:
        return None

    value = re.sub(r"[\s\-_]+", "", value)

    if value.isdigit():
        value = "EMP" + value

    if re.fullmatch(r"EMP\d+", value):
        return value

    return None


def normalize_username(value):
    """
    Normalize usernames conservatively.

    We do not attempt to infer or reconstruct missing usernames.
    """

    if pd.isna(value):
        return None

    value = str(value).strip().lower()

    if not value:
        return None

    return value


def normalize_hostname(value):
    """
    Normalize hostname representations.

    Examples:
        ws-123
        WS_123
        ws-123.corp.local

    become:

        WS-123
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


def normalize_manager_username(value):
    """
    Normalize manager usernames without inventing missing values.
    """

    if pd.isna(value):
        return None

    value = str(value).strip().lower()

    if not value:
        return None

    return value


def normalize_device_id(value):
    """
    Normalize device IDs conservatively.

    Only whitespace/case formatting is standardized.
    """

    if pd.isna(value):
        return None

    value = str(value).strip().upper()

    if not value:
        return None

    value = re.sub(r"\s+", "", value)

    return value


def normalize_location(value):
    """
    Normalize location text conservatively.

    We do not merge locations based on assumptions.
    """

    if pd.isna(value):
        return None

    value = str(value).strip()

    if not value:
        return None

    value = re.sub(r"\s+", " ", value)

    return value


# ============================================================
# DATE PARSER
# ============================================================

def parse_identity_date(value):
    """
    Parse Identity date values.

    Supported:
    1. Semantic missing values
    2. Unix epoch timestamps in seconds
    3. Common textual date/datetime formats
    4. Pandas mixed-format fallback

    Raw values are preserved separately.

    No date is fabricated or inferred.
    """

    if pd.isna(value):
        return pd.NaT

    value_str = str(value).strip()

    if not value_str:
        return pd.NaT

    # --------------------------------------------------------
    # Semantic missing values
    # --------------------------------------------------------

    semantic_missing = {
        "not available",
        "not_available",
        "n/a",
        "na",
        "none",
        "null",
        "unknown",
        "-",
    }

    if value_str.lower() in semantic_missing:
        return pd.NaT

    # --------------------------------------------------------
    # Unix epoch seconds
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
    # Explicit textual formats
    # --------------------------------------------------------

    formats = [
        # ISO-like
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",

        # YYYY/MM/DD
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",

        # DD-MM-YYYY
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",

        # DD/MM/YYYY
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",

        # MM/DD/YYYY
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",

        # MM-DD-YYYY AM/PM
        "%m-%d-%Y %I:%M:%S %p",
        "%m-%d-%Y %I:%M %p",

        # MM/DD/YYYY AM/PM
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %I:%M %p",

        # Textual month
        "%d-%b-%Y %H:%M:%S",
        "%d-%b-%Y %H:%M",

        "%d-%b-%Y %I:%M:%S %p",
        "%d-%b-%Y %I:%M %p",

        # Date-only
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
    # Mixed-format fallback
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


def date_issue_reason(value):
    """
    Classify date values for auditability.
    """

    if pd.isna(value):
        return "missing"

    value_str = str(value).strip()

    if not value_str:
        return "missing"

    semantic_missing = {
        "not available",
        "not_available",
        "n/a",
        "na",
        "none",
        "null",
        "unknown",
        "-",
    }

    if value_str.lower() in semantic_missing:
        return "semantic_missing"

    parsed = parse_identity_date(value)

    if pd.isna(parsed):
        return "invalid_format"

    if re.fullmatch(r"\d{10}", value_str):
        return "unix_epoch"

    return "valid"


# ============================================================
# CONTROLLED DEPARTMENT MAPPING
# ============================================================

DEPARTMENT_MAP = {

    # IT
    "IT": "IT",
    "IT DEPT": "IT",
    "INFORMATION TECHNOLOGY": "IT",
    "INFORMATION TECH": "IT",

    # Human Resources
    "HR": "Human Resources",
    "HR DEPT": "Human Resources",
    "HUMAN RESOURCE": "Human Resources",
    "HUMAN RESOURCES": "Human Resources",
    "PEOPLE TEAM": "Human Resources",

    # Finance
    "FINANCE": "Finance",
    "FIN": "Finance",
    "FINANCE DEPT": "Finance",
    "ACCOUNTS": "Finance",

    # Operations
    "OPS": "Operations",
    "OPS TEAM": "Operations",
    "OPERATIONS": "Operations",
    "OPERATIONS DEPT": "Operations",

    # Procurement
    "PURCHASE": "Procurement",
    "PURCH": "Procurement",
    "PROCUREMENT": "Procurement",
    "PROCUREMENT TEAM": "Procurement",

    # Marketing
    "MKT": "Marketing",
    "MKTG": "Marketing",
    "MARKETING": "Marketing",
    "MARKETING DEPT": "Marketing",

    # Sales
    "SALES": "Sales",
    "SALES TEAM": "Sales",
    "SALES DEPT": "Sales",
    "BUSINESS SALES": "Sales",

    # Legal
    "LEGAL": "Legal",
    "LEGAL DEPT": "Legal",

    # Research & Development
    "R&D": "R&D",
    "RD": "R&D",
    "RND": "R&D",
    "RESEARCH AND DEVELOPMENT": "R&D",

    # Customer Support
    "CS": "Customer Support",
    "CUSTOMER CARE": "Customer Support",
    "CUSTOMER SUPPORT": "Customer Support",

    # Other explicit organizational categories
    "SUPPORT": "Support",
    "CALL CENTER": "Call Center",
    "BRAND TEAM": "Brand",
    "COMPLIANCE": "Compliance",
    "INNOVATION": "Innovation",
    "SUPPLY CHAIN": "Supply Chain",
    "IT SUPPORT": "IT Support",
}


# ============================================================
# CONTROLLED STATUS MAPPING
# ============================================================

STATUS_MAP = {

    # Active
    "LIVE": "Active",
    "ACTIVE": "Active",
    "A": "Active",
    "WORKING": "Active",
    "ENABLED": "Active",

    # Disabled
    "DISABLED": "Disabled",
    "DEACTIVATED": "Disabled",
    "D": "Disabled",

    # Terminated
    "EXITED": "Terminated",
    "LEFT": "Terminated",
    "TERMINATED": "Terminated",
    "RESIGNED": "Terminated",

    # On leave
    "LEAVE": "On Leave",
    "ON LEAVE": "On Leave",
    "ON_LEAVE": "On Leave",
    "L": "On Leave",
    "LWP": "On Leave",
    "OOO": "On Leave",

    # Preserve as distinct account state
    "BLOCKED": "Blocked",
}


# ============================================================
# MAIN PIPELINE
# ============================================================

print("=" * 60)
print("IDENTITY DATA CLEANING PIPELINE")
print("=" * 60)


# ------------------------------------------------------------
# 1. LOAD
# ------------------------------------------------------------

print("\n[1/10] Loading raw identity data...")

df = pd.read_csv(RAW_FILE)

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
# 3. USER ID + USERNAME
# ------------------------------------------------------------

print("\n[3/10] Cleaning user IDs and usernames...")

df["user_id_raw"] = df["user_id"]

df["user_id_clean"] = (
    df["user_id"].apply(normalize_user_id)
)

df["user_id_valid"] = (
    df["user_id"].isna()
    | df["user_id_clean"].notna()
)

user_id_invalid = int(
    (
        df["user_id"].notna()
        & df["user_id_clean"].isna()
    ).sum()
)


df["username_raw"] = df["username"]

df["username_clean"] = (
    df["username"].apply(normalize_username)
)

df["username_valid"] = (
    df["username"].isna()
    | df["username_clean"].notna()
)

username_invalid = int(
    (
        df["username"].notna()
        & df["username_clean"].isna()
    ).sum()
)


# ------------------------------------------------------------
# 4. DEPARTMENT
# ------------------------------------------------------------

print("\n[4/10] Standardizing departments...")

df["department_raw"] = df["department"]

department_key = (
    df["department"].apply(normalize_key)
)

df["department_clean"] = (
    department_key.map(DEPARTMENT_MAP)
)

df["department_valid"] = (
    df["department"].isna()
    | df["department_clean"].notna()
)

department_unmapped = int(
    (
        df["department"].notna()
        & df["department_clean"].isna()
    ).sum()
)


# ------------------------------------------------------------
# 5. STATUS
# ------------------------------------------------------------

print("\n[5/10] Standardizing employee status...")

df["status_raw"] = df["status"]

status_key = (
    df["status"].apply(normalize_key)
)

df["status_clean"] = (
    status_key.map(STATUS_MAP)
)

df["status_valid"] = (
    df["status"].isna()
    | df["status_clean"].notna()
)

status_unmapped = int(
    (
        df["status"].notna()
        & df["status_clean"].isna()
    ).sum()
)


# ------------------------------------------------------------
# 6. HOSTNAME / DEVICE / LOCATION
# ------------------------------------------------------------

print("\n[6/10] Normalizing hostname, device ID and location...")

# Hostname
df["hostname_raw"] = df["hostname"]

df["hostname_clean"] = (
    df["hostname"].apply(normalize_hostname)
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


# Device ID
df["device_id_raw"] = df["device_id"]

df["device_id_clean"] = (
    df["device_id"].apply(normalize_device_id)
)


# Location
df["location_raw"] = df["location"]

df["location_clean"] = (
    df["location"].apply(normalize_location)
)


# Manager username
df["manager_username_raw"] = (
    df["manager_username"]
)

df["manager_username_clean"] = (
    df["manager_username"]
    .apply(normalize_manager_username)
)


# ------------------------------------------------------------
# 7. DATES
# ------------------------------------------------------------

print("\n[7/10] Cleaning hire and termination dates...")


# Preserve raw values.
df["hire_date_raw"] = df["hire_date"]

df["termination_date_raw"] = (
    df["termination_date"]
)


# Parse.
df["hire_date_clean"] = (
    df["hire_date"].apply(parse_identity_date)
)

df["termination_date_clean"] = (
    df["termination_date"]
    .apply(parse_identity_date)
)


# Issue classification.
df["hire_date_issue"] = (
    df["hire_date"].apply(date_issue_reason)
)

df["termination_date_issue"] = (
    df["termination_date"]
    .apply(date_issue_reason)
)


# Validity.
df["hire_date_valid"] = (
    df["hire_date"].isna()
    | df["hire_date_clean"].notna()
)

df["termination_date_valid"] = (
    df["termination_date"].isna()
    | df["termination_date_clean"].notna()
)


hire_date_invalid = int(
    (
        df["hire_date"].notna()
        & df["hire_date_clean"].isna()
        & ~df["hire_date_issue"].eq(
            "semantic_missing"
        )
    ).sum()
)

termination_date_invalid = int(
    (
        df["termination_date"].notna()
        & df["termination_date_clean"].isna()
        & ~df["termination_date_issue"].eq(
            "semantic_missing"
        )
    ).sum()
)


# ------------------------------------------------------------
# 8. DATE / STATUS SEMANTIC VALIDATION
# ------------------------------------------------------------

print("\n[8/10] Validating date/status consistency...")


# Terminated employees should normally have a termination date.
terminated_missing_date = int(
    (
        df["status_clean"].eq("Terminated")
        & df["termination_date_clean"].isna()
    ).sum()
)


# Active employees should normally NOT have a termination date.
active_with_termination_date = int(
    (
        df["status_clean"].eq("Active")
        & df["termination_date_clean"].notna()
    ).sum()
)


# Hire date after termination date is a chronology anomaly.
hire_after_termination = int(
    (
        df["hire_date_clean"].notna()
        & df["termination_date_clean"].notna()
        & (
            df["hire_date_clean"]
            > df["termination_date_clean"]
        )
    ).sum()
)


df["termination_date_status_issue"] = "none"

df.loc[
    (
        df["status_clean"].eq("Terminated")
        & df["termination_date_clean"].isna()
    ),
    "termination_date_status_issue"
] = "terminated_missing_date"

df.loc[
    (
        df["status_clean"].eq("Active")
        & df["termination_date_clean"].notna()
    ),
    "termination_date_status_issue"
] = "active_with_termination_date"

df.loc[
    (
        df["hire_date_clean"].notna()
        & df["termination_date_clean"].notna()
        & (
            df["hire_date_clean"]
            > df["termination_date_clean"]
        )
    ),
    "termination_date_status_issue"
] = "hire_after_termination"


# ------------------------------------------------------------
# 9. SEMANTIC MISSING VALUES
# ------------------------------------------------------------

print("\n[9/10] Preserving semantic missing values...")

# No arbitrary imputation is performed.
#
# Examples:
# - Active employees can legitimately have no termination date.
# - Manager may be missing.
# - Device ID may be missing.
# - Location may be missing.
# - Hostname may be missing.
# - Username may be missing.
#
# "not available" in termination_date is treated as
# semantic missing rather than an invented date.


# ------------------------------------------------------------
# 10. SAVE
# ------------------------------------------------------------

print("\n[10/10] Saving cleaned data and summary...")


df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# CLEANING SUMMARY
# ============================================================

summary = pd.DataFrame(
    [
        {
            "dataset": "identity",
            "raw_rows": raw_rows,
            "exact_duplicates_removed":
                exact_duplicates_removed,
            "cleaned_rows": len(df),

            "user_id_invalid":
                user_id_invalid,

            "username_invalid":
                username_invalid,

            "department_unmapped":
                department_unmapped,

            "status_unmapped":
                status_unmapped,

            "hostname_invalid":
                hostname_invalid,

            "hire_date_invalid":
                hire_date_invalid,

            "termination_date_invalid":
                termination_date_invalid,

            "terminated_missing_termination_date":
                terminated_missing_date,

            "active_with_termination_date":
                active_with_termination_date,

            "hire_after_termination":
                hire_after_termination,
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
print("IDENTITY CLEANING COMPLETE")
print("=" * 60)

print(f"Raw rows                 : {raw_rows:,}")

print(
    f"Exact duplicates removed : "
    f"{exact_duplicates_removed:,}"
)

print(f"Cleaned rows             : {len(df):,}")

print(
    f"User ID invalid          : "
    f"{user_id_invalid:,}"
)

print(
    f"Username invalid         : "
    f"{username_invalid:,}"
)

print(
    f"Department unmapped      : "
    f"{department_unmapped:,}"
)

print(
    f"Status unmapped          : "
    f"{status_unmapped:,}"
)

print(
    f"Hostname invalid         : "
    f"{hostname_invalid:,}"
)

print(
    f"Hire date invalid        : "
    f"{hire_date_invalid:,}"
)

print(
    f"Termination date invalid : "
    f"{termination_date_invalid:,}"
)

print(
    f"Terminated + missing termination date : "
    f"{terminated_missing_date:,}"
)

print(
    f"Active + termination date             : "
    f"{active_with_termination_date:,}"
)

print(
    f"Hire date after termination date      : "
    f"{hire_after_termination:,}"
)

print("\nGenerated:")
print(f"  {OUTPUT_FILE}")
print(f"  {SUMMARY_FILE}")