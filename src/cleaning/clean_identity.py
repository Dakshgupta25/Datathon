"""
Identity Master Data Cleaning Pipeline
--------------------------------------

Phase 1 + Phase 2
Datathon - Track 2: Zero-Trust Telemetry & Insider Threat Logs

Purpose:
    Clean and standardize the Identity Master dataset while preserving
    reproducibility, auditability, and analytical usability.

Key principles:
    1. Raw data is never modified.
    2. Exact duplicate rows are removed.
    3. User IDs, departments, statuses, hostnames and other categorical
       fields are standardized using explicit mappings.
    4. Dates are parsed from supported formats, including Unix epoch
       timestamps where applicable.
    5. Invalid source values are not fabricated.
    6. Final analytical output contains zero missing cells using
       documented semantic sentinel values.
    7. Only the final 12 analytical columns are written to the cleaned file.

Final output:
    data/cleaned/identity_cleaned.csv
"""

from pathlib import Path
import re
import pandas as pd
import numpy as np


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = PROJECT_ROOT / "data" / "raw" / "track2_identity_asset_master.csv"
OUTPUT_FILE = PROJECT_ROOT / "data" / "cleaned" / "identity_cleaned.csv"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_text(value):
    """
    Basic text normalization.

    Returns:
        Cleaned string or NaN when the source value is missing.
    """
    if pd.isna(value):
        return np.nan

    value = str(value).strip()

    if value == "":
        return np.nan

    return value


def normalize_upper(value):
    """
    Normalize text to uppercase.
    """
    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    return value.upper()


def normalize_lower(value):
    """
    Normalize text to lowercase.
    """
    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    return value.lower()


def normalize_user_id(value):
    """
    Standardize user IDs.

    Supported examples:
        EMP12345
        emp12345
        EMP-12345
        EMP 12345
        numeric-only IDs

    Canonical format:
        EMP12345
    """

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = value.upper().strip()

    # Remove separators
    value = re.sub(r"[\s\-_]+", "", value)

    # Numeric-only IDs
    if value.isdigit():
        return "EMP" + value

    # EMP-prefixed IDs
    if value.startswith("EMP"):
        numeric_part = value[3:]

        if numeric_part.isdigit():
            return "EMP" + numeric_part

    return np.nan


def normalize_username(value):
    """
    Standardize usernames.
    """
    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    return value.lower()


def normalize_hostname(value):
    """
    Canonical hostname representation.

    Rules:
        - trim whitespace
        - uppercase
        - replace underscores with hyphens
        - remove .corp.local suffix
    """

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = value.strip().upper()

    value = value.replace("_", "-")

    if value.endswith(".CORP.LOCAL"):
        value = value[:-10]

    return value


def normalize_device_id(value):
    """
    Standardize device identifiers.
    """
    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    return value.strip().upper()


def normalize_location(value):
    """
    Standardize location text.
    """
    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    return re.sub(r"\s+", " ", value).strip()


# ============================================================
# DATE PARSER
# ============================================================

def parse_identity_date(value):
    """
    Parse identity date values from supported formats.

    Supported:
        - normal date strings
        - ISO timestamps
        - common textual date formats
        - Unix epoch seconds

    Invalid/unparseable values return NaT.

    No dates are fabricated.
    """

    if pd.isna(value):
        return pd.NaT

    value_str = str(value).strip()

    if value_str == "":
        return pd.NaT

    lower_value = value_str.lower()

    semantic_missing = {
        "na",
        "n/a",
        "none",
        "null",
        "nan",
        "not available",
        "not_available",
        "unknown",
        "missing",
        "not applicable",
        "not_applicable",
    }

    if lower_value in semantic_missing:
        return pd.NaT

    # --------------------------------------------------------
    # Unix epoch seconds
    # --------------------------------------------------------

    if re.fullmatch(r"\d{10}", value_str):
        try:
            return pd.to_datetime(
                int(value_str),
                unit="s",
                errors="coerce"
            )
        except Exception:
            return pd.NaT

    # --------------------------------------------------------
    # Numeric Excel-style serial dates
    # --------------------------------------------------------

    if re.fullmatch(r"\d{5}", value_str):
        try:
            numeric_value = float(value_str)

            # Excel serial dates are generally around this range.
            if 20000 <= numeric_value <= 60000:
                return pd.Timestamp("1899-12-30") + pd.to_timedelta(
                    numeric_value,
                    unit="D"
                )
        except Exception:
            pass

    # --------------------------------------------------------
    # Explicit formats
    # --------------------------------------------------------

    formats = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%m-%d-%Y",
        "%m/%d/%Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m-%d-%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M",
        "%d-%b-%Y",
        "%d-%B-%Y",
        "%b %d, %Y",
        "%B %d, %Y",
    ]

    for fmt in formats:
        try:
            parsed = pd.to_datetime(
                value_str,
                format=fmt,
                errors="coerce"
            )

            if not pd.isna(parsed):
                return parsed
        except Exception:
            continue

    # --------------------------------------------------------
    # Final fallback
    # --------------------------------------------------------

    try:
        return pd.to_datetime(
          value_str,
          errors="coerce",
          format="mixed"
      )
    except Exception:
        return pd.NaT


# ============================================================
# DEPARTMENT STANDARDIZATION
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

    # R&D
    "R&D": "R&D",
    "RD": "R&D",
    "RND": "R&D",
    "RESEARCH AND DEVELOPMENT": "R&D",

    # Operations
    "OPS": "Operations",
    "OPS TEAM": "Operations",
    "OPERATIONS": "Operations",
    "OPERATIONS DEPT": "Operations",

    # Marketing
    "MKT": "Marketing",
    "MKTG": "Marketing",
    "MARKETING": "Marketing",
    "MARKETING DEPT": "Marketing",

    # Finance
    "FINANCE": "Finance",
    "FIN": "Finance",
    "FINANCE DEPT": "Finance",
    "ACCOUNTS": "Finance",

    # Procurement
    "PURCHASE": "Procurement",
    "PURCH": "Procurement",
    "PROCUREMENT": "Procurement",
    "PROCUREMENT TEAM": "Procurement",

    # Legal
    "LEGAL": "Legal",
    "LEGAL DEPT": "Legal",

    # Sales
    "SALES": "Sales",
    "SALES TEAM": "Sales",
    "SALES DEPT": "Sales",
    "BUSINESS SALES": "Sales",

    # Customer Support
    "CS": "Customer Support",
    "CUSTOMER CARE": "Customer Support",
    "CUSTOMER SUPPORT": "Customer Support",

    # Other known canonical departments
    "SUPPORT": "Support",
    "IT SUPPORT": "IT Support",
    "BRAND TEAM": "Brand",
    "BRAND": "Brand",
    "COMPLIANCE": "Compliance",
    "INNOVATION": "Innovation",
    "SUPPLY CHAIN": "Supply Chain",
    "CALL CENTER": "Call Center",
}


def standardize_department(value):
    """
    Standardize department using an explicit controlled mapping.
    """

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    key = re.sub(r"\s+", " ", value.strip()).upper()

    return DEPARTMENT_MAP.get(key, np.nan)


# ============================================================
# STATUS STANDARDIZATION
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

    # Leave
    "LEAVE": "On Leave",
    "ON LEAVE": "On Leave",
    "ON_LEAVE": "On Leave",
    "LWP": "On Leave",
    "OOO": "On Leave",
    "L": "On Leave",

    # Blocked
    "BLOCKED": "Blocked",
}


def standardize_status(value):
    """
    Standardize employee status using an explicit mapping.
    """

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    key = re.sub(r"\s+", " ", value.strip()).upper()

    return STATUS_MAP.get(key, np.nan)


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    print("=" * 60)
    print("IDENTITY DATA CLEANING PIPELINE")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. Load
    # --------------------------------------------------------

    print("\n[1/10] Loading raw identity data...")

    df = pd.read_csv(
        RAW_FILE,
        low_memory=False
    )

    raw_rows = len(df)

    print(f"Raw rows loaded: {raw_rows:,}")

    # --------------------------------------------------------
    # 2. Remove exact duplicate rows
    # --------------------------------------------------------

    print("\n[2/10] Removing exact duplicate rows...")

    duplicate_mask = df.duplicated(
        keep="first"
    )

    exact_duplicates_removed = int(
        duplicate_mask.sum()
    )

    df = df.drop_duplicates(
        keep="first"
    ).copy()

    print(
        f"Exact duplicate rows removed: "
        f"{exact_duplicates_removed:,}"
    )

    print(
        f"Rows remaining: {len(df):,}"
    )

    # --------------------------------------------------------
    # 3. User IDs and usernames
    # --------------------------------------------------------

    print(
        "\n[3/10] Cleaning user IDs and usernames..."
    )

    df["user_id_clean"] = (
        df["user_id"]
        .apply(normalize_user_id)
    )

    df["username_clean"] = (
        df["username"]
        .apply(normalize_username)
    )

    user_id_invalid = int(
        df["user_id_clean"].isna().sum()
    )

    # --------------------------------------------------------
    # 4. Departments
    # --------------------------------------------------------

    print(
        "\n[4/10] Standardizing departments..."
    )

    df["department_clean"] = (
        df["department"]
        .apply(standardize_department)
    )

    department_unmapped = int(
        df["department_clean"].isna().sum()
    )

    # --------------------------------------------------------
    # 5. Employee status
    # --------------------------------------------------------

    print(
        "\n[5/10] Standardizing employee status..."
    )

    df["status_clean"] = (
        df["status"]
        .apply(standardize_status)
    )

    status_unmapped = int(
        df["status_clean"].isna().sum()
    )

    # --------------------------------------------------------
    # 6. Hostname, device ID and location
    # --------------------------------------------------------

    print(
        "\n[6/10] Normalizing hostname, device ID "
        "and location..."
    )

    df["hostname_clean"] = (
        df["hostname"]
        .apply(normalize_hostname)
    )

    df["device_id_clean"] = (
        df["device_id"]
        .apply(normalize_device_id)
    )

    df["location_clean"] = (
        df["location"]
        .apply(normalize_location)
    )

    # --------------------------------------------------------
    # Manager username
    # --------------------------------------------------------

    df["manager_username_clean"] = (
        df["manager_username"]
        .apply(normalize_username)
    )

    # --------------------------------------------------------
    # 7. Hire and termination dates
    # --------------------------------------------------------

    print(
        "\n[7/10] Cleaning hire and termination dates..."
    )

    df["hire_date_clean"] = (
        df["hire_date"]
        .apply(parse_identity_date)
    )

    df["termination_date_clean"] = (
        df["termination_date"]
        .apply(parse_identity_date)
    )

    hire_date_invalid = int(
        (
            df["hire_date"].notna()
            & df["hire_date_clean"].isna()
        ).sum()
    )

    termination_date_invalid = int(
        (
            df["termination_date"].notna()
            & df["termination_date_clean"].isna()
        ).sum()
    )

    # --------------------------------------------------------
    # 8. Date/status consistency
    # --------------------------------------------------------

    print(
        "\n[8/10] Validating date/status consistency..."
    )

    terminated_mask = (
        df["status_clean"] == "Terminated"
    )

    active_like_mask = df["status_clean"].isin(
        [
            "Active",
            "On Leave",
            "Disabled",
            "Blocked",
        ]
    )

    terminated_missing_date = int(
        (
            terminated_mask
            & df["termination_date_clean"].isna()
        ).sum()
    )

    active_with_termination_date = int(
        (
            active_like_mask
            & df["termination_date_clean"].notna()
        ).sum()
    )

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

    # --------------------------------------------------------
    # 9. Final missing-value handling
    # --------------------------------------------------------

    print(
        "\n[9/10] Handling missing values..."
    )

    # ========================================================
    # IMPORTANT:
    #
    # Final analytical dataset must contain ZERO missing cells.
    #
    # We use semantic sentinel values for unavailable
    # categorical/date information rather than fabricating
    # source values.
    #
    # "Unknown"       = source information unavailable
    # "Not Terminated"= termination date is not applicable
    # ========================================================

    # --------------------------------------------------------
    # Text / categorical fields
    # --------------------------------------------------------

    df["user_id_clean"] = (
        df["user_id_clean"]
        .fillna("Unknown")
    )

    df["username_clean"] = (
        df["username_clean"]
        .fillna("Unknown")
    )

    df["department_clean"] = (
        df["department_clean"]
        .fillna("Unknown")
    )

    df["status_clean"] = (
        df["status_clean"]
        .fillna("Unknown")
    )

    df["manager_username_clean"] = (
        df["manager_username_clean"]
        .fillna("Unknown")
    )

    df["device_id_clean"] = (
        df["device_id_clean"]
        .fillna("Unknown")
    )

    df["location_clean"] = (
        df["location_clean"]
        .fillna("Unknown")
    )

    df["hostname_clean"] = (
        df["hostname_clean"]
        .fillna("Unknown")
    )

    df["full_name"] = (
        df["full_name"]
        .fillna("Unknown")
    )

    df["role"] = (
        df["role"]
        .fillna("Unknown")
    )

    # --------------------------------------------------------
    # Hire date
    # --------------------------------------------------------
    #
    # IMPORTANT:
    # Convert datetime column to object BEFORE inserting
    # the string "Unknown".
    #
    # This prevents pandas from raising:
    #
    # TypeError:
    # Invalid value 'Unknown' for dtype datetime64
    # --------------------------------------------------------

    df["hire_date_clean"] = (
        df["hire_date_clean"]
        .astype(object)
    )

    df["hire_date_clean"] = (
        df["hire_date_clean"]
        .where(
            df["hire_date_clean"].notna(),
            "Unknown"
        )
    )

    # --------------------------------------------------------
    # Termination date
    # --------------------------------------------------------
    #
    # Convert datetime column to object BEFORE mixing
    # Timestamp values with semantic strings.
    # --------------------------------------------------------

    df["termination_date_clean"] = (
        df["termination_date_clean"]
        .astype(object)
    )

    terminated_mask = (
        df["status_clean"] == "Terminated"
    )

    # Non-terminated employees:
    # termination date is not applicable.
    df.loc[
        ~terminated_mask
        & df["termination_date_clean"].isna(),
        "termination_date_clean"
    ] = "Not Terminated"

    # Terminated employees with no date:
    # preserve the fact that the date is unknown.
    df.loc[
        terminated_mask
        & df["termination_date_clean"].isna(),
        "termination_date_clean"
    ] = "Unknown"

    # Safety fallback for any remaining missing values.
    df["termination_date_clean"] = (
        df["termination_date_clean"]
        .fillna("Unknown")
    )

    # --------------------------------------------------------
    # 10. Final analytical output
    # --------------------------------------------------------

    print(
        "\n[10/10] Creating final analytical dataset..."
    )

    final_columns = [
        "user_id_clean",
        "username_clean",
        "department_clean",
        "status_clean",
        "hire_date_clean",
        "termination_date_clean",
        "manager_username_clean",
        "device_id_clean",
        "location_clean",
        "hostname_clean",
        "full_name",
        "role",
    ]

    final_df = df[final_columns].copy()

    # --------------------------------------------------------
    # Rename columns to clean analytical names
    # --------------------------------------------------------

    final_df = final_df.rename(
        columns={
            "user_id_clean": "user_id",
            "username_clean": "username",
            "department_clean": "department",
            "status_clean": "status",
            "hire_date_clean": "hire_date",
            "termination_date_clean": "termination_date",
            "manager_username_clean": "manager_username",
            "device_id_clean": "device_id",
            "location_clean": "location",
            "hostname_clean": "hostname",
        }
    )

    # --------------------------------------------------------
    # Final safety checks
    # --------------------------------------------------------

    final_missing_cells = int(
        final_df.isna().sum().sum()
    )

    final_duplicate_rows = int(
        final_df.duplicated().sum()
    )

    duplicate_user_ids = int(
        final_df["user_id"]
        .duplicated()
        .sum()
    )

    # --------------------------------------------------------
    # Do not allow missing values in final output
    # --------------------------------------------------------

    if final_missing_cells != 0:
        raise ValueError(
            "Final Identity dataset still contains "
            f"{final_missing_cells} missing cells."
        )

    # --------------------------------------------------------
    # User ID uniqueness
    # --------------------------------------------------------

    if duplicate_user_ids != 0:
        raise ValueError(
            "Final Identity dataset contains "
            f"{duplicate_user_ids} duplicate user IDs."
        )

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Save final cleaned dataset
    # --------------------------------------------------------

    final_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ========================================================
    # FINAL REPORT
    # ========================================================

    print("\n" + "=" * 60)
    print("IDENTITY CLEANING SUMMARY")
    print("=" * 60)

    print(
        f"Raw rows: {raw_rows:,}"
    )

    print(
        f"Exact duplicates removed: "
        f"{exact_duplicates_removed:,}"
    )

    print(
        f"Cleaned rows: {len(final_df):,}"
    )

    print(
        f"User ID invalid: {user_id_invalid:,}"
    )

    print(
        f"Department unmapped: "
        f"{department_unmapped:,}"
    )

    print(
        f"Status unmapped: "
        f"{status_unmapped:,}"
    )

    print(
        f"Hire date invalid: "
        f"{hire_date_invalid:,}"
    )

    print(
        f"Termination date invalid: "
        f"{termination_date_invalid:,}"
    )

    print(
        f"Terminated + missing termination date: "
        f"{terminated_missing_date:,}"
    )

    print(
        f"Active-like + termination date: "
        f"{active_with_termination_date:,}"
    )

    print(
        f"Hire date after termination date: "
        f"{hire_after_termination:,}"
    )

    print(
        f"Final missing cells: "
        f"{final_missing_cells:,}"
    )

    print(
        f"Final duplicate rows: "
        f"{final_duplicate_rows:,}"
    )

    print(
        f"Duplicate user IDs: "
        f"{duplicate_user_ids:,}"
    )

    print(
        f"Final columns: "
        f"{len(final_df.columns)}"
    )

    print(
        f"\nOutput written to:\n{OUTPUT_FILE}"
    )

    print("=" * 60)
    print("IDENTITY CLEANING COMPLETE")
    print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()