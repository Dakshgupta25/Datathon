"""
IAM Data Cleaning Pipeline
Track 2 — Zero-Trust Telemetry & Insider Threat Logs

Phase 1 + Phase 2
-----------------
Cleans the raw IAM audit trail and produces an analysis-ready CSV.

Input:
    data/raw/track2_iam_audit_trail.json

Output:
    data/cleaned/iam_cleaned.csv

Cleaning principles:
    - Raw data is never modified.
    - Exact duplicate rows are removed.
    - Equivalent representations are standardized.
    - Invalid IP addresses are represented as "Unknown".
    - Invalid/out-of-range risk scores are imputed using the median
      of valid numeric risk scores.
    - Missing categorical values use documented semantic values.
    - Failure reasons follow event-type semantics.
    - Final output contains zero missing cells.
    - The pipeline is reproducible from the raw source.
"""

from pathlib import Path
import re
import json
import ipaddress

import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "track2_iam_audit_trail.json"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "cleaned"
    / "iam_cleaned.csv"
)


# ============================================================
# EXPECTED FINAL SCHEMA
# ============================================================

FINAL_COLUMNS = [
    "event_id",
    "timestamp",
    "user_id",
    "username",
    "department",
    "event_type",
    "auth_method",
    "source_ip",
    "hostname",
    "device_id",
    "session_id",
    "mfa_passed",
    "failure_reason",
    "risk_score",
    "geo_location",
]


# ============================================================
# GENERAL HELPERS
# ============================================================

NA_LIKE_VALUES = {
    "",
    "NA",
    "N/A",
    "NONE",
    "NULL",
    "NAN",
    "NOT AVAILABLE",
    "NOT_AVAILABLE",
}


def normalize_text(value):
    """Strip whitespace and convert obvious missing markers to NaN."""

    if value is None:
        return np.nan

    if pd.isna(value):
        return np.nan

    value = str(value).strip()

    if value.upper() in NA_LIKE_VALUES:
        return np.nan

    return value


# ============================================================
# USER ID
# ============================================================

def normalize_user_id(value):
    """
    Standardize employee IDs.

    Examples:
        EMP12345
        emp12345
        EMP-12345
        EMP 12345
        12345

    become:
        EMP12345
    """

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = str(value).strip().upper()

    # Remove spaces and hyphens.
    value = re.sub(r"[\s\-_]", "", value)

    # Numeric-only IDs.
    if value.isdigit():
        return f"EMP{value}"

    # EMP + numeric ID.
    match = re.fullmatch(r"EMP(\d+)", value)

    if match:
        return f"EMP{match.group(1)}"

    return value


# ============================================================
# HOSTNAME
# ============================================================

def normalize_hostname(value):
    """Normalize hostname formatting."""

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = str(value).strip().upper()

    # Underscore -> hyphen.
    value = value.replace("_", "-")

    # Remove known corporate suffix.
    value = re.sub(
        r"\.CORP\.LOCAL$",
        "",
        value,
    )

    return value


# ============================================================
# DEPARTMENT
# ============================================================

DEPARTMENT_MAP = {
    # IT
    "it": "IT",
    "it dept": "IT",
    "information technology": "IT",
    "information tech": "IT",

    # HR
    "hr": "Human Resources",
    "hr dept": "Human Resources",
    "human resource": "Human Resources",
    "human resources": "Human Resources",
    "people team": "Human Resources",

    # R&D
    "r&d": "R&D",
    "rd": "R&D",
    "rnd": "R&D",
    "research and development": "R&D",

    # Operations
    "ops": "Operations",
    "ops team": "Operations",
    "operations": "Operations",
    "operations dept": "Operations",

    # Marketing
    "mkt": "Marketing",
    "mktg": "Marketing",
    "marketing": "Marketing",
    "marketing dept": "Marketing",

    # Finance
    "finance": "Finance",
    "fin": "Finance",
    "finance dept": "Finance",
    "accounts": "Finance",

    # Procurement
    "purchase": "Procurement",
    "purch": "Procurement",
    "procurement": "Procurement",
    "procurement team": "Procurement",

    # Legal
    "legal": "Legal",
    "legal dept": "Legal",

    # Sales
    "sales": "Sales",
    "sales team": "Sales",
    "sales dept": "Sales",
    "business sales": "Sales",

    # Customer Support
    "cs": "Customer Support",
    "customer care": "Customer Support",
    "customer support": "Customer Support",

    # Other known categories
    "support": "Support",
    "it support": "IT Support",
    "brand": "Brand",
    "brand team": "Brand",
    "compliance": "Compliance",
    "innovation": "Innovation",
    "supply chain": "Supply Chain",
    "call center": "Call Center",
}


def normalize_department(value):
    """Map known department variants to canonical labels."""

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    key = str(value).strip().lower()

    return DEPARTMENT_MAP.get(key, str(value).strip())


# ============================================================
# EVENT TYPE
# ============================================================

SUCCESS_EVENTS = {
    "sso_success",
    "success_login",
    "auth_success",
    "login_success",
    "successful_login",
    "logon_success",
    "successful_logon",
    "login_succeeded",
}


FAILURE_EVENTS = {
    "login_failed",
    "mfa_failed",
    "logon_failure",
    "auth_failed",
    "failed_login",
    "invalid_credentials",
    "failed_logon",
    "authentication_failed",
}


def normalize_event_type(value):
    """
    Reduce IAM event types to:

        login_success
        login_failed
        other
    """

    value = normalize_text(value)

    if pd.isna(value):
        return "other"

    normalized = (
        str(value)
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )

    if normalized in SUCCESS_EVENTS:
        return "login_success"

    if normalized in FAILURE_EVENTS:
        return "login_failed"

    return "other"


# ============================================================
# AUTH METHOD
# ============================================================

def normalize_auth_method(value):
    """Standardize basic authentication-method formatting."""

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = str(value).strip().lower()

    auth_map = {
        "password": "Password",
        "pwd": "Password",
        "password_auth": "Password",

        "sso": "SSO",
        "sso_auth": "SSO",

        "mfa": "MFA",
        "multi_factor": "MFA",
        "multi-factor": "MFA",

        "oauth": "OAuth",
        "oauth2": "OAuth",

        "certificate": "Certificate",
        "cert": "Certificate",

        "biometric": "Biometric",
    }

    return auth_map.get(
        value,
        str(value).strip(),
    )


# ============================================================
# BOOLEAN / MFA
# ============================================================

def normalize_boolean(value):
    """Normalize common boolean representations."""

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = str(value).strip().lower()

    true_values = {
        "true",
        "t",
        "yes",
        "y",
        "1",
        "passed",
    }

    false_values = {
        "false",
        "f",
        "no",
        "n",
        "0",
        "failed",
    }

    if value in true_values:
        return True

    if value in false_values:
        return False

    return np.nan


# ============================================================
# IP VALIDATION
# ============================================================

def normalize_ip(value):
    """
    Validate IPv4 and IPv6 addresses.

    Invalid addresses become NaN and are later represented
    as Unknown.
    """

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = str(value).strip()

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return np.nan


# ============================================================
# RISK SCORE
# ============================================================

def normalize_risk_score(value):
    """
    Convert risk score to numeric 0–100.

    Supported examples:
        78
        "78"
        "78/100"
        High
        Medium
        Low

    Values outside 0–100 are invalid.
    """

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = str(value).strip()

    # Example: 78/100
    match = re.fullmatch(
        r"(\d+(?:\.\d+)?)\s*/\s*100",
        value,
    )

    if match:
        score = float(match.group(1))

    else:
        numeric = pd.to_numeric(
            value,
            errors="coerce",
        )

        if not pd.isna(numeric):
            score = float(numeric)

        else:
            category_map = {
                "high": 80.0,
                "medium": 50.0,
                "low": 20.0,
            }

            score = category_map.get(
                value.lower(),
                np.nan,
            )

    if pd.isna(score):
        return np.nan

    if score < 0 or score > 100:
        return np.nan

    return score


# ============================================================
# FAILURE REASON
# ============================================================

FAILURE_REASON_MAP = {
    "invalid credentials": "invalid credentials",
    "invalid_credentials": "invalid credentials",

    "timeout": "timeout",

    "unknown user": "unknown user",
    "unknown_user": "unknown user",

    "bad token": "bad token",
    "bad_token": "bad token",

    "account locked": "account locked",
    "account_locked": "account locked",

    "wrong password": "wrong_password",
    "wrong_password": "wrong_password",

    "mfa failed": "MFA failed",
    "mfa_failed": "MFA failed",

    "otp expired": "OTP expired",
    "otp_expired": "OTP expired",

    "expired password": "expired password",
    "expired_password": "expired password",
}


def normalize_failure_reason(value):
    """Standardize known failure-reason variants."""

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    key = str(value).strip().lower()

    return FAILURE_REASON_MAP.get(
        key,
        str(value).strip(),
    )


# ============================================================
# TIMESTAMP
# ============================================================

def parse_timestamp(value):
    """
    Parse mixed timestamp formats and 10-digit Unix epoch seconds.
    """

    value = normalize_text(value)

    if pd.isna(value):
        return pd.NaT

    value = str(value).strip()

    # Unix epoch seconds.
    if re.fullmatch(r"\d{10}", value):
        try:
            return pd.to_datetime(
                int(value),
                unit="s",
                errors="coerce",
            )
        except Exception:
            return pd.NaT

    # Try normal datetime parsing.
    return pd.to_datetime(
        value,
        errors="coerce",
        format="mixed",
    )


# ============================================================
# LOAD JSON
# ============================================================

def load_iam_json(path):
    """
    Load IAM JSON robustly.

    Handles:
        1. JSON array of records
        2. JSON object containing a list of records
        3. JSON Lines / NDJSON
    """

    # First attempt: standard JSON.
    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        if isinstance(data, list):
            return pd.DataFrame(data)

        if isinstance(data, dict):

            # Common wrapper keys.
            for key in [
                "data",
                "records",
                "events",
                "logs",
                "iam_logs",
            ]:
                if key in data and isinstance(
                    data[key],
                    list,
                ):
                    return pd.DataFrame(data[key])

            # Single record.
            return pd.DataFrame([data])

    except json.JSONDecodeError:
        pass

    # Second attempt: JSON Lines.
    try:
        return pd.read_json(
            path,
            lines=True,
        )
    except Exception as exc:
        raise ValueError(
            f"Unable to parse IAM JSON file: {path}\n"
            f"Error: {exc}"
        ) from exc


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("IAM DATA CLEANING PIPELINE")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. LOAD RAW DATA
    # --------------------------------------------------------

    print("\n[1/10] Loading raw IAM data...")

    if not RAW_FILE.exists():
        raise FileNotFoundError(
            f"Raw IAM file not found: {RAW_FILE}"
        )

    df = load_iam_json(RAW_FILE)

    raw_rows = len(df)

    print(f"Raw rows: {raw_rows:,}")
    print(f"Raw columns: {len(df.columns)}")

    # --------------------------------------------------------
    # 2. STANDARDIZE COLUMN NAMES
    # --------------------------------------------------------

    print("\n[2/10] Standardizing column names...")

    df.columns = (
        df.columns
        .astype(str)
        .str.strip()
        .str.lower()
        .str.replace(" ", "_", regex=False)
    )

    print("Columns:")
    print(", ".join(df.columns))

    # --------------------------------------------------------
    # REQUIRED SOURCE COLUMNS
    # --------------------------------------------------------

    missing_source_columns = [
        column
        for column in FINAL_COLUMNS
        if column not in df.columns
    ]

    if missing_source_columns:
        raise ValueError(
            "Required IAM columns are missing from raw data: "
            f"{missing_source_columns}"
        )

    # --------------------------------------------------------
    # 3. REMOVE EXACT DUPLICATES
    # --------------------------------------------------------

    print("\n[3/10] Removing exact duplicate rows...")

    duplicate_rows = int(
        df.duplicated().sum()
    )

    df = df.drop_duplicates().copy()

    print(
        f"Exact duplicate rows removed: "
        f"{duplicate_rows:,}"
    )

    print(
        f"Rows remaining: {len(df):,}"
    )

    # --------------------------------------------------------
    # 4. BASIC TEXT NORMALIZATION
    # --------------------------------------------------------

    print("\n[4/10] Normalizing textual fields...")

    for column in FINAL_COLUMNS:

        df[column] = df[column].apply(
            normalize_text
        )

    # --------------------------------------------------------
    # 5. IDENTIFIERS + CATEGORIES
    # --------------------------------------------------------

    print(
        "\n[5/10] Standardizing identifiers "
        "and categorical values..."
    )

    df["user_id"] = df["user_id"].apply(
        normalize_user_id
    )

    df["department"] = df["department"].apply(
        normalize_department
    )

    df["event_type"] = df["event_type"].apply(
        normalize_event_type
    )

    df["auth_method"] = df["auth_method"].apply(
        normalize_auth_method
    )

    df["hostname"] = df["hostname"].apply(
        normalize_hostname
    )

    # --------------------------------------------------------
    # 6. TIMESTAMP
    # --------------------------------------------------------

    print("\n[6/10] Parsing timestamps...")

    parsed_timestamp = df["timestamp"].apply(
        parse_timestamp
    )

    timestamp_invalid = int(
        parsed_timestamp.isna().sum()
    )

    df["timestamp"] = (
        parsed_timestamp
        .dt.strftime("%Y-%m-%d %H:%M:%S")
    )

    df["timestamp"] = df["timestamp"].replace(
        {
            "NaT": np.nan,
            "": np.nan,
        }
    )

    print(
        f"Missing/invalid timestamps: "
        f"{timestamp_invalid:,}"
    )

    # --------------------------------------------------------
    # 7. IP VALIDATION
    # --------------------------------------------------------

    print("\n[7/10] Validating source IP addresses...")

    df["source_ip"] = df["source_ip"].apply(
        normalize_ip
    )

    invalid_ip_count = int(
        df["source_ip"].isna().sum()
    )

    print(
        f"Missing/invalid source IP values: "
        f"{invalid_ip_count:,}"
    )

    # --------------------------------------------------------
    # 8. MFA + RISK SCORE
    # --------------------------------------------------------

    print(
        "\n[8/10] Standardizing MFA "
        "and risk scores..."
    )

    df["mfa_passed"] = df["mfa_passed"].apply(
        normalize_boolean
    )

    df["risk_score"] = df["risk_score"].apply(
        normalize_risk_score
    )

    valid_risk_scores = (
        df["risk_score"]
        .dropna()
    )

    if len(valid_risk_scores) > 0:
        risk_median = float(
            valid_risk_scores.median()
        )
    else:
        risk_median = 50.0

    df["risk_score"] = (
        df["risk_score"]
        .fillna(risk_median)
    )

    print(
        f"Risk score median used: "
        f"{risk_median:.2f}"
    )

    # --------------------------------------------------------
    # 9. FAILURE REASON
    # --------------------------------------------------------

    print(
        "\n[9/10] Applying failure-reason semantics..."
    )

    df["failure_reason"] = (
        df["failure_reason"]
        .apply(normalize_failure_reason)
    )

    missing_failure_reason = (
        df["failure_reason"].isna()
        |
        df["failure_reason"]
        .astype("string")
        .str.strip()
        .eq("")
        |
        df["failure_reason"]
        .astype("string")
        .str.upper()
        .isin(
            {
                "NA",
                "N/A",
                "NONE",
                "NULL",
                "NAN",
            }
        )
    )

    # login_success / other:
    # failure reason is not applicable.
    non_failure_events = df[
        "event_type"
    ].isin(
        {
            "login_success",
            "other",
        }
    )

    df.loc[
        non_failure_events
        & missing_failure_reason,
        "failure_reason",
    ] = "Not Applicable"

    # login_failed:
    # missing reason means reason was not available.
    login_failure_events = df[
        "event_type"
    ].eq("login_failed")

    df.loc[
        login_failure_events
        & missing_failure_reason,
        "failure_reason",
    ] = "Unknown"

    # --------------------------------------------------------
    # 10. ZERO-MISSING FINALIZATION
    # --------------------------------------------------------

    print(
        "\n[10/10] Finalizing "
        "zero-missing analytical dataset..."
    )

    # --------------------------------------------------------
    # Semantic Unknown values
    # --------------------------------------------------------

    unknown_columns = [
        "event_id",
        "user_id",
        "username",
        "department",
        "auth_method",
        "source_ip",
        "hostname",
        "device_id",
        "session_id",
        "geo_location",
    ]

    for column in unknown_columns:

        df[column] = (
            df[column]
            .replace(
                {
                    "": np.nan,
                    "NA": np.nan,
                    "N/A": np.nan,
                    "NONE": np.nan,
                    "NULL": np.nan,
                }
            )
            .fillna("Unknown")
        )

    # Timestamp.
    df["timestamp"] = (
        df["timestamp"]
        .replace(
            {
                "": np.nan,
                "NA": np.nan,
                "N/A": np.nan,
                "NONE": np.nan,
                "NULL": np.nan,
            }
        )
        .fillna("Unknown")
    )

    # MFA.
    df["mfa_passed"] = (
        df["mfa_passed"]
        .map(
            {
                True: "True",
                False: "False",
            }
        )
        .fillna("Unknown")
    )

    # Failure reason.
    df["failure_reason"] = (
        df["failure_reason"]
        .replace(
            {
                "": np.nan,
                "NA": np.nan,
                "N/A": np.nan,
                "NONE": np.nan,
                "NULL": np.nan,
            }
        )
        .fillna("Unknown")
    )

    # Risk score.
    df["risk_score"] = (
        pd.to_numeric(
            df["risk_score"],
            errors="coerce",
        )
        .fillna(risk_median)
        .clip(
            lower=0,
            upper=100,
        )
    )

    # --------------------------------------------------------
    # FINAL COLUMN ORDER
    # --------------------------------------------------------

    df = df[FINAL_COLUMNS].copy()

    # --------------------------------------------------------
    # FINAL QUALITY CHECKS
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL QUALITY CHECKS")
    print("=" * 70)

    missing_cells = int(
        df.isna().sum().sum()
    )

    duplicate_rows_final = int(
        df.duplicated().sum()
    )

    duplicate_event_ids = int(
        df["event_id"].duplicated().sum()
    )

    invalid_risk_scores = int(
        (
            (df["risk_score"] < 0)
            |
            (df["risk_score"] > 100)
        ).sum()
    )

    invalid_event_types = int(
        (
            ~df["event_type"].isin(
                {
                    "login_success",
                    "login_failed",
                    "other",
                }
            )
        ).sum()
    )

    invalid_mfa = int(
        (
            ~df["mfa_passed"].isin(
                {
                    "True",
                    "False",
                    "Unknown",
                }
            )
        ).sum()
    )

    invalid_failure_reason_semantics = int(
        (
            df["event_type"].isin(
                {
                    "login_success",
                    "other",
                }
            )
            &
            ~df["failure_reason"].isin(
                {
                    "Not Applicable",
                    "Unknown",
                }
            )
        ).sum()
    )

    login_failure_unknown = int(
        (
            df["event_type"].eq(
                "login_failed"
            )
            &
            df["failure_reason"].eq(
                "Unknown"
            )
        ).sum()
    )

    print(
        f"Final rows: "
        f"{len(df):,}"
    )

    print(
        f"Final columns: "
        f"{len(df.columns)}"
    )

    print(
        f"Final missing cells: "
        f"{missing_cells:,}"
    )

    print(
        f"Final duplicate rows: "
        f"{duplicate_rows_final:,}"
    )

    print(
        f"Duplicate event IDs: "
        f"{duplicate_event_ids:,}"
    )

    print(
        f"Invalid risk scores: "
        f"{invalid_risk_scores:,}"
    )

    print(
        f"Invalid event types: "
        f"{invalid_event_types:,}"
    )

    print(
        f"Invalid MFA values: "
        f"{invalid_mfa:,}"
    )

    print(
        "Invalid non-failure event reasons: "
        f"{invalid_failure_reason_semantics:,}"
    )

    print(
        "Login failures marked Unknown: "
        f"{login_failure_unknown:,}"
    )

    # --------------------------------------------------------
    # FAIL HARD
    # --------------------------------------------------------

    if missing_cells != 0:
        raise ValueError(
            f"Final IAM dataset still contains "
            f"{missing_cells} missing cells."
        )

    if duplicate_rows_final != 0:
        raise ValueError(
            "Final IAM dataset contains duplicate rows."
        )

    if duplicate_event_ids != 0:
        raise ValueError(
            "Final IAM dataset contains duplicate event IDs."
        )

    if invalid_risk_scores != 0:
        raise ValueError(
            "Final IAM dataset contains invalid risk scores."
        )

    if invalid_event_types != 0:
        raise ValueError(
            "Final IAM dataset contains invalid event types."
        )

    if invalid_mfa != 0:
        raise ValueError(
            "Final IAM dataset contains invalid MFA values."
        )

    if invalid_failure_reason_semantics != 0:
        raise ValueError(
            "Failure reason semantics are inconsistent."
        )

    # --------------------------------------------------------
    # SAVE OUTPUT
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    df.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("IAM CLEANING COMPLETE")
    print("=" * 70)

    print(
        f"Input:  {RAW_FILE}"
    )

    print(
        f"Output: {OUTPUT_FILE}"
    )

    print(
        f"Raw rows: "
        f"{raw_rows:,}"
    )

    print(
        f"Exact duplicates removed: "
        f"{duplicate_rows:,}"
    )

    print(
        f"Final rows: "
        f"{len(df):,}"
    )

    print(
        f"Final columns: "
        f"{len(df.columns)}"
    )

    print(
        f"Final missing cells: "
        f"{missing_cells}"
    )

    print(
        f"Final duplicate rows: "
        f"{duplicate_rows_final}"
    )

    print("\nRESULT: IAM CLEANING PASSED")


if __name__ == "__main__":
    main()