from pathlib import Path
import ipaddress
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_PATH = PROJECT_ROOT / "data" / "raw" / "track2_iam_audit_trail.json"
CLEANED_PATH = PROJECT_ROOT / "data" / "cleaned" / "iam_cleaned.csv"
SUMMARY_PATH = PROJECT_ROOT / "reports" / "iam_cleaning_summary.csv"


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_missing(value):
    """Safely identify missing values."""
    return pd.isna(value)


def normalize_text(value):
    """Strip whitespace and normalize text."""
    if is_missing(value):
        return None

    text = str(value).strip()

    if text == "":
        return None

    return text


# ============================================================
# USER ID CLEANING
# ============================================================

def clean_user_id(value):
    """
    Convert user IDs into canonical EMP12345 format.

    Examples:
        emp12345   -> EMP12345
        EMP-12345  -> EMP12345
        EMP 12345  -> EMP12345
        12345      -> EMP12345
    """

    if is_missing(value):
        return pd.NA

    text = str(value).strip().upper()

    # Remove spaces, hyphens and underscores
    text = re.sub(r"[\s\-_]", "", text)

    if text == "":
        return pd.NA

    # Numeric-only IDs receive EMP prefix
    if text.isdigit():
        text = "EMP" + text

    return text


def validate_user_id(value):
    """Validate canonical EMP + numeric ID format."""

    if pd.isna(value):
        return pd.NA

    return bool(re.fullmatch(r"EMP\d+", str(value)))


# ============================================================
# DEPARTMENT STANDARDIZATION
# ============================================================

DEPARTMENT_MAP = {
    # Procurement
    "procurement": "Procurement",
    "procurement team": "Procurement",
    "purchase": "Procurement",
    "purch": "Procurement",

    # Human Resources
    "hr": "Human Resources",
    "human resource": "Human Resources",
    "human resources": "Human Resources",
    "hr dept": "Human Resources",

    # Information Technology
    "it": "Information Technology",
    "it dept": "Information Technology",
    "information tech": "Information Technology",
    "information technology": "Information Technology",

    # Keep IT Support separate because it may represent a
    # distinct organizational function.
    "it support": "IT Support",

    # Customer Support
    "cs": "Customer Support",
    "customer care": "Customer Support",
    "support": "Customer Support",
    "customer support": "Customer Support",
    "call center": "Customer Support",

    # Brand
    "brand team": "Brand Team",

    # Research and Development
    "r&d": "Research and Development",
    "rnd": "Research and Development",
    "rd": "Research and Development",
    "research and development": "Research and Development",

    # Finance
    "finance": "Finance",
    "fin": "Finance",
    "finance dept": "Finance",

    # Marketing
    "marketing": "Marketing",
    "marketing dept": "Marketing",
    "mkt": "Marketing",
    "mktg": "Marketing",

    # Operations
    "operations": "Operations",
    "ops": "Operations",
    "ops team": "Operations",
    "operations dept": "Operations",

    # Sales
    "sales": "Sales",
    "sales team": "Sales",
    "sales dept": "Sales",

    # Legal
    "legal": "Legal",
    "legal dept": "Legal",

    # Other observed departments
    "accounts": "Accounts",
    "compliance": "Compliance",
    "innovation": "Innovation",
    "supply chain": "Supply Chain",
    "business sales": "Business Sales",
    "people team": "People Team",
}


def clean_department(value):
    """
    Apply an explicit controlled department mapping.

    Unknown values are NOT guessed.
    Missing values remain missing.
    """

    if is_missing(value):
        return pd.NA

    text = str(value).strip().lower()

    if text == "":
        return pd.NA

    return DEPARTMENT_MAP.get(text, pd.NA)


def department_status(raw_value, clean_value):
    """Describe department cleaning outcome."""

    if is_missing(raw_value):
        return "missing"

    if is_missing(clean_value):
        return "unmapped"

    return "mapped"


# ============================================================
# EVENT TYPE STANDARDIZATION
# ============================================================

# All values are represented in their normalized form because
# normalize_event_key() converts spaces/hyphens to underscores.

LOGIN_SUCCESS_VARIANTS = {
    "SSO_SUCCESS",
    "SUCCESS_LOGIN",
    "AUTH_SUCCESS",
    "LOGIN_SUCCESS",
    "SUCCESSFUL_LOGIN",
    "LOGON_SUCCESS",
}


LOGIN_FAILED_VARIANTS = {
    "LOGIN_FAILED",
    "MFA_FAILED",
    "LOGON_FAILURE",
    "AUTH_FAILED",
    "FAILED_LOGIN",
    "INVALID_CREDENTIALS",
    "FAILED_LOGON",
}


OTHER_EVENT_VARIANTS = {
    "PASSWORD_RESET",
    "ACCOUNT_LOCK",
    "ACCOUNT_UNLOCK",
    "DEVICE_REGISTERED",
    "PRIVILEGE_ESCALATION_REQUEST",
    "SESSION_TERMINATED",
    "MFA_ENROLLMENT",
}


def normalize_event_key(value):
    """
    Normalize event type text.

    Examples:
        Successful Login -> SUCCESSFUL_LOGIN
        failed logon     -> FAILED_LOGON
        Login Failed     -> LOGIN_FAILED
    """

    if is_missing(value):
        return None

    text = str(value).strip().upper()

    if text == "":
        return None

    # Convert spaces and hyphens to underscores
    text = re.sub(r"[\s\-]+", "_", text)

    return text


def clean_event_type(value):
    """
    Normalize primary event type into:

        login_success
        login_failed
        other
    """

    key = normalize_event_key(value)

    if key is None:
        return pd.NA

    if key in LOGIN_SUCCESS_VARIANTS:
        return "login_success"

    if key in LOGIN_FAILED_VARIANTS:
        return "login_failed"

    if key in OTHER_EVENT_VARIANTS:
        return "other"

    # Unknown values are deliberately not guessed.
    return pd.NA


def clean_event_category(value):
    """
    Preserve finer-grained security event meaning.
    """

    key = normalize_event_key(value)

    if key is None:
        return pd.NA

    category_map = {
        # Successful authentication
        "SSO_SUCCESS": "login_success",
        "SUCCESS_LOGIN": "login_success",
        "AUTH_SUCCESS": "login_success",
        "LOGIN_SUCCESS": "login_success",
        "SUCCESSFUL_LOGIN": "login_success",
        "LOGON_SUCCESS": "login_success",

        # Failed authentication
        "LOGIN_FAILED": "login_failed",
        "MFA_FAILED": "mfa_failed",
        "LOGON_FAILURE": "login_failed",
        "AUTH_FAILED": "login_failed",
        "FAILED_LOGIN": "login_failed",
        "INVALID_CREDENTIALS": "login_failed",
        "FAILED_LOGON": "login_failed",

        # Other security events
        "PASSWORD_RESET": "password_reset",
        "ACCOUNT_LOCK": "account_lock",
        "ACCOUNT_UNLOCK": "account_unlock",
        "DEVICE_REGISTERED": "device_registered",
        "PRIVILEGE_ESCALATION_REQUEST": "privilege_escalation_request",
        "SESSION_TERMINATED": "session_terminated",
        "MFA_ENROLLMENT": "mfa_enrollment",
    }

    return category_map.get(key, pd.NA)


def event_type_status(raw_value, clean_value):
    """Describe event type cleaning outcome."""

    if is_missing(raw_value):
        return "missing"

    if is_missing(clean_value):
        return "unmapped"

    return "mapped"


# ============================================================
# MFA CLEANING
# ============================================================

MFA_TRUE_VALUES = {
    "TRUE",
    "Y",
    "YES",
    "1",
}

MFA_FALSE_VALUES = {
    "FALSE",
    "N",
    "NO",
    "0",
}


def clean_mfa(value):
    """Normalize MFA values into nullable Boolean."""

    if is_missing(value):
        return pd.NA

    text = str(value).strip().upper()

    if text in MFA_TRUE_VALUES:
        return True

    if text in MFA_FALSE_VALUES:
        return False

    return pd.NA


def validate_mfa(raw_value, clean_value):
    """Validate MFA cleaning result."""

    if is_missing(raw_value):
        return pd.NA

    return not is_missing(clean_value)


# ============================================================
# TIMESTAMP CLEANING
# ============================================================

def clean_timestamp(series):
    """
    Parse mixed timestamp formats.

    Invalid timestamps are converted to NULL in the clean
    analytical column while the original raw value is preserved.
    """

    return pd.to_datetime(
        series,
        format="mixed",
        errors="coerce",
        utc=True,
    )


def timestamp_validity(raw_series, clean_series):
    """
    Nullable validation:

        missing raw value -> <NA>
        valid timestamp   -> True
        invalid timestamp -> False
    """

    result = pd.Series(
        pd.NA,
        index=raw_series.index,
        dtype="boolean",
    )

    non_missing_mask = ~raw_series.isna()

    result.loc[non_missing_mask] = (
        clean_series.loc[non_missing_mask].notna()
    )

    return result


# ============================================================
# SOURCE IP CLEANING
# ============================================================

def clean_ip(value):
    """
    Validate and canonicalize IPv4/IPv6 addresses.

    Invalid non-empty IP values become NULL in the clean
    analytical field. Raw values are preserved separately.
    """

    if is_missing(value):
        return pd.NA

    text = str(value).strip()

    if text == "":
        return pd.NA

    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return pd.NA


def ip_validity(raw_series, clean_series):
    """
    Nullable IP validation.
    """

    result = pd.Series(
        pd.NA,
        index=raw_series.index,
        dtype="boolean",
    )

    non_missing_mask = ~raw_series.isna()

    result.loc[non_missing_mask] = (
        clean_series.loc[non_missing_mask].notna()
    )

    return result


# ============================================================
# RISK SCORE CLEANING
# ============================================================

def clean_risk_score(value):
    """
    Clean and classify risk score.

    Returns:
        numeric_score
        category
        status
        anomaly_reason

    Important:
    High / Medium / Low are preserved as categories.
    They are NOT converted to arbitrary numeric scores.
    """

    if is_missing(value):
        return pd.NA, pd.NA, "missing", pd.NA

    text = str(value).strip()

    if text == "":
        return pd.NA, pd.NA, "missing", pd.NA

    # --------------------------------------------------------
    # Categorical risk labels
    # --------------------------------------------------------

    category_map = {
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }

    upper_text = text.upper()

    if upper_text in category_map:
        return (
            pd.NA,
            category_map[upper_text],
            "valid_categorical",
            pd.NA,
        )

    # --------------------------------------------------------
    # Fraction format such as 78/100
    # --------------------------------------------------------

    fraction_match = re.fullmatch(
        r"\s*(-?\d+(?:\.\d+)?)\s*/\s*100\s*",
        text,
    )

    if fraction_match:

        score = float(fraction_match.group(1))

        if 0 <= score <= 100:
            return (
                score,
                pd.NA,
                "valid_numeric_fraction",
                pd.NA,
            )

        return (
            pd.NA,
            pd.NA,
            "invalid_range",
            "outside_0_100",
        )

    # --------------------------------------------------------
    # Direct numeric value
    # --------------------------------------------------------

    numeric = pd.to_numeric(text, errors="coerce")

    if pd.notna(numeric):

        if 0 <= float(numeric) <= 100:
            return (
                float(numeric),
                pd.NA,
                "valid_numeric",
                pd.NA,
            )

        return (
            pd.NA,
            pd.NA,
            "invalid_range",
            "outside_0_100",
        )

    # --------------------------------------------------------
    # Unknown non-numeric value
    # --------------------------------------------------------

    return (
        pd.NA,
        pd.NA,
        "invalid_format",
        "unrecognized_risk_value",
    )


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    print("=" * 60)
    print("IAM DATA CLEANING PIPELINE")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. LOAD RAW DATA
    # --------------------------------------------------------

    print("\n[1/10] Loading raw IAM data...")

    df = pd.read_json(RAW_PATH)

    raw_rows = len(df)

    print(f"Raw rows loaded: {raw_rows:,}")

    # --------------------------------------------------------
    # 2. REMOVE EXACT DUPLICATES
    # --------------------------------------------------------

    print("\n[2/10] Removing exact duplicate rows...")

    duplicate_mask = df.duplicated(keep="first")

    exact_duplicates_removed = int(
        duplicate_mask.sum()
    )

    # Remove only extra copies.
    # The raw JSON file remains untouched.
    df = df.loc[~duplicate_mask].copy()

    cleaned_rows = len(df)

    print(
        f"Exact duplicate rows removed: "
        f"{exact_duplicates_removed:,}"
    )

    print(f"Rows remaining: {cleaned_rows:,}")

    # --------------------------------------------------------
    # 3. USER ID
    # --------------------------------------------------------

    print("\n[3/10] Cleaning user IDs...")

    df["user_id_raw"] = df["user_id"]

    df["user_id_clean"] = (
        df["user_id"]
        .apply(clean_user_id)
    )

    df["user_id_valid"] = (
        df["user_id_clean"]
        .apply(validate_user_id)
        .astype("boolean")
    )

    # --------------------------------------------------------
    # 4. DEPARTMENT
    # --------------------------------------------------------

    print("\n[4/10] Standardizing departments...")

    df["department_raw"] = df["department"]

    df["department_clean"] = (
        df["department"]
        .apply(clean_department)
    )

    df["department_status"] = [
        department_status(raw, clean)
        for raw, clean in zip(
            df["department_raw"],
            df["department_clean"],
        )
    ]

    # --------------------------------------------------------
    # 5. EVENT TYPE
    # --------------------------------------------------------

    print("\n[5/10] Standardizing event types...")

    df["event_type_raw"] = df["event_type"]

    df["event_type_clean"] = (
        df["event_type"]
        .apply(clean_event_type)
    )

    df["event_category"] = (
        df["event_type"]
        .apply(clean_event_category)
    )

    df["event_type_status"] = [
        event_type_status(raw, clean)
        for raw, clean in zip(
            df["event_type_raw"],
            df["event_type_clean"],
        )
    ]

    # --------------------------------------------------------
    # 6. MFA
    # --------------------------------------------------------

    print("\n[6/10] Standardizing MFA values...")

    df["mfa_passed_raw"] = df["mfa_passed"]

    df["mfa_passed_clean"] = (
        df["mfa_passed"]
        .apply(clean_mfa)
        .astype("boolean")
    )

    df["mfa_passed_valid"] = [
        validate_mfa(raw, clean)
        for raw, clean in zip(
            df["mfa_passed_raw"],
            df["mfa_passed_clean"],
        )
    ]

    df["mfa_passed_valid"] = (
        df["mfa_passed_valid"]
        .astype("boolean")
    )

    # --------------------------------------------------------
    # 7. TIMESTAMP
    # --------------------------------------------------------

    print("\n[7/10] Cleaning timestamps...")

    df["timestamp_raw"] = df["timestamp"]

    df["timestamp_clean"] = clean_timestamp(
        df["timestamp"]
    )

    df["timestamp_valid"] = timestamp_validity(
        df["timestamp_raw"],
        df["timestamp_clean"],
    )

    # --------------------------------------------------------
    # 8. SOURCE IP
    # --------------------------------------------------------

    print("\n[8/10] Validating source IP addresses...")

    df["source_ip_raw"] = df["source_ip"]

    df["source_ip_clean"] = (
        df["source_ip"]
        .apply(clean_ip)
    )

    df["source_ip_valid"] = ip_validity(
        df["source_ip_raw"],
        df["source_ip_clean"],
    )

    # --------------------------------------------------------
    # 9. RISK SCORE
    # --------------------------------------------------------

    print("\n[9/10] Cleaning risk scores...")

    risk_results = (
        df["risk_score"]
        .apply(clean_risk_score)
    )

    df["risk_score_raw"] = df["risk_score"]

    df["risk_score_numeric"] = (
        risk_results
        .apply(lambda x: x[0])
    )

    df["risk_score_category"] = (
        risk_results
        .apply(lambda x: x[1])
    )

    df["risk_score_status"] = (
        risk_results
        .apply(lambda x: x[2])
    )

    df["risk_anomaly_reason"] = (
        risk_results
        .apply(lambda x: x[3])
    )

    # --------------------------------------------------------
    # 10. SAVE CLEANED DATA + SUMMARY
    # --------------------------------------------------------

    print("\n[10/10] Saving cleaned data and summary...")

    CLEANED_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    SUMMARY_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Save cleaned IAM data
    df.to_csv(
        CLEANED_PATH,
        index=False,
    )

    # --------------------------------------------------------
    # SUMMARY COUNTS
    # --------------------------------------------------------

    user_id_invalid = int(
        (df["user_id_valid"] == False).sum()
    )

    department_unmapped = int(
        (df["department_status"] == "unmapped").sum()
    )

    event_unmapped = int(
        (df["event_type_status"] == "unmapped").sum()
    )

    mfa_invalid = int(
        (df["mfa_passed_valid"] == False).sum()
    )

    timestamp_invalid = int(
        (df["timestamp_valid"] == False).sum()
    )

    source_ip_invalid = int(
        (df["source_ip_valid"] == False).sum()
    )

    risk_invalid_range = int(
        (df["risk_score_status"] == "invalid_range").sum()
    )

    risk_invalid_format = int(
        (df["risk_score_status"] == "invalid_format").sum()
    )

    risk_categorical = int(
        (df["risk_score_status"] == "valid_categorical").sum()
    )

    risk_missing = int(
        (df["risk_score_status"] == "missing").sum()
    )

    # --------------------------------------------------------
    # CREATE SUMMARY REPORT
    # --------------------------------------------------------

    summary = pd.DataFrame([
        {
            "dataset": "IAM",
            "raw_rows": raw_rows,
            "exact_duplicate_rows_removed":
                exact_duplicates_removed,
            "cleaned_rows": cleaned_rows,

            "user_id_invalid":
                user_id_invalid,

            "department_unmapped":
                department_unmapped,

            "event_type_unmapped":
                event_unmapped,

            "mfa_invalid":
                mfa_invalid,

            "timestamp_invalid":
                timestamp_invalid,

            "source_ip_invalid":
                source_ip_invalid,

            "risk_invalid_range":
                risk_invalid_range,

            "risk_invalid_format":
                risk_invalid_format,

            "risk_categorical":
                risk_categorical,

            "risk_missing":
                risk_missing,

            "output_file":
                str(CLEANED_PATH),
        }
    ])

    summary.to_csv(
        SUMMARY_PATH,
        index=False,
    )

    # --------------------------------------------------------
    # TERMINAL REPORT
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("IAM CLEANING COMPLETE")
    print("=" * 60)

    print(
        f"Raw rows                 : "
        f"{raw_rows:,}"
    )

    print(
        f"Exact duplicates removed : "
        f"{exact_duplicates_removed:,}"
    )

    print(
        f"Cleaned rows             : "
        f"{cleaned_rows:,}"
    )

    print(
        f"User ID invalid          : "
        f"{user_id_invalid:,}"
    )

    print(
        f"Department unmapped      : "
        f"{department_unmapped:,}"
    )

    print(
        f"Event type unmapped      : "
        f"{event_unmapped:,}"
    )

    print(
        f"MFA invalid              : "
        f"{mfa_invalid:,}"
    )

    print(
        f"Timestamp invalid        : "
        f"{timestamp_invalid:,}"
    )

    print(
        f"Source IP invalid        : "
        f"{source_ip_invalid:,}"
    )

    print(
        f"Risk invalid range       : "
        f"{risk_invalid_range:,}"
    )

    print(
        f"Risk invalid format      : "
        f"{risk_invalid_format:,}"
    )

    print(
        f"Risk categorical         : "
        f"{risk_categorical:,}"
    )

    print(
        f"Risk missing             : "
        f"{risk_missing:,}"
    )

    print("\nGenerated:")
    print(f"  {CLEANED_PATH}")
    print(f"  {SUMMARY_PATH}")


if __name__ == "__main__":
    main()