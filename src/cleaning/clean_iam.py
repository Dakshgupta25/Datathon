"""
IAM Data Cleaning Pipeline
Track 2 — Zero-Trust Telemetry & Insider Threat Logs

Phase 1 + Phase 2 + Phase B (Data Trust Finalization)
---------------------------------------------------
Cleans the raw IAM audit trail and produces an analysis-ready CSV with 
explicit risk score governance and quality metadata.

Input:
    data/raw/track2_iam_audit_trail.json

Output:
    data/cleaned/iam_cleaned.csv

Cleaning principles:
    - Raw data is never modified.
    - Exact duplicate rows are removed.
    - Equivalent representations are standardized.
    - Invalid IP addresses are represented as "Unknown".
    - IAM risk_score field preserves risk_score_raw, risk_score_numeric,
      risk_score_valid, risk_label, and risk_quality_flag.
    - Categorical strings (High/Medium/Low) are preserved as labels without
      converting to unsupported arbitrary numbers.
    - Final output contains quality metadata (data_quality_status, is_imputed, is_repaired).
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
# EXPECTED FINAL SCHEMA (PHASE B DATA TRUST ENRICHED)
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
    "risk_score_raw",
    "risk_score_numeric",
    "risk_score_valid",
    "risk_label",
    "risk_quality_flag",
    "geo_location",
    "data_quality_status",
    "is_imputed",
    "is_repaired",
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
    """Standardize employee IDs."""

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = str(value).strip().upper()
    value = re.sub(r"[\s\-_]", "", value)

    if value.isdigit():
        return f"EMP{value}"

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
    value = value.replace("_", "-")
    value = re.sub(r"\.CORP\.LOCAL$", "", value)

    return value


# ============================================================
# DEPARTMENT
# ============================================================

DEPARTMENT_MAP = {
    "it": "IT", "it dept": "IT", "information technology": "IT", "information tech": "IT",
    "hr": "Human Resources", "hr dept": "Human Resources", "human resource": "Human Resources",
    "human resources": "Human Resources", "people team": "Human Resources",
    "r&d": "R&D", "rd": "R&D", "rnd": "R&D", "research and development": "R&D",
    "ops": "Operations", "ops team": "Operations", "operations": "Operations", "operations dept": "Operations",
    "mkt": "Marketing", "mktg": "Marketing", "marketing": "Marketing", "marketing dept": "Marketing",
    "finance": "Finance", "fin": "Finance", "finance dept": "Finance", "accounts": "Finance",
    "purchase": "Procurement", "purch": "Procurement", "procurement": "Procurement", "procurement team": "Procurement",
    "legal": "Legal", "legal dept": "Legal",
    "sales": "Sales", "sales team": "Sales", "sales dept": "Sales", "business sales": "Sales",
    "cs": "Customer Support", "customer care": "Customer Support", "customer support": "Customer Support",
    "support": "Support", "it support": "IT Support", "brand": "Brand", "brand team": "Brand",
    "compliance": "Compliance", "innovation": "Innovation", "supply chain": "Supply Chain", "call center": "Call Center",
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
    "sso_success", "success_login", "auth_success", "login_success",
    "successful_login", "logon_success", "successful_logon", "login_succeeded",
}

FAILURE_EVENTS = {
    "login_failed", "mfa_failed", "logon_failure", "auth_failed",
    "failed_login", "invalid_credentials", "failed_logon", "authentication_failed",
}


def normalize_event_type(value):
    """Reduce IAM event types to: login_success, login_failed, other."""

    value = normalize_text(value)

    if pd.isna(value):
        return "other"

    normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")

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
        "password": "Password", "pwd": "Password", "password_auth": "Password",
        "sso": "SSO", "sso_auth": "SSO",
        "mfa": "MFA", "multi_factor": "MFA", "multi-factor": "MFA",
        "oauth": "OAuth", "oauth2": "OAuth",
        "certificate": "Certificate", "cert": "Certificate",
        "biometric": "Biometric",
    }

    return auth_map.get(value, str(value).strip())


# ============================================================
# BOOLEAN / MFA
# ============================================================

def normalize_boolean(value):
    """Normalize common boolean representations."""

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    value = str(value).strip().lower()

    if value in {"true", "t", "yes", "y", "1", "passed"}:
        return True

    if value in {"false", "f", "no", "n", "0", "failed"}:
        return False

    return np.nan


# ============================================================
# IP VALIDATION
# ============================================================

def normalize_ip(value):
    """Validate IPv4 and IPv6 addresses."""

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
# PHASE B ENRICHED RISK SCORE PARSER
# ============================================================

def parse_risk_score_phase_b(raw_val, risk_median=50.0):
    """
    Strict Phase B Risk Score governance parser:
    - Preserves risk_score_raw
    - Numeric 0-100 -> valid numeric
    - "x/100" -> parsed numeric
    - Negative or >100 -> invalid
    - High/Medium/Low -> preserved as categorical without converting to arbitrary numbers
    - Missing -> missing
    """

    if raw_val is None or pd.isna(raw_val):
        raw_str = "Missing"
    else:
        raw_str = str(raw_val).strip()

    if not raw_str or raw_str.upper() in NA_LIKE_VALUES or raw_str == "Missing":
        return {
            "risk_score_raw": "Missing",
            "risk_score_numeric": "Unknown",
            "risk_score_valid": "False",
            "risk_label": "Missing",
            "risk_quality_flag": "MISSING",
            "risk_score": risk_median,
            "is_imputed": True,
        }

    # Check "x/100"
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*/\s*100", raw_str)
    if match:
        score = float(match.group(1))
        if 0 <= score <= 100:
            label = "High" if score >= 71 else ("Medium" if score >= 31 else "Low")
            return {
                "risk_score_raw": raw_str,
                "risk_score_numeric": str(score),
                "risk_score_valid": "True",
                "risk_label": label,
                "risk_quality_flag": "PARSED_PERCENTAGE",
                "risk_score": score,
                "is_imputed": False,
            }
        else:
            return {
                "risk_score_raw": raw_str,
                "risk_score_numeric": "Unknown",
                "risk_score_valid": "False",
                "risk_label": "Invalid",
                "risk_quality_flag": "OUT_OF_RANGE",
                "risk_score": risk_median,
                "is_imputed": True,
            }

    # Check numeric
    try:
        score = float(raw_str)
        if 0 <= score <= 100:
            label = "High" if score >= 71 else ("Medium" if score >= 31 else "Low")
            return {
                "risk_score_raw": raw_str,
                "risk_score_numeric": str(score),
                "risk_score_valid": "True",
                "risk_label": label,
                "risk_quality_flag": "VALID_NUMERIC",
                "risk_score": score,
                "is_imputed": False,
            }
        else:
            return {
                "risk_score_raw": raw_str,
                "risk_score_numeric": "Unknown",
                "risk_score_valid": "False",
                "risk_label": "Invalid",
                "risk_quality_flag": "OUT_OF_RANGE",
                "risk_score": risk_median,
                "is_imputed": True,
            }
    except ValueError:
        pass

    # Check categorical strings (High, Medium, Low)
    lower = raw_str.lower()
    if lower in {"high", "medium", "low"}:
        return {
            "risk_score_raw": raw_str,
            "risk_score_numeric": "Unknown",
            "risk_score_valid": "True",
            "risk_label": raw_str.capitalize(),
            "risk_quality_flag": "CATEGORICAL_PRESERVED",
            "risk_score": risk_median,
            "is_imputed": True,
        }

    return {
        "risk_score_raw": raw_str,
        "risk_score_numeric": "Unknown",
        "risk_score_valid": "False",
        "risk_label": "Unmapped",
        "risk_quality_flag": "UNMAPPED_CATEGORICAL",
        "risk_score": risk_median,
        "is_imputed": True,
    }


# ============================================================
# FAILURE REASON
# ============================================================

FAILURE_REASON_MAP = {
    "invalid credentials": "invalid credentials", "invalid_credentials": "invalid credentials",
    "timeout": "timeout", "unknown user": "unknown user", "unknown_user": "unknown user",
    "bad token": "bad token", "bad_token": "bad token", "account locked": "account locked",
    "account_locked": "account locked", "wrong password": "wrong_password",
    "wrong_password": "wrong_password", "mfa failed": "MFA failed", "mfa_failed": "MFA failed",
    "otp expired": "OTP expired", "otp_expired": "OTP expired",
    "expired password": "expired password", "expired_password": "expired password",
}


def normalize_failure_reason(value):
    """Standardize known failure-reason variants."""

    value = normalize_text(value)

    if pd.isna(value):
        return np.nan

    key = str(value).strip().lower()

    return FAILURE_REASON_MAP.get(key, str(value).strip())


# ============================================================
# TIMESTAMP
# ============================================================

def parse_timestamp(value):
    """Parse mixed timestamp formats and 10-digit Unix epoch seconds."""

    value = normalize_text(value)

    if pd.isna(value):
        return pd.NaT

    value = str(value).strip()

    if re.fullmatch(r"\d{10}", value):
        try:
            return pd.to_datetime(int(value), unit="s", errors="coerce")
        except Exception:
            return pd.NaT

    return pd.to_datetime(value, errors="coerce", format="mixed")


# ============================================================
# LOAD JSON
# ============================================================

def load_iam_json(path):
    """Load IAM JSON robustly."""

    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return pd.DataFrame(data)

        if isinstance(data, dict):
            for key in ["data", "records", "events", "logs", "iam_logs"]:
                if key in data and isinstance(data[key], list):
                    return pd.DataFrame(data[key])
            return pd.DataFrame([data])

    except json.JSONDecodeError:
        pass

    try:
        return pd.read_json(path, lines=True)
    except Exception as exc:
        raise ValueError(f"Unable to parse IAM JSON file: {path}\nError: {exc}") from exc


# ============================================================
# MAIN PIPELINE
# ============================================================

def main():

    print("=" * 70)
    print("IAM DATA CLEANING & TRUST PIPELINE")
    print("=" * 70)

    # 1. LOAD RAW DATA
    print("\n[1/10] Loading raw IAM data...")
    if not RAW_FILE.exists():
        raise FileNotFoundError(f"Raw IAM file not found: {RAW_FILE}")

    df_raw = load_iam_json(RAW_FILE)
    raw_rows = len(df_raw)
    print(f"Raw rows: {raw_rows:,}")

    # Preserved raw risk score
    raw_risk_series = df_raw["risk_score"].copy() if "risk_score" in df_raw.columns else pd.Series([np.nan]*raw_rows)

    df = df_raw.copy()

    # 2. STANDARDIZE COLUMN NAMES
    print("\n[2/10] Standardizing column names...")
    df.columns = df.columns.astype(str).str.strip().str.lower().str.replace(" ", "_", regex=False)

    # 3. REMOVE EXACT DUPLICATES
    print("\n[3/10] Removing exact duplicate rows...")
    dup_mask = df.duplicated()
    duplicate_rows = int(dup_mask.sum())
    df = df.drop_duplicates().copy()
    raw_risk_series = raw_risk_series.loc[~dup_mask].copy()

    print(f"Exact duplicate rows removed: {duplicate_rows:,}")
    print(f"Rows remaining: {len(df):,}")

    # 4. BASIC TEXT NORMALIZATION
    print("\n[4/10] Normalizing textual fields...")
    text_cols = ["user_id", "username", "department", "event_type", "auth_method", "source_ip", "hostname", "device_id", "session_id", "geo_location", "failure_reason"]
    for col in text_cols:
        if col in df.columns:
            df[col] = df[col].apply(normalize_text)

    # 5. IDENTIFIERS + CATEGORIES
    print("\n[5/10] Standardizing identifiers and categorical values...")
    user_id_raw = df["user_id"].copy()
    df["user_id"] = df["user_id"].apply(normalize_user_id)
    df["department"] = df["department"].apply(normalize_department)
    df["event_type"] = df["event_type"].apply(normalize_event_type)
    df["auth_method"] = df["auth_method"].apply(normalize_auth_method)
    hostname_raw = df["hostname"].copy()
    df["hostname"] = df["hostname"].apply(normalize_hostname)

    # Track repair flag
    df["is_repaired"] = (user_id_raw != df["user_id"]) | (hostname_raw != df["hostname"])

    # 6. TIMESTAMP
    print("\n[6/10] Parsing timestamps...")
    parsed_ts = df["timestamp"].apply(parse_timestamp)
    df["timestamp"] = parsed_ts.dt.strftime("%Y-%m-%d %H:%M:%S")
    df["timestamp"] = df["timestamp"].replace({"NaT": np.nan, "": np.nan})

    # 7. IP VALIDATION
    print("\n[7/10] Validating source IP addresses...")
    df["source_ip"] = df["source_ip"].apply(normalize_ip)

    # 8. MFA + RISK SCORE PHASE B GOVERNANCE
    print("\n[8/10] Standardizing MFA and Phase B Risk Score Governance...")
    df["mfa_passed"] = df["mfa_passed"].apply(normalize_boolean)

    # Compute valid risk score median for legacy numerical float field
    valid_numerics = []
    for r in raw_risk_series:
        if r is not None and not pd.isna(r):
            try:
                num = float(str(r).split("/")[0])
                if 0 <= num <= 100:
                    valid_numerics.append(num)
            except ValueError:
                pass
    risk_median = float(np.median(valid_numerics)) if len(valid_numerics) > 0 else 50.0

    parsed_risk_list = [parse_risk_score_phase_b(r, risk_median) for r in raw_risk_series]
    risk_df = pd.DataFrame(parsed_risk_list)

    for c in ["risk_score_raw", "risk_score_numeric", "risk_score_valid", "risk_label", "risk_quality_flag", "risk_score", "is_imputed"]:
        df[c] = risk_df[c].values

    print(f"Risk score median used for legacy zero-missing field: {risk_median:.2f}")

    # 9. FAILURE REASON
    print("\n[9/10] Applying failure-reason semantics...")
    df["failure_reason"] = df["failure_reason"].apply(normalize_failure_reason)

    missing_reason = df["failure_reason"].isna() | df["failure_reason"].astype(str).str.strip().eq("") | df["failure_reason"].astype(str).str.upper().isin({"NA", "N/A", "NONE", "NULL", "NAN"})
    df.loc[df["event_type"].isin({"login_success", "other"}) & missing_reason, "failure_reason"] = "Not Applicable"
    df.loc[df["event_type"].eq("login_failed") & missing_reason, "failure_reason"] = "Unknown"

    # 10. ZERO-MISSING FINALIZATION & QUALITY STATUS
    print("\n[10/10] Finalizing zero-missing analytical dataset & quality metadata...")

    unknown_cols = ["event_id", "user_id", "username", "department", "auth_method", "source_ip", "hostname", "device_id", "session_id", "geo_location"]
    for col in unknown_cols:
        df[col] = df[col].replace({"": np.nan, "NA": np.nan, "N/A": np.nan, "NONE": np.nan, "NULL": np.nan}).fillna("Unknown")

    df["timestamp"] = df["timestamp"].replace({"": np.nan, "NA": np.nan, "N/A": np.nan, "NONE": np.nan, "NULL": np.nan}).fillna("Unknown")
    df["mfa_passed"] = df["mfa_passed"].map({True: "True", False: "False"}).fillna("Unknown")
    df["failure_reason"] = df["failure_reason"].replace({"": np.nan, "NA": np.nan, "N/A": np.nan, "NONE": np.nan, "NULL": np.nan}).fillna("Unknown")

    # Record data quality status
    df["data_quality_status"] = "VALID"
    df.loc[df["is_imputed"] == True, "data_quality_status"] = "IMPUTED"
    df.loc[df["is_repaired"] == True, "data_quality_status"] = "REPAIRED"
    df.loc[(df["timestamp"] == "Unknown") | (df["source_ip"] == "Unknown"), "data_quality_status"] = "UNKNOWN"

    df["is_imputed"] = df["is_imputed"].astype(str)
    df["is_repaired"] = df["is_repaired"].astype(str)

    # FINAL COLUMN SELECTION
    df = df[FINAL_COLUMNS].copy()

    # FINAL CHECKS
    missing_cells = int(df.isna().sum().sum())
    duplicate_rows_final = int(df.duplicated().sum())

    if missing_cells != 0:
        raise ValueError(f"Final IAM dataset contains {missing_cells} missing cells.")
    if duplicate_rows_final != 0:
        raise ValueError("Final IAM dataset contains duplicate rows.")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print("\n" + "=" * 70)
    print("IAM CLEANING COMPLETE")
    print("=" * 70)
    print(f"Output: {OUTPUT_FILE}")
    print(f"Final rows: {len(df):,}")
    print(f"Final columns: {len(df.columns)}")
    print("RESULT: IAM CLEANING PASSED")


if __name__ == "__main__":
    main()