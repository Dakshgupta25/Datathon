from pathlib import Path
import ipaddress
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "track2_iam_audit_trail.json"
)

CLEAN_PATH = (
    PROJECT_ROOT
    / "data"
    / "cleaned"
    / "iam_cleaned.csv"
)


# ============================================================
# EXPECTED FINAL SCHEMA
# ============================================================

EXPECTED_COLUMNS = [
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
# VALIDATION HELPERS
# ============================================================

def is_valid_ip(value):
    """
    Validate an IP address.

    Unknown is a valid semantic sentinel representing
    unavailable source information.
    """

    if pd.isna(value):
        return False

    value = str(value).strip()

    if value == "Unknown":
        return True

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_user_id(value):
    """
    Valid canonical user ID:

        EMP12345
    """

    if pd.isna(value):
        return False

    value = str(value).strip().upper()

    if value == "Unknown":
        return False

    return bool(
        re.fullmatch(
            r"EMP\d+",
            value,
        )
    )


def is_valid_timestamp(value):
    """
    Validate final timestamp.

    Unknown is accepted as the documented semantic
    representation of unavailable/invalid timestamps.
    """

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
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("IAM CLEANED DATA VALIDATION")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. LOAD
    # --------------------------------------------------------

    print("\n[1/10] Loading raw and cleaned data...")

    raw = pd.read_json(
        RAW_PATH
    )

    # IMPORTANT:
    # Preserve semantic sentinels such as:
    #     Unknown
    #     Not Applicable
    #
    # Otherwise pandas may automatically convert them to NaN.
    clean = pd.read_csv(
        CLEAN_PATH,
        low_memory=False,
        keep_default_na=False,
    )

    print(
        f"Raw rows     : {len(raw):,}"
    )

    print(
        f"Cleaned rows : {len(clean):,}"
    )

    # --------------------------------------------------------
    # 2. ROW COUNT
    # --------------------------------------------------------

    print("\n[2/10] Checking row count...")

    expected_cleaned_rows = len(raw) - 500

    row_count_pass = (
        len(clean) == expected_cleaned_rows
        and len(clean) == 20000
    )

    print(
        f"Expected cleaned rows : "
        f"{expected_cleaned_rows:,}"
    )

    print(
        f"Actual cleaned rows   : "
        f"{len(clean):,}"
    )

    # --------------------------------------------------------
    # 3. FINAL SCHEMA
    # --------------------------------------------------------

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

    schema_pass = (
        len(missing_columns) == 0
        and len(unexpected_columns) == 0
        and len(clean.columns) == 15
    )

    print(
        f"Expected columns : {len(EXPECTED_COLUMNS)}"
    )

    print(
        f"Actual columns   : {len(clean.columns)}"
    )

    print(
        "Missing columns  : "
        + (
            "None"
            if not missing_columns
            else str(missing_columns)
        )
    )

    print(
        "Unexpected columns: "
        + (
            "None"
            if not unexpected_columns
            else str(unexpected_columns)
        )
    )

    # --------------------------------------------------------
    # 4. DUPLICATES
    # --------------------------------------------------------

    print("\n[4/10] Checking duplicates...")

    duplicate_rows = int(
        clean.duplicated().sum()
    )

    duplicate_event_ids = int(
        clean["event_id"]
        .duplicated()
        .sum()
    )

    print(
        f"Exact duplicate rows remaining : "
        f"{duplicate_rows:,}"
    )

    print(
        f"Duplicate event IDs remaining  : "
        f"{duplicate_event_ids:,}"
    )

    # --------------------------------------------------------
    # 5. USER IDs
    # --------------------------------------------------------

    print("\n[5/10] Validating user IDs...")

    invalid_user_ids = int(
        (
            ~clean["user_id"]
            .apply(is_valid_user_id)
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

    # --------------------------------------------------------
    # 6. DEPARTMENT + EVENT TYPE
    # --------------------------------------------------------

    print(
        "\n[6/10] Checking departments and event types..."
    )

    valid_departments = {
        "IT",
        "Human Resources",
        "Finance",
        "Operations",
        "Procurement",
        "Marketing",
        "Sales",
        "Legal",
        "R&D",
        "Customer Support",
        "Support",
        "Call Center",
        "Brand",
        "Compliance",
        "Innovation",
        "Supply Chain",
        "IT Support",
        "Unknown",
    }

    invalid_departments = int(
        (
            ~clean["department"]
            .isin(valid_departments)
        ).sum()
    )

    valid_event_types = {
        "login_success",
        "login_failed",
        "other",
    }

    invalid_event_types = int(
        (
            ~clean["event_type"]
            .isin(valid_event_types)
        ).sum()
    )

    print(
        f"Invalid department values : "
        f"{invalid_departments:,}"
    )

    print(
        f"Invalid event type values  : "
        f"{invalid_event_types:,}"
    )

    print("\nEvent type distribution:")

    print(
        clean["event_type"]
        .value_counts(dropna=False)
        .to_string()
    )

    # --------------------------------------------------------
    # 7. MFA
    # --------------------------------------------------------

    print(
        "\n[7/10] Validating MFA values..."
    )

    mfa_values = (
        clean["mfa_passed"]
        .astype(str)
        .str.strip()
    )

    valid_mfa_values = {
        "True",
        "False",
        "Unknown",
    }

    invalid_mfa = int(
        (
            ~mfa_values
            .isin(valid_mfa_values)
        ).sum()
    )

    print(
        "MFA values:"
    )

    print(
        mfa_values
        .value_counts(dropna=False)
        .to_string()
    )

    print(
        f"\nInvalid MFA values : "
        f"{invalid_mfa:,}"
    )

    # --------------------------------------------------------
    # 8. SOURCE IP
    # --------------------------------------------------------

    print(
        "\n[8/10] Validating source IP..."
    )

    invalid_ips = int(
        (
            ~clean["source_ip"]
            .apply(is_valid_ip)
        ).sum()
    )

    unknown_ips = int(
        clean["source_ip"]
        .eq("Unknown")
        .sum()
    )

    valid_ips = int(
        (
            clean["source_ip"]
            .apply(is_valid_ip)
            & ~clean["source_ip"]
            .eq("Unknown")
        ).sum()
    )

    print(
        f"Valid IPs    : {valid_ips:,}"
    )

    print(
        f"Unknown IPs  : {unknown_ips:,}"
    )

    print(
        f"Invalid IPs  : {invalid_ips:,}"
    )

    # --------------------------------------------------------
    # 9. RISK SCORE
    # --------------------------------------------------------

    print(
        "\n[9/10] Validating risk scores..."
    )

    risk_numeric = pd.to_numeric(
        clean["risk_score"],
        errors="coerce",
    )

    invalid_risk_format = int(
        risk_numeric.isna().sum()
    )

    outside_range = int(
        (
            risk_numeric.notna()
            & (
                (risk_numeric < 0)
                | (risk_numeric > 100)
            )
        ).sum()
    )

    print(
        f"Invalid/non-numeric risk values : "
        f"{invalid_risk_format:,}"
    )

    print(
        f"Risk values outside 0-100       : "
        f"{outside_range:,}"
    )

    print(
        f"Risk score minimum              : "
        f"{risk_numeric.min():.2f}"
    )

    print(
        f"Risk score maximum              : "
        f"{risk_numeric.max():.2f}"
    )

    print(
        f"Risk score median               : "
        f"{risk_numeric.median():.2f}"
    )

    # --------------------------------------------------------
    # 10. TIMESTAMP + COMPLETENESS
    # --------------------------------------------------------

    print(
        "\n[10/10] Validating timestamps and final completeness..."
    )

    invalid_timestamps = int(
        (
            ~clean["timestamp"]
            .apply(is_valid_timestamp)
        ).sum()
    )

    unknown_timestamps = int(
        clean["timestamp"]
        .eq("Unknown")
        .sum()
    )

    valid_actual_timestamps = int(
        (
            clean["timestamp"]
            .apply(is_valid_timestamp)
            & ~clean["timestamp"]
            .eq("Unknown")
        ).sum()
    )

    total_missing_cells = int(
        clean.isna().sum().sum()
    )

    print(
        f"Valid timestamps   : "
        f"{valid_actual_timestamps:,}"
    )

    print(
        f"Unknown timestamps : "
        f"{unknown_timestamps:,}"
    )

    print(
        f"Invalid timestamps : "
        f"{invalid_timestamps:,}"
    )

    print(
        f"Final missing cells: "
        f"{total_missing_cells:,}"
    )

    # --------------------------------------------------------
    # FAILURE REASON SEMANTICS
    # --------------------------------------------------------

    print(
        "\nChecking failure reason semantics..."
    )

    failure_reason = (
        clean["failure_reason"]
        .astype(str)
        .str.strip()
    )

    # For login_success and other events, a failure reason
    # normally does not apply.
    #
    # Both "Not Applicable" and "Unknown" are accepted.
    non_failure_events = clean[
        "event_type"
    ].isin(
        {
            "login_success",
            "other",
        }
    )

    invalid_non_failure_reason = int(
        (
            non_failure_events
            & ~failure_reason.isin(
                {
                    "Not Applicable",
                    "Unknown",
                }
            )
        ).sum()
    )

    # For login_failed, "Not Applicable" would be semantically
    # incorrect because a failure event should either have an
    # actual reason or explicitly have an unknown reason.
    login_failed_na = int(
        (
            clean["event_type"].eq(
                "login_failed"
            )
            & failure_reason.eq(
                "Not Applicable"
            )
        ).sum()
    )

    login_failed_unknown = int(
        (
            clean["event_type"].eq(
                "login_failed"
            )
            & failure_reason.eq(
                "Unknown"
            )
        ).sum()
    )

    print(
        f"Invalid non-failure event reasons : "
        f"{invalid_non_failure_reason:,}"
    )

    print(
        f"Login failures marked Unknown     : "
        f"{login_failed_unknown:,}"
    )

    print(
        f"Login failures marked "
        f"Not Applicable                  : "
        f"{login_failed_na:,}"
    )

    # ========================================================
    # OVERALL VALIDATION
    # ========================================================

    all_pass = (
        row_count_pass
        and schema_pass
        and duplicate_rows == 0
        and duplicate_event_ids == 0
        and invalid_user_ids == 0
        and unknown_user_ids == 0
        and invalid_departments == 0
        and invalid_event_types == 0
        and invalid_mfa == 0
        and invalid_ips == 0
        and invalid_risk_format == 0
        and outside_range == 0
        and invalid_timestamps == 0
        and total_missing_cells == 0
        and invalid_non_failure_reason == 0
        and login_failed_na == 0
    )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print("\n" + "=" * 70)
    print("IAM VALIDATION SUMMARY")
    print("=" * 70)

    print(
        f"Row count correct          : "
        f"{'PASS' if row_count_pass else 'FAIL'}"
    )

    print(
        f"Final schema correct       : "
        f"{'PASS' if schema_pass else 'FAIL'}"
    )

    print(
        f"Exact duplicates           : "
        f"{duplicate_rows:,}"
    )

    print(
        f"Duplicate event IDs        : "
        f"{duplicate_event_ids:,}"
    )

    print(
        f"Invalid user IDs           : "
        f"{invalid_user_ids:,}"
    )

    print(
        f"Invalid departments        : "
        f"{invalid_departments:,}"
    )

    print(
        f"Invalid event types        : "
        f"{invalid_event_types:,}"
    )

    print(
        f"Invalid MFA values         : "
        f"{invalid_mfa:,}"
    )

    print(
        f"Invalid source IPs         : "
        f"{invalid_ips:,}"
    )

    print(
        f"Risk values outside range  : "
        f"{outside_range:,}"
    )

    print(
        f"Invalid timestamps         : "
        f"{invalid_timestamps:,}"
    )

    print(
        f"Final missing cells        : "
        f"{total_missing_cells:,}"
    )

    print(
        f"Invalid failure semantics  : "
        f"{invalid_non_failure_reason:,}"
    )

    print(
        f"Login failures marked "
        f"'Not Applicable'         : "
        f"{login_failed_na:,}"
    )

    print("\n" + "=" * 70)

    if all_pass:
        print(
            "RESULT: ALL IAM VALIDATION CHECKS PASSED"
        )
    else:
        print(
            "RESULT: IAM VALIDATION FAILURES FOUND"
        )

    print("=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()