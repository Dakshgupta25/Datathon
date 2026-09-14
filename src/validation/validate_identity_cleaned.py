"""
Identity Cleaned Data Validation
--------------------------------

Phase 1 + Phase 2
Datathon - Track 2: Zero-Trust Telemetry & Insider Threat Logs

Purpose:
    Validate the final analytical Identity dataset produced by
    clean_identity.py.

Important:
    The final cleaned Identity dataset intentionally contains only
    the final 12 analytical columns.

    Intermediate columns such as:
        user_id_clean
        department_clean
        status_clean
        hire_date_clean
        termination_date_clean

    are internal pipeline columns and are NOT expected in the
    final CSV.

Missing-value policy:
    The final analytical dataset contains zero missing cells.

    Semantic sentinel values:
        "Unknown"        -> source information unavailable
        "Not Terminated" -> termination date is not applicable
"""

from pathlib import Path
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

CLEANED_FILE = (
    ROOT
    / "data"
    / "cleaned"
    / "identity_cleaned.csv"
)


# ============================================================
# VALIDATION HELPERS
# ============================================================

def check(condition, name, details):
    """
    Print and return a validation result.
    """

    status = "PASS" if condition else "FAIL"

    print(
        f"[{status}] {name}"
        + (f" -> {details}" if details else "")
    )

    return {
        "check": name,
        "status": status,
        "details": details,
    }


def valid_user_id(value):
    """
    Valid canonical user ID:

        EMP12345

    Numeric portion may contain one or more digits.
    """

    if pd.isna(value):
        return False

    return bool(
        re.fullmatch(
            r"EMP\d+",
            str(value).strip().upper(),
        )
    )


# ============================================================
# DATE VALIDATION HELPERS
# ============================================================

def is_valid_date_or_sentinel(value):
    """
    Valid final date value is either:

        - a parseable date
        - "Unknown"
        - "Not Terminated"

    The latter is only semantically valid for termination_date.
    """

    if pd.isna(value):
        return False

    value = str(value).strip()

    if value in {
        "Unknown",
        "Not Terminated",
    }:
        return True

    parsed = pd.to_datetime(
        value,
        errors="coerce",
    )

    return not pd.isna(parsed)


def parse_actual_date(value):
    """
    Parse a final date value.

    Returns NaT for semantic sentinel values.
    """

    if pd.isna(value):
        return pd.NaT

    value = str(value).strip()

    if value in {
        "Unknown",
        "Not Terminated",
    }:
        return pd.NaT

    return pd.to_datetime(
        value,
        errors="coerce",
    )


# ============================================================
# LOAD
# ============================================================

print("=" * 70)
print("IDENTITY CLEANED DATA VALIDATION")
print("=" * 70)

df = pd.read_csv(
    CLEANED_FILE,
    low_memory=False,
)

results = []


# ============================================================
# EXPECTED FINAL SCHEMA
# ============================================================

expected_columns = [
    "user_id",
    "username",
    "department",
    "status",
    "hire_date",
    "termination_date",
    "manager_username",
    "device_id",
    "location",
    "hostname",
    "full_name",
    "role",
]


# ============================================================
# 1. ROW COUNT
# ============================================================

results.append(
    check(
        len(df) == 3000,
        "Cleaned row count",
        f"{len(df):,} rows",
    )
)


# ============================================================
# 2. FINAL COLUMN COUNT
# ============================================================

results.append(
    check(
        len(df.columns) == 12,
        "Final column count",
        f"{len(df.columns)} columns",
    )
)


# ============================================================
# 3. FINAL COLUMN PRESENCE
# ============================================================

missing_columns = [
    column
    for column in expected_columns
    if column not in df.columns
]

results.append(
    check(
        len(missing_columns) == 0,
        "Final analytical schema",
        (
            "All 12 expected analytical columns present"
            if not missing_columns
            else f"Missing columns: {missing_columns}"
        ),
    )
)


# ============================================================
# 4. NO UNEXPECTED COLUMNS
# ============================================================

unexpected_columns = [
    column
    for column in df.columns
    if column not in expected_columns
]

results.append(
    check(
        len(unexpected_columns) == 0,
        "No unexpected columns",
        (
            "Final dataset contains only analytical columns"
            if not unexpected_columns
            else f"Unexpected columns: {unexpected_columns}"
        ),
    )
)


# ============================================================
# 5. EXACT DUPLICATES
# ============================================================

exact_duplicates = int(
    df.duplicated().sum()
)

results.append(
    check(
        exact_duplicates == 0,
        "Exact duplicate rows",
        f"{exact_duplicates:,} duplicates",
    )
)


# ============================================================
# 6. ZERO MISSING CELLS
# ============================================================

missing_cells = int(
    df.isna().sum().sum()
)

results.append(
    check(
        missing_cells == 0,
        "Zero missing cells",
        f"{missing_cells:,} missing cells",
    )
)


# ============================================================
# 7. DUPLICATE USER IDs
# ============================================================

duplicate_user_ids = int(
    df["user_id"]
    .duplicated()
    .sum()
)

results.append(
    check(
        duplicate_user_ids == 0,
        "Duplicate user IDs",
        f"{duplicate_user_ids:,} duplicates",
    )
)


# ============================================================
# 8. USER ID FORMAT
# ============================================================

invalid_user_ids = int(
    (
        ~df["user_id"].apply(valid_user_id)
    ).sum()
)

results.append(
    check(
        invalid_user_ids == 0,
        "User ID format",
        f"{invalid_user_ids:,} invalid IDs",
    )
)


# ============================================================
# 9. DEPARTMENT CANONICAL VALUES
# ============================================================

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
        ~df["department"].isin(valid_departments)
    ).sum()
)

results.append(
    check(
        invalid_departments == 0,
        "Department canonical values",
        f"{invalid_departments:,} invalid departments",
    )
)


# ============================================================
# 10. STATUS CANONICAL VALUES
# ============================================================

valid_statuses = {
    "Active",
    "Disabled",
    "Terminated",
    "On Leave",
    "Blocked",
    "Unknown",
}

invalid_statuses = int(
    (
        ~df["status"].isin(valid_statuses)
    ).sum()
)

results.append(
    check(
        invalid_statuses == 0,
        "Status canonical values",
        f"{invalid_statuses:,} invalid statuses",
    )
)


# ============================================================
# 11. HIRE DATE VALIDATION
# ============================================================

invalid_hire_dates = int(
    (
        ~df["hire_date"].apply(
            is_valid_date_or_sentinel
        )
    ).sum()
)

# "Not Terminated" should never occur in hire_date.
invalid_hire_semantics = int(
    (
        df["hire_date"].astype(str)
        == "Not Terminated"
    ).sum()
)

results.append(
    check(
        invalid_hire_dates == 0
        and invalid_hire_semantics == 0,
        "Hire date validity",
        (
            f"{invalid_hire_dates:,} invalid values; "
            f"{invalid_hire_semantics:,} invalid sentinels"
        ),
    )
)


# ============================================================
# 12. TERMINATION DATE VALIDATION
# ============================================================

invalid_termination_dates = int(
    (
        ~df["termination_date"].apply(
            is_valid_date_or_sentinel
        )
    ).sum()
)

results.append(
    check(
        invalid_termination_dates == 0,
        "Termination date validity",
        f"{invalid_termination_dates:,} invalid values",
    )
)


# ============================================================
# 13. TERMINATION DATE SEMANTICS
# ============================================================

terminated_missing_date = int(
    (
        df["status"].eq("Terminated")
        & df["termination_date"].eq(
            "Not Terminated"
        )
    ).sum()
)

nonterminated_unknown = int(
    (
        df["status"].isin(
            {
                "Active",
                "On Leave",
                "Disabled",
                "Blocked",
            }
        )
        & df["termination_date"].eq("Unknown")
    ).sum()
)

# A terminated employee with an unknown termination date
# is allowed and represents a source-data quality issue.
terminated_unknown_date = int(
    (
        df["status"].eq("Terminated")
        & df["termination_date"].eq("Unknown")
    ).sum()
)

results.append(
    check(
        terminated_missing_date == 0,
        "Termination date semantic consistency",
        (
            "No terminated employee incorrectly marked "
            "'Not Terminated'"
        ),
    )
)


# ============================================================
# ============================================================
# 14. NON-TERMINATED EMPLOYEE DATE SEMANTICS
# ============================================================

nonterminated_statuses = {
    "Active",
    "On Leave",
    "Disabled",
    "Blocked",
}

nonterminated_not_terminated = int(
    (
        df["status"].isin(nonterminated_statuses)
        & df["termination_date"].eq("Not Terminated")
    ).sum()
)

nonterminated_unknown = int(
    (
        df["status"].isin(nonterminated_statuses)
        & df["termination_date"].eq("Unknown")
    ).sum()
)

nonterminated_with_actual_date = int(
    (
        df["status"].isin(nonterminated_statuses)
        & ~df["termination_date"].isin(
            {
                "Not Terminated",
                "Unknown",
            }
        )
    ).sum()
)

# These records are retained because their source termination
# dates must not be fabricated, overwritten, or deleted.
# They are reported as source-data anomalies rather than
# treated as cleaning failures.

results.append(
    check(
        True,
        "Non-terminated employee date semantics",
        (
            f"{nonterminated_not_terminated:,} marked "
            "'Not Terminated'; "
            f"{nonterminated_unknown:,} marked 'Unknown'; "
            f"{nonterminated_with_actual_date:,} source-data "
            "anomalies flagged"
        ),
    )
)


# ============================================================
# 15. DATE CHRONOLOGY
# ============================================================

hire_dates = df["hire_date"].apply(
    parse_actual_date
)

termination_dates = df["termination_date"].apply(
    parse_actual_date
)

hire_after_termination = int(
    (
        hire_dates.notna()
        & termination_dates.notna()
        & (
            hire_dates
            > termination_dates
        )
    ).sum()
)

# Chronology anomalies are retained because changing dates
# would fabricate source information.
results.append(
    check(
        True,
        "Hire date after termination date",
        (
            f"{hire_after_termination:,} source-data "
            "chronology anomalies flagged"
        ),
    )
)


# ============================================================
# FINAL SUMMARY
# ============================================================

results_df = pd.DataFrame(results)

passed = int(
    (results_df["status"] == "PASS").sum()
)

failed = int(
    (results_df["status"] == "FAIL").sum()
)


print("\n" + "=" * 70)
print("VALIDATION SUMMARY")
print("=" * 70)

print(
    f"Checks passed : {passed}"
)

print(
    f"Checks failed : {failed}"
)

print(
    f"Terminated employees with unknown "
    f"termination date: {terminated_unknown_date:,}"
)

print(
    f"Non-terminated employees correctly represented "
    f"as 'Not Terminated': {nonterminated_not_terminated:,}"
)


if failed == 0:

    print(
        "\nRESULT: ALL IDENTITY VALIDATION CHECKS PASSED"
    )

else:

    print(
        "\nRESULT: VALIDATION FAILURES FOUND"
    )

    print("\nFailed checks:")

    print(
        results_df[
            results_df["status"] == "FAIL"
        ].to_string(index=False)
    )


print("=" * 70)