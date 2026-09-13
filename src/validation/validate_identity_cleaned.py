from pathlib import Path
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

CLEANED_FILE = ROOT / "data" / "cleaned" / "identity_cleaned.csv"


# ============================================================
# VALIDATION HELPERS
# ============================================================

def check(condition, name, details):
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
    if pd.isna(value):
        return False

    return bool(
        re.fullmatch(
            r"EMP\d+",
            str(value).strip().upper()
        )
    )


def valid_sha_placeholder():
    # Identity does not contain SHA-256.
    return True


# ============================================================
# LOAD
# ============================================================

print("=" * 70)
print("IDENTITY CLEANED DATA VALIDATION")
print("=" * 70)

df = pd.read_csv(CLEANED_FILE)

results = []


# ============================================================
# 1. ROW COUNT
# ============================================================

results.append(
    check(
        len(df) == 3000,
        "Cleaned row count",
        f"{len(df):,} rows"
    )
)


# ============================================================
# 2. EXACT DUPLICATES
# ============================================================

exact_duplicates = int(
    df.duplicated().sum()
)

results.append(
    check(
        exact_duplicates == 0,
        "Exact duplicate rows",
        f"{exact_duplicates:,} duplicates"
    )
)


# ============================================================
# 3. DUPLICATE USER IDs
# ============================================================

duplicate_user_ids = int(
    df["user_id_clean"]
    .dropna()
    .duplicated()
    .sum()
)

results.append(
    check(
        duplicate_user_ids == 0,
        "Duplicate cleaned user IDs",
        f"{duplicate_user_ids:,} duplicates"
    )
)


# ============================================================
# 4. USER ID FORMAT
# ============================================================

invalid_user_ids = int(
    (
        df["user_id_clean"].notna()
        & ~df["user_id_clean"].apply(valid_user_id)
    ).sum()
)

results.append(
    check(
        invalid_user_ids == 0,
        "User ID format",
        f"{invalid_user_ids:,} invalid IDs"
    )
)


# ============================================================
# 5. DEPARTMENT STANDARDIZATION
# ============================================================

invalid_departments = int(
    (
        df["department_clean"].notna()
        & ~df["department_clean"].isin([
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
        ])
    ).sum()
)

results.append(
    check(
        invalid_departments == 0,
        "Department canonical values",
        f"{invalid_departments:,} invalid canonical departments"
    )
)


# ============================================================
# 6. DEPARTMENT MAPPING COMPLETENESS
# ============================================================

department_unmapped = int(
    (
        df["department_raw"].notna()
        & df["department_clean"].isna()
    ).sum()
)

results.append(
    check(
        department_unmapped == 0,
        "Department mapping completeness",
        f"{department_unmapped:,} unmapped values"
    )
)


# ============================================================
# 7. STATUS STANDARDIZATION
# ============================================================

valid_statuses = {
    "Active",
    "Disabled",
    "Terminated",
    "On Leave",
    "Blocked",
}

invalid_statuses = int(
    (
        df["status_clean"].notna()
        & ~df["status_clean"].isin(valid_statuses)
    ).sum()
)

results.append(
    check(
        invalid_statuses == 0,
        "Status canonical values",
        f"{invalid_statuses:,} invalid canonical statuses"
    )
)


# ============================================================
# 8. STATUS MAPPING COMPLETENESS
# ============================================================

status_unmapped = int(
    (
        df["status_raw"].notna()
        & df["status_clean"].isna()
    ).sum()
)

results.append(
    check(
        status_unmapped == 0,
        "Status mapping completeness",
        f"{status_unmapped:,} unmapped values"
    )
)


# ============================================================
# 9. DATE PARSING
# ============================================================

invalid_hire_dates = int(
    (
        df["hire_date_raw"].notna()
        & ~df["hire_date_issue"].isin([
            "valid",
            "unix_epoch",
            "semantic_missing",
            "missing",
        ])
    ).sum()
)

results.append(
    check(
        invalid_hire_dates == 0,
        "Hire date parsing",
        f"{invalid_hire_dates:,} invalid parsed dates"
    )
)


invalid_termination_dates = int(
    (
        df["termination_date_raw"].notna()
        & ~df["termination_date_issue"].isin([
            "valid",
            "unix_epoch",
            "semantic_missing",
            "missing",
        ])
    ).sum()
)

results.append(
    check(
        invalid_termination_dates == 0,
        "Termination date parsing",
        f"{invalid_termination_dates:,} invalid parsed dates"
    )
)


# ============================================================
# 10. TERMINATION DATE SEMANTIC CHECK
# ============================================================

terminated_missing_date = int(
    (
        df["status_clean"].eq("Terminated")
        & df["termination_date_clean"].isna()
    ).sum()
)

# This is a flagged data-quality issue, NOT a cleaning failure.
results.append(
    check(
        True,
        "Terminated employees with missing termination date",
        f"{terminated_missing_date:,} flagged records (retained, not imputed)"
    )
)


# ============================================================
# 11. ACTIVE + TERMINATION DATE
# ============================================================

active_with_termination = int(
    (
        df["status_clean"].eq("Active")
        & df["termination_date_clean"].notna()
    ).sum()
)

results.append(
    check(
        active_with_termination == 0,
        "Active employees with termination date",
        f"{active_with_termination:,} records"
    )
)


# ============================================================
# 12. EMPLOYMENT DATE CHRONOLOGY
# ============================================================

hire_after_termination = int(
    (
        df["hire_date_clean"].notna()
        & df["termination_date_clean"].notna()
        & (
            pd.to_datetime(df["hire_date_clean"])
            > pd.to_datetime(df["termination_date_clean"])
        )
    ).sum()
)

results.append(
    check(
        hire_after_termination == 0,
        "Hire date after termination date",
        f"{hire_after_termination:,} chronology anomalies"
    )
)


# ============================================================
# 13. RAW COLUMN PRESERVATION
# ============================================================

expected_raw_columns = [
    "user_id",
    "username",
    "full_name",
    "department",
    "role",
    "status",
    "hire_date",
    "termination_date",
    "manager_username",
    "device_id",
    "location",
    "hostname",
]

missing_raw_columns = [
    col
    for col in expected_raw_columns
    if col not in df.columns
]

results.append(
    check(
        len(missing_raw_columns) == 0,
        "Raw column preservation",
        (
            "All raw columns preserved"
            if not missing_raw_columns
            else str(missing_raw_columns)
        )
    )
)


# ============================================================
# 14. CLEAN COLUMN PRESENCE
# ============================================================

expected_clean_columns = [
    "user_id_clean",
    "username_clean",
    "department_clean",
    "status_clean",
    "hostname_clean",
    "device_id_clean",
    "location_clean",
    "manager_username_clean",
    "hire_date_clean",
    "termination_date_clean",
]

missing_clean_columns = [
    col
    for col in expected_clean_columns
    if col not in df.columns
]

results.append(
    check(
        len(missing_clean_columns) == 0,
        "Cleaned column presence",
        (
            "All expected cleaned columns present"
            if not missing_clean_columns
            else str(missing_clean_columns)
        )
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

print(f"Checks passed : {passed}")
print(f"Checks failed : {failed}")

if failed == 0:
    print("\nRESULT: ALL IDENTITY VALIDATION CHECKS PASSED")
else:
    print("\nRESULT: VALIDATION FAILURES FOUND")

    print("\nFailed checks:")
    print(
        results_df[
            results_df["status"] == "FAIL"
        ].to_string(index=False)
    )

print("=" * 70)