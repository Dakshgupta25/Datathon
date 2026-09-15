from pathlib import Path
import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

CLEANED_DIR = ROOT / "data" / "cleaned"
REPORT_DIR = ROOT / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# EXPECTED FINAL SCHEMAS
# ============================================================

EXPECTED_COLUMNS = {
    "iam": [
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
    ],
    "endpoint": [
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
    ],
    "firewall": [
        "log_id",
        "timestamp",
        "hostname",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "action",
        "bytes_sent",
        "bytes_received",
        "session_id",
        "threat_flag",
        "rule_name",
        "geo_country",
    ],
    "identity": [
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
    ],
}


# ============================================================
# LOAD CLEANED DATA
# ============================================================

print("=" * 70)
print("CLEANED DATA JOIN VALIDATION")
print("=" * 70)

iam = pd.read_csv(CLEANED_DIR / "iam_cleaned.csv")
endpoint = pd.read_csv(CLEANED_DIR / "endpoint_cleaned.csv")
firewall = pd.read_csv(CLEANED_DIR / "firewall_cleaned.csv")
identity = pd.read_csv(CLEANED_DIR / "identity_cleaned.csv")

print("\nDatasets loaded:")
print(f"IAM       : {len(iam):,} rows")
print(f"Endpoint  : {len(endpoint):,} rows")
print(f"Firewall  : {len(firewall):,} rows")
print(f"Identity  : {len(identity):,} rows")


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def clean_key(series):
    """
    Normalize a final analytical join key.

    'Unknown' is treated as unavailable and therefore excluded
    from join coverage calculations.
    """
    return (
        series
        .astype("string")
        .str.strip()
        .replace("", pd.NA)
        .replace("Unknown", pd.NA)
    )


def clean_hostname_key(series):
    """
    Create a deterministic hostname join key.

    This does not modify the final analytical hostname column.

    Rules:
    1. Trim whitespace.
    2. Convert to uppercase.
    3. Remove optional .CORP.LOCAL suffix.
    4. Convert underscores to hyphens.
    5. Treat Unknown as unavailable.
    """
    return (
        series
        .astype("string")
        .str.strip()
        .replace("", pd.NA)
        .replace("Unknown", pd.NA)
        .str.upper()
        .str.replace(r"\.CORP\.LOCAL$", "", regex=True)
        .str.replace("_", "-", regex=False)
    )


def record(check_name, condition, details):
    status = "PASS" if condition else "FAIL"

    results.append(
        {
            "check": check_name,
            "status": status,
            "details": details,
        }
    )

    print(
        f"[{status}] {check_name}"
        + (f" -> {details}" if details else "")
    )


results = []


# ============================================================
# 1. FINAL SCHEMA VALIDATION
# ============================================================

print("\n[1/9] Validating final analytical schemas...")

datasets = {
    "IAM": iam,
    "Endpoint": endpoint,
    "Firewall": firewall,
    "Identity": identity,
}

schema_failures = 0

for name, df in datasets.items():

    expected = EXPECTED_COLUMNS[name.lower()]
    actual = list(df.columns)

    missing = [
        column
        for column in expected
        if column not in actual
    ]

    unexpected = [
        column
        for column in actual
        if column not in expected
    ]

    valid = (
        actual == expected
        and not missing
        and not unexpected
    )

    if not valid:
        schema_failures += 1

    print(
        f"{name:10} -> "
        f"{len(actual)} columns | "
        f"missing={missing or 'None'} | "
        f"unexpected={unexpected or 'None'}"
    )

record(
    "Final analytical schemas",
    schema_failures == 0,
    f"{schema_failures} dataset schema failures",
)


# ============================================================
# 2. IDENTITY USER ID UNIQUENESS
# ============================================================

print("\n[2/9] Checking Identity user_id uniqueness...")

identity_user_key = clean_key(identity["user_id"])

duplicate_identity_users = (
    identity_user_key
    .dropna()
    .value_counts()
)

duplicate_identity_users = duplicate_identity_users[
    duplicate_identity_users > 1
]

duplicate_user_count = len(duplicate_identity_users)

record(
    "Identity unique user_id join key",
    duplicate_user_count == 0,
    f"{duplicate_user_count:,} duplicate cleaned user IDs",
)


# ============================================================
# 3. IDENTITY HOSTNAME UNIQUENESS
# ============================================================

print("\n[3/9] Checking Identity hostname uniqueness...")

identity_hostname_key = clean_hostname_key(
    identity["hostname"]
)

duplicate_identity_hosts = (
    identity_hostname_key
    .dropna()
    .value_counts()
)

duplicate_identity_hosts = duplicate_identity_hosts[
    duplicate_identity_hosts > 1
]

duplicate_host_count = len(duplicate_identity_hosts)

record(
    "Identity hostname uniqueness",
    duplicate_host_count == 0,
    f"{duplicate_host_count:,} duplicate cleaned hostnames",
)


# ============================================================
# CREATE MASTER KEY SETS
# ============================================================

identity_user_ids = set(
    identity_user_key
    .dropna()
    .unique()
)

identity_hostnames = set(
    identity_hostname_key
    .dropna()
    .unique()
)


# ============================================================
# 4. IAM -> IDENTITY BY USER ID
# ============================================================

print("\n[4/9] Checking IAM -> Identity user_id coverage...")

iam_user_key = clean_key(iam["user_id"])

iam_mask = iam_user_key.notna()

iam_matches = (
    iam_user_key.loc[iam_mask]
    .isin(identity_user_ids)
)

iam_matched = int(iam_matches.sum())
iam_unmatched = int((~iam_matches).sum())
iam_usable = int(iam_mask.sum())

record(
    "IAM -> Identity user_id join",
    iam_unmatched == 0,
    (
        f"{iam_matched:,} matched / "
        f"{iam_unmatched:,} unmatched "
        f"among {iam_usable:,} usable IDs"
    ),
)


# ============================================================
# 5. ENDPOINT -> IDENTITY BY USER ID
# ============================================================

print("\n[5/9] Checking Endpoint -> Identity user_id coverage...")

endpoint_user_key = clean_key(endpoint["user_id"])

endpoint_user_mask = endpoint_user_key.notna()

endpoint_user_matches = (
    endpoint_user_key.loc[endpoint_user_mask]
    .isin(identity_user_ids)
)

endpoint_user_matched = int(
    endpoint_user_matches.sum()
)

endpoint_user_unmatched = int(
    (~endpoint_user_matches).sum()
)

endpoint_user_usable = int(
    endpoint_user_mask.sum()
)

record(
    "Endpoint -> Identity user_id join",
    endpoint_user_unmatched == 0,
    (
        f"{endpoint_user_matched:,} matched / "
        f"{endpoint_user_unmatched:,} unmatched "
        f"among {endpoint_user_usable:,} usable IDs"
    ),
)


# ============================================================
# 6. ENDPOINT -> IDENTITY BY HOSTNAME
# ============================================================

print("\n[6/9] Checking Endpoint -> Identity hostname coverage...")

endpoint_hostname_key = clean_hostname_key(
    endpoint["hostname"]
)

endpoint_host_mask = endpoint_hostname_key.notna()

endpoint_host_matches = (
    endpoint_hostname_key.loc[endpoint_host_mask]
    .isin(identity_hostnames)
)

endpoint_host_matched = int(
    endpoint_host_matches.sum()
)

endpoint_host_unmatched = int(
    (~endpoint_host_matches).sum()
)

endpoint_host_usable = int(
    endpoint_host_mask.sum()
)

endpoint_host_coverage = (
    endpoint_host_matched / endpoint_host_usable
    if endpoint_host_usable
    else 0
)

print(
    f"Matched   : {endpoint_host_matched:,}"
)

print(
    f"Unmatched : {endpoint_host_unmatched:,}"
)

print(
    f"Usable    : {endpoint_host_usable:,}"
)

print(
    f"Coverage  : {endpoint_host_coverage:.2%}"
)

# Hostname coverage gaps are reported as INFO rather than
# treated as cleaning failures because they may originate
# from source-data coverage rather than incorrect cleaning.

results.append(
    {
        "check": "Endpoint -> Identity hostname join",
        "status": "INFO",
        "details": (
            f"{endpoint_host_matched:,} matched / "
            f"{endpoint_host_unmatched:,} unmatched "
            f"among {endpoint_host_usable:,} usable hostnames "
            f"({endpoint_host_coverage:.2%} coverage)"
        ),
    }
)

print(
    "[INFO] Endpoint -> Identity hostname join"
    f" -> {endpoint_host_matched:,} matched / "
    f"{endpoint_host_unmatched:,} unmatched "
    f"among {endpoint_host_usable:,} usable hostnames "
    f"({endpoint_host_coverage:.2%} coverage)"
)


# ============================================================
# 7. FIREWALL -> IDENTITY BY HOSTNAME
# ============================================================

print("\n[7/9] Checking Firewall -> Identity hostname coverage...")

firewall_hostname_key = clean_hostname_key(
    firewall["hostname"]
)

firewall_host_mask = firewall_hostname_key.notna()

firewall_host_matches = (
    firewall_hostname_key.loc[firewall_host_mask]
    .isin(identity_hostnames)
)

firewall_host_matched = int(
    firewall_host_matches.sum()
)

firewall_host_unmatched = int(
    (~firewall_host_matches).sum()
)

firewall_host_usable = int(
    firewall_host_mask.sum()
)

firewall_host_coverage = (
    firewall_host_matched / firewall_host_usable
    if firewall_host_usable
    else 0
)

print(
    f"Matched   : {firewall_host_matched:,}"
)

print(
    f"Unmatched : {firewall_host_unmatched:,}"
)

print(
    f"Usable    : {firewall_host_usable:,}"
)

print(
    f"Coverage  : {firewall_host_coverage:.2%}"
)

results.append(
    {
        "check": "Firewall -> Identity hostname join",
        "status": "INFO",
        "details": (
            f"{firewall_host_matched:,} matched / "
            f"{firewall_host_unmatched:,} unmatched "
            f"among {firewall_host_usable:,} usable hostnames "
            f"({firewall_host_coverage:.2%} coverage)"
        ),
    }
)

print(
    "[INFO] Firewall -> Identity hostname join"
    f" -> {firewall_host_matched:,} matched / "
    f"{firewall_host_unmatched:,} unmatched "
    f"among {firewall_host_usable:,} usable hostnames "
    f"({firewall_host_coverage:.2%} coverage)"
)


# ============================================================
# 8. IAM -> FIREWALL SESSION ID COVERAGE
# ============================================================

print("\n[8/9] Checking IAM -> Firewall session_id coverage...")

iam_session_key = clean_key(iam["session_id"])

firewall_session_key = clean_key(
    firewall["session_id"]
)

firewall_sessions = set(
    firewall_session_key
    .dropna()
    .unique()
)

iam_session_mask = iam_session_key.notna()

iam_session_matches = (
    iam_session_key.loc[iam_session_mask]
    .isin(firewall_sessions)
)

iam_session_matched = int(
    iam_session_matches.sum()
)

iam_session_unmatched = int(
    (~iam_session_matches).sum()
)

iam_session_usable = int(
    iam_session_mask.sum()
)

iam_session_coverage = (
    iam_session_matched / iam_session_usable
    if iam_session_usable
    else 0
)

results.append(
    {
        "check": "IAM -> Firewall session_id coverage",
        "status": "INFO",
        "details": (
            f"{iam_session_matched:,} matched / "
            f"{iam_session_unmatched:,} unmatched "
            f"among {iam_session_usable:,} usable session IDs "
            f"({iam_session_coverage:.2%} coverage)"
        ),
    }
)

print(
    "[INFO] IAM -> Firewall session_id coverage"
    f" -> {iam_session_matched:,} matched / "
    f"{iam_session_unmatched:,} unmatched "
    f"among {iam_session_usable:,} usable session IDs "
    f"({iam_session_coverage:.2%} coverage)"
)


# ============================================================
# 9. JOIN KEY COMPLETENESS
# ============================================================

print("\n[9/9] Checking join-key completeness...")

join_key_checks = {
    "IAM user_id": iam["user_id"],
    "Endpoint user_id": endpoint["user_id"],
    "Identity user_id": identity["user_id"],
}

join_key_missing = {}

for name, series in join_key_checks.items():

    missing_count = int(
        clean_key(series).isna().sum()
    )

    join_key_missing[name] = missing_count

    print(
        f"{name:20} -> "
        f"{missing_count:,} unavailable"
    )

# This is informational because 'Unknown' is a valid semantic
# representation in the final zero-missing analytical datasets.

total_unavailable = sum(
    join_key_missing.values()
)

results.append(
    {
        "check": "Primary user_id join-key completeness",
        "status": "INFO",
        "details": (
            f"{total_unavailable:,} unavailable semantic "
            "user_id values across IAM, Endpoint and Identity"
        ),
    }
)


# ============================================================
# SAVE REPORT
# ============================================================

results_df = pd.DataFrame(results)

REPORT_FILE = (
    REPORT_DIR /
    "cleaned_join_validation_summary.csv"
)

results_df.to_csv(
    REPORT_FILE,
    index=False,
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("JOIN VALIDATION SUMMARY")
print("=" * 70)

passed = int(
    (results_df["status"] == "PASS").sum()
)

failed = int(
    (results_df["status"] == "FAIL").sum()
)

info = int(
    (results_df["status"] == "INFO").sum()
)

print(f"Checks passed : {passed}")
print(f"Checks failed : {failed}")
print(f"Informational: {info}")

print("\nValidation results:")
print(
    results_df.to_string(index=False)
)

print("\nGenerated:")
print(
    f"  {REPORT_FILE}"
)

print("\n" + "=" * 70)

if failed == 0:
    print(
        "RESULT: ALL CLEANED JOIN VALIDATION CHECKS PASSED"
    )
else:
    print(
        "RESULT: CLEANED JOIN VALIDATION REQUIRES REVIEW"
    )

print("=" * 70)