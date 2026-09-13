import pandas as pd
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]
CLEANED_DIR = ROOT / "data" / "cleaned"
REPORT_DIR = ROOT / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


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
# HELPER
# ============================================================

def clean_key(series):
    return (
        series
        .astype("string")
        .str.strip()
        .replace("", pd.NA)
    )

def clean_hostname_key(series):
    """
    Canonicalize hostnames for cross-dataset joins only.

    Rules:
    1. Trim surrounding whitespace.
    2. Convert to uppercase.
    3. Remove the optional .corp.local suffix.
    4. Convert underscores to hyphens.

    This does not modify the source/cleaned hostname columns.
    It only creates a deterministic join key.
    """
    return (
        series
        .astype("string")
        .str.strip()
        .replace("", pd.NA)
        .str.upper()
        .str.replace(r"\.CORP\.LOCAL$", "", regex=True)
        .str.replace("_", "-", regex=False)
    )


results = []


def record(check_name, condition, details):
    status = "PASS" if condition else "FAIL"

    results.append({
        "check": check_name,
        "status": status,
        "details": details,
    })

    print(
        f"[{status}] {check_name}"
        + (f" -> {details}" if details else "")
    )


# ============================================================
# NORMALIZE JOIN KEYS
# ============================================================

for df in [iam, endpoint, identity]:
    df["user_id_join"] = clean_key(df["user_id_clean"])

for df in [endpoint, firewall, identity, iam]:
    hostname_column = (
        df["hostname_clean"]
        if "hostname_clean" in df.columns
        else df["hostname"]
    )
    df["hostname_join"] = clean_hostname_key(hostname_column)

iam["session_id_join"] = clean_key(iam["session_id"])
firewall["session_id_join"] = clean_key(firewall["session_id"])


# ============================================================
# IDENTITY MASTER KEY SETS
# ============================================================

identity_user_ids = set(
    identity["user_id_join"]
    .dropna()
    .unique()
)

identity_hostnames = set(
    identity["hostname_join"]
    .dropna()
    .unique()
)


# ============================================================
# 1. IAM -> IDENTITY BY USER ID
# ============================================================

iam_user_mask = iam["user_id_join"].notna()

iam_user_matches = (
    iam.loc[iam_user_mask, "user_id_join"]
    .isin(identity_user_ids)
)

iam_matched = int(iam_user_matches.sum())
iam_unmatched = int((~iam_user_matches).sum())

record(
    "IAM -> Identity user_id join",
    iam_unmatched == 0,
    (
        f"{iam_matched:,} matched / "
        f"{iam_unmatched:,} unmatched "
        f"among {int(iam_user_mask.sum()):,} usable IDs"
    ),
)


# ============================================================
# 2. ENDPOINT -> IDENTITY BY USER ID
# ============================================================

endpoint_user_mask = endpoint["user_id_join"].notna()

endpoint_user_matches = (
    endpoint.loc[endpoint_user_mask, "user_id_join"]
    .isin(identity_user_ids)
)

endpoint_user_matched = int(endpoint_user_matches.sum())
endpoint_user_unmatched = int((~endpoint_user_matches).sum())

record(
    "Endpoint -> Identity user_id join",
    endpoint_user_unmatched == 0,
    (
        f"{endpoint_user_matched:,} matched / "
        f"{endpoint_user_unmatched:,} unmatched "
        f"among {int(endpoint_user_mask.sum()):,} usable IDs"
    ),
)


# ============================================================
# 3. ENDPOINT -> IDENTITY BY HOSTNAME
# ============================================================

endpoint_host_mask = endpoint["hostname_join"].notna()

endpoint_host_matches = (
    endpoint.loc[endpoint_host_mask, "hostname_join"]
    .isin(identity_hostnames)
)

endpoint_host_matched = int(endpoint_host_matches.sum())
endpoint_host_unmatched = int((~endpoint_host_matches).sum())

record(
    "Endpoint -> Identity hostname join",
    endpoint_host_unmatched == 0,
    (
        f"{endpoint_host_matched:,} matched / "
        f"{endpoint_host_unmatched:,} unmatched "
        f"among {int(endpoint_host_mask.sum()):,} usable hostnames"
    ),
)


# ============================================================
# 4. FIREWALL -> IDENTITY BY HOSTNAME
# ============================================================

firewall_host_mask = firewall["hostname_join"].notna()

firewall_host_matches = (
    firewall.loc[firewall_host_mask, "hostname_join"]
    .isin(identity_hostnames)
)

firewall_host_matched = int(firewall_host_matches.sum())
firewall_host_unmatched = int((~firewall_host_matches).sum())

record(
    "Firewall -> Identity hostname join",
    firewall_host_unmatched == 0,
    (
        f"{firewall_host_matched:,} matched / "
        f"{firewall_host_unmatched:,} unmatched "
        f"among {int(firewall_host_mask.sum()):,} usable hostnames"
    ),
)


# ============================================================
# 5. IAM -> FIREWALL SESSION ID COVERAGE
# ============================================================

firewall_sessions = set(
    firewall["session_id_join"]
    .dropna()
    .unique()
)

iam_session_mask = iam["session_id_join"].notna()

iam_session_matches = (
    iam.loc[iam_session_mask, "session_id_join"]
    .isin(firewall_sessions)
)

iam_session_matched = int(iam_session_matches.sum())
iam_session_unmatched = int((~iam_session_matches).sum())

results.append({
    "check": "IAM -> Firewall session_id coverage",
    "status": "INFO",
    "details": (
        f"{iam_session_matched:,} matched / "
        f"{iam_session_unmatched:,} unmatched "
        f"among {int(iam_session_mask.sum()):,} usable session IDs"
    ),
})

print(
    "[INFO] IAM -> Firewall session_id coverage"
    + (
        f" -> {iam_session_matched:,} matched / "
        f"{iam_session_unmatched:,} unmatched "
        f"among {int(iam_session_mask.sum()):,} usable session IDs"
    )
)

# ============================================================
# 6. DUPLICATE JOIN KEYS IN IDENTITY
# ============================================================

duplicate_identity_users = (
    identity["user_id_join"]
    .dropna()
    .value_counts()
)

duplicate_identity_users = duplicate_identity_users[
    duplicate_identity_users > 1
]

record(
    "Identity unique user_id join key",
    len(duplicate_identity_users) == 0,
    f"{len(duplicate_identity_users):,} duplicate cleaned user IDs",
)


# ============================================================
# 7. DUPLICATE HOSTNAMES IN IDENTITY
# ============================================================

duplicate_identity_hosts = (
    identity["hostname_join"]
    .dropna()
    .value_counts()
)

duplicate_identity_hosts = duplicate_identity_hosts[
    duplicate_identity_hosts > 1
]

record(
    "Identity hostname uniqueness",
    len(duplicate_identity_hosts) == 0,
    f"{len(duplicate_identity_hosts):,} duplicate cleaned hostnames",
)

# ============================================================
# SAVE DETAILED REPORTS
# ============================================================

pd.DataFrame(results).to_csv(
    REPORT_DIR / "cleaned_join_validation_summary.csv",
    index=False,
)

print("\n" + "=" * 70)
print("JOIN VALIDATION SUMMARY")
print("=" * 70)

results_df = pd.DataFrame(results)

passed = int((results_df["status"] == "PASS").sum())
failed = int((results_df["status"] == "FAIL").sum())
info = int((results_df["status"] == "INFO").sum())

print(f"Checks passed : {passed}")
print(f"Checks failed : {failed}")
print(f"Informational: {info}")

if failed == 0:
    print("\nRESULT: ALL CLEANED JOIN VALIDATION CHECKS PASSED")
else:
    print("\nRESULT: CLEANED JOIN VALIDATION REQUIRES REVIEW")

print("=" * 70)
print("\nGenerated:")
print("  reports/cleaned_join_validation_summary.csv")