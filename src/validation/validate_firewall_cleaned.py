from pathlib import Path
import re
import ipaddress

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = ROOT / "data" / "raw" / "track2_firewall_logs.csv"
CLEANED_FILE = ROOT / "data" / "cleaned" / "firewall_cleaned.csv"
REPORT_FILE = ROOT / "reports" / "firewall_validation_report.csv"


# ============================================================
# EXPECTED FINAL ANALYTICAL SCHEMA
# ============================================================

EXPECTED_COLUMNS = [
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
]


# ============================================================
# VALIDATION HELPERS
# ============================================================

def check(condition, name, value, expected):
    status = "PASS" if condition else "FAIL"

    print(
        f"[{'PASS' if condition else 'FAIL'}] "
        f"{name} -> {value}"
    )

    return {
        "check": name,
        "value": value,
        "expected": expected,
        "status": status,
    }


def valid_ipv4(value):
    """
    Validate a final analytical IPv4 value.

    'Unknown' is an accepted semantic representation for
    unavailable/invalid source IPs after cleaning.
    """
    if pd.isna(value):
        return False

    value = str(value).strip()

    if value == "Unknown":
        return True

    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4
    except ValueError:
        return False


def valid_port(value):
    """
    Valid network port range: 1-65535.

    'Unknown' is accepted as the semantic representation
    for unavailable source values.
    """
    if pd.isna(value):
        return False

    value = str(value).strip()

    if value == "Unknown":
        return True

    try:
        number = float(value)

        if not number.is_integer():
            return False

        number = int(number)

        return 1 <= number <= 65535

    except (ValueError, TypeError):
        return False


def valid_nonnegative_number(value):
    """
    Validate non-negative byte counts.

    'Unknown' is accepted as the semantic representation
    for unavailable source values.
    """
    if pd.isna(value):
        return False

    value = str(value).strip()

    if value == "Unknown":
        return True

    try:
        return float(value) >= 0
    except (ValueError, TypeError):
        return False


def valid_protocol(value):
    if pd.isna(value):
        return False

    return str(value).strip().upper() in {
        "TCP",
        "UDP",
        "ICMP",
        "Unknown",
    }


def valid_action(value):
    if pd.isna(value):
        return False

    return str(value).strip().title() in {
        "Allow",
        "Deny",
        "Drop",
        "Block",
        "Unknown",
    }


def valid_threat_flag(value):
    """
    Accept boolean values and their canonical string forms.
    """
    if pd.isna(value):
        return False

    if isinstance(value, bool):
        return True

    value = str(value).strip().lower()

    return value in {
        "true",
        "false",
    }


def valid_log_id(value):
    """
    log_id must be present and non-empty.
    """
    if pd.isna(value):
        return False

    return str(value).strip() != ""


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("FIREWALL CLEANED DATA VALIDATION")
print("=" * 70)


# ============================================================
# LOAD DATA
# ============================================================

print("\n[1/12] Loading raw and cleaned data...")

raw_df = pd.read_csv(RAW_FILE)
df = pd.read_csv(CLEANED_FILE)

print(f"Raw rows     : {len(raw_df):,}")
print(f"Cleaned rows : {len(df):,}")


results = []


# ============================================================
# 1. ROW COUNT
# ============================================================

print("\n[2/12] Checking row count...")

raw_exact_duplicates = int(
    raw_df.duplicated().sum()
)

expected_cleaned_rows = len(raw_df) - raw_exact_duplicates
actual_cleaned_rows = len(df)

results.append(
    check(
        actual_cleaned_rows == expected_cleaned_rows,
        "Cleaned row count",
        f"{actual_cleaned_rows:,} rows",
        f"{expected_cleaned_rows:,} rows",
    )
)


# ============================================================
# 2. FINAL ANALYTICAL SCHEMA
# ============================================================

print("\n[3/12] Checking final analytical schema...")

actual_columns = list(df.columns)

missing_columns = [
    column
    for column in EXPECTED_COLUMNS
    if column not in actual_columns
]

unexpected_columns = [
    column
    for column in actual_columns
    if column not in EXPECTED_COLUMNS
]

schema_valid = (
    len(actual_columns) == len(EXPECTED_COLUMNS)
    and not missing_columns
    and not unexpected_columns
    and actual_columns == EXPECTED_COLUMNS
)

print(f"Expected columns : {len(EXPECTED_COLUMNS)}")
print(f"Actual columns   : {len(actual_columns)}")
print(f"Missing columns  : {missing_columns or 'None'}")
print(f"Unexpected columns: {unexpected_columns or 'None'}")

results.append(
    check(
        schema_valid,
        "Final analytical schema",
        f"{len(actual_columns)} columns",
        f"{len(EXPECTED_COLUMNS)} columns",
    )
)


# ============================================================
# 3. DUPLICATES
# ============================================================

print("\n[4/12] Checking duplicates...")

exact_duplicates = int(
    df.duplicated().sum()
)

duplicate_log_ids = int(
    df["log_id"]
    .dropna()
    .astype(str)
    .str.strip()
    .duplicated()
    .sum()
)

print(f"Exact duplicate rows remaining : {exact_duplicates}")
print(f"Duplicate log IDs remaining    : {duplicate_log_ids}")

results.append(
    check(
        exact_duplicates == 0,
        "Exact duplicate rows",
        exact_duplicates,
        0,
    )
)

results.append(
    check(
        duplicate_log_ids == 0,
        "Duplicate log IDs",
        duplicate_log_ids,
        0,
    )
)


# ============================================================
# 4. LOG ID VALIDATION
# ============================================================

print("\n[5/12] Validating log IDs...")

invalid_log_ids = int(
    (~df["log_id"].apply(valid_log_id))
    .sum()
)

print(f"Invalid log IDs : {invalid_log_ids}")

results.append(
    check(
        invalid_log_ids == 0,
        "Log ID validity",
        invalid_log_ids,
        0,
    )
)


# ============================================================
# 5. TIMESTAMP VALIDATION
# ============================================================

print("\n[6/12] Validating timestamps...")

timestamp_text = (
    df["timestamp"]
    .astype(str)
    .str.strip()
)

timestamp_unknown = int(
    (timestamp_text == "Unknown").sum()
)

timestamp_series = pd.to_datetime(
    df.loc[
        timestamp_text != "Unknown",
        "timestamp"
    ],
    errors="coerce",
)

invalid_timestamps = int(
    timestamp_series.isna().sum()
)

print(f"Unknown timestamps : {timestamp_unknown:,}")
print(f"Invalid timestamps : {invalid_timestamps:,}")

results.append(
    check(
        invalid_timestamps == 0,
        "Timestamp validity",
        invalid_timestamps,
        0,
    )
)


# ============================================================
# 6. IP VALIDATION
# ============================================================

print("\n[7/12] Validating IP addresses...")

invalid_src_ip = int(
    (~df["src_ip"].apply(valid_ipv4))
    .sum()
)

invalid_dst_ip = int(
    (~df["dst_ip"].apply(valid_ipv4))
    .sum()
)

print(f"Invalid source IPs      : {invalid_src_ip:,}")
print(f"Invalid destination IPs : {invalid_dst_ip:,}")

results.append(
    check(
        invalid_src_ip == 0,
        "Source IP validity",
        invalid_src_ip,
        0,
    )
)

results.append(
    check(
        invalid_dst_ip == 0,
        "Destination IP validity",
        invalid_dst_ip,
        0,
    )
)


# ============================================================
# 7. PORT VALIDATION
# ============================================================

print("\n[8/12] Validating network ports...")

invalid_src_port = int(
    (~df["src_port"].apply(valid_port))
    .sum()
)

invalid_dst_port = int(
    (~df["dst_port"].apply(valid_port))
    .sum()
)

print(f"Invalid source ports      : {invalid_src_port:,}")
print(f"Invalid destination ports : {invalid_dst_port:,}")

results.append(
    check(
        invalid_src_port == 0,
        "Source port validity",
        invalid_src_port,
        0,
    )
)

results.append(
    check(
        invalid_dst_port == 0,
        "Destination port validity",
        invalid_dst_port,
        0,
    )
)


# ============================================================
# 8. BYTE VALIDATION
# ============================================================

print("\n[9/12] Validating byte counts...")

invalid_bytes_sent = int(
    (~df["bytes_sent"].apply(valid_nonnegative_number))
    .sum()
)

invalid_bytes_received = int(
    (~df["bytes_received"].apply(valid_nonnegative_number))
    .sum()
)

print(f"Invalid bytes sent     : {invalid_bytes_sent:,}")
print(f"Invalid bytes received : {invalid_bytes_received:,}")

results.append(
    check(
        invalid_bytes_sent == 0,
        "Bytes sent validity",
        invalid_bytes_sent,
        0,
    )
)

results.append(
    check(
        invalid_bytes_received == 0,
        "Bytes received validity",
        invalid_bytes_received,
        0,
    )
)


# ============================================================
# 9. CATEGORICAL STANDARDIZATION
# ============================================================

print("\n[10/12] Validating categorical standardization...")

invalid_protocol = int(
    (~df["protocol"].apply(valid_protocol))
    .sum()
)

invalid_action = int(
    (~df["action"].apply(valid_action))
    .sum()
)

invalid_threat_flag = int(
    (~df["threat_flag"].apply(valid_threat_flag))
    .sum()
)

print(f"Invalid protocol values   : {invalid_protocol:,}")
print(f"Invalid action values     : {invalid_action:,}")
print(f"Invalid threat flag values: {invalid_threat_flag:,}")

results.append(
    check(
        invalid_protocol == 0,
        "Protocol standardization",
        invalid_protocol,
        0,
    )
)

results.append(
    check(
        invalid_action == 0,
        "Action standardization",
        invalid_action,
        0,
    )
)

results.append(
    check(
        invalid_threat_flag == 0,
        "Threat flag validity",
        invalid_threat_flag,
        0,
    )
)


# ============================================================
# 10. FINAL COMPLETENESS
# ============================================================

print("\n[11/12] Checking final completeness...")

final_missing_cells = int(
    df.isna().sum().sum()
)

empty_string_cells = int(
    (
        df.astype(str)
        .apply(lambda column: column.str.strip().eq("").sum())
        .sum()
    )
)

print(f"Final missing cells : {final_missing_cells:,}")
print(f"Empty string cells  : {empty_string_cells:,}")

results.append(
    check(
        final_missing_cells == 0,
        "Final missing cells",
        final_missing_cells,
        0,
    )
)

results.append(
    check(
        empty_string_cells == 0,
        "Empty string cells",
        empty_string_cells,
        0,
    )
)


# ============================================================
# 11. SOURCE DUPLICATE RECONCILIATION
# ============================================================

print("\n[12/12] Reconciling duplicate removal...")

duplicates_removed = len(raw_df) - len(df)

print(f"Raw exact duplicates       : {raw_exact_duplicates:,}")
print(f"Rows removed from raw data : {duplicates_removed:,}")
print(f"Expected rows              : {expected_cleaned_rows:,}")
print(f"Actual cleaned rows        : {actual_cleaned_rows:,}")

results.append(
    check(
        duplicates_removed == raw_exact_duplicates,
        "Duplicate removal reconciliation",
        duplicates_removed,
        raw_exact_duplicates,
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


# ============================================================
# SAVE REPORT
# ============================================================

REPORT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True,
)

results_df.to_csv(
    REPORT_FILE,
    index=False,
)


# ============================================================
# PRINT SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("FIREWALL VALIDATION SUMMARY")
print("=" * 70)

print(f"PASS checks : {passed}")
print(f"FAIL checks : {failed}")

print("\nValidation results:")
print(
    results_df.to_string(index=False)
)

print("\nGenerated:")
print(f"  {REPORT_FILE}")

print("\n" + "=" * 70)

if failed == 0:
    print("RESULT: ALL FIREWALL VALIDATION CHECKS PASSED")
else:
    print("RESULT: FIREWALL VALIDATION FAILURES FOUND")

print("=" * 70)