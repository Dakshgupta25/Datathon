from pathlib import Path
import re

import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

CLEANED_FILE = ROOT / "data" / "cleaned" / "firewall_cleaned.csv"


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


def valid_ipv4(value):
    """
    Validate IPv4 address.
    """
    if pd.isna(value):
        return False

    value = str(value).strip()

    parts = value.split(".")

    if len(parts) != 4:
        return False

    try:
        return all(
            0 <= int(part) <= 255
            and str(int(part)) == part
            for part in parts
        )
    except ValueError:
        return False


def valid_port(value):
    """
    Valid TCP/UDP port range: 1-65535.
    """
    if pd.isna(value):
        return False

    try:
        value = int(float(value))
        return 1 <= value <= 65535
    except (ValueError, TypeError):
        return False


def valid_nonnegative_number(value):
    """
    Validate non-negative byte counts.
    """
    if pd.isna(value):
        return False

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
    }


def valid_action(value):
    if pd.isna(value):
        return False

    return str(value).strip().title() in {
        "Allow",
        "Deny",
        "Drop",
        "Block",
    }


def valid_threat_flag(value):
    if pd.isna(value):
        return False

    if isinstance(value, bool):
        return True

    return str(value).strip().lower() in {
        "true",
        "false",
    }


# ============================================================
# LOAD
# ============================================================

print("=" * 70)
print("FIREWALL CLEANED DATA VALIDATION")
print("=" * 70)

df = pd.read_csv(CLEANED_FILE)

results = []


# ============================================================
# 1. ROW COUNT
# ============================================================

results.append(
    check(
        len(df) == 30000,
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
# 3. DUPLICATE LOG IDs
# ============================================================

duplicate_log_ids = int(
    df["log_id"]
    .dropna()
    .duplicated()
    .sum()
)

results.append(
    check(
        duplicate_log_ids == 0,
        "Duplicate log IDs",
        f"{duplicate_log_ids:,} duplicates"
    )
)


# ============================================================
# 4. TIMESTAMP VALIDATION
# ============================================================

clean_timestamp = pd.to_datetime(
    df["timestamp_clean"],
    errors="coerce"
)

invalid_timestamps = int(
    (
        df["timestamp_clean"].notna()
        & clean_timestamp.isna()
    ).sum()
)

results.append(
    check(
        invalid_timestamps == 0,
        "Clean timestamp validity",
        f"{invalid_timestamps:,} invalid timestamps"
    )
)


# ============================================================
# 5. SOURCE IP
# ============================================================

invalid_src_ip = int(
    (
        df["src_ip_clean"].notna()
        & ~df["src_ip_clean"].apply(valid_ipv4)
    ).sum()
)

results.append(
    check(
        invalid_src_ip == 0,
        "Source IP validity",
        f"{invalid_src_ip:,} invalid cleaned source IPs"
    )
)


# ============================================================
# 6. DESTINATION IP
# ============================================================

invalid_dst_ip = int(
    (
        df["dst_ip_clean"].notna()
        & ~df["dst_ip_clean"].apply(valid_ipv4)
    ).sum()
)

results.append(
    check(
        invalid_dst_ip == 0,
        "Destination IP validity",
        f"{invalid_dst_ip:,} invalid cleaned destination IPs"
    )
)


# ============================================================
# 7. SOURCE PORT
# ============================================================

invalid_src_port = int(
    (
        df["src_port_clean"].notna()
        & ~df["src_port_clean"].apply(valid_port)
    ).sum()
)

results.append(
    check(
        invalid_src_port == 0,
        "Source port validity",
        f"{invalid_src_port:,} invalid cleaned source ports"
    )
)


# ============================================================
# 8. DESTINATION PORT
# ============================================================

invalid_dst_port = int(
    (
        df["dst_port_clean"].notna()
        & ~df["dst_port_clean"].apply(valid_port)
    ).sum()
)

results.append(
    check(
        invalid_dst_port == 0,
        "Destination port validity",
        f"{invalid_dst_port:,} invalid cleaned destination ports"
    )
)


# ============================================================
# 9. BYTE COUNTS
# ============================================================

invalid_bytes_sent = int(
    (
        df["bytes_sent_clean"].notna()
        & ~df["bytes_sent_clean"].apply(
            valid_nonnegative_number
        )
    ).sum()
)

invalid_bytes_received = int(
    (
        df["bytes_received_clean"].notna()
        & ~df["bytes_received_clean"].apply(
            valid_nonnegative_number
        )
    ).sum()
)

results.append(
    check(
        invalid_bytes_sent == 0,
        "Bytes sent validity",
        f"{invalid_bytes_sent:,} invalid values"
    )
)

results.append(
    check(
        invalid_bytes_received == 0,
        "Bytes received validity",
        f"{invalid_bytes_received:,} invalid values"
    )
)


# ============================================================
# 10. PROTOCOL
# ============================================================

invalid_protocol = int(
    (
        df["protocol_clean"].notna()
        & ~df["protocol_clean"].apply(valid_protocol)
    ).sum()
)

results.append(
    check(
        invalid_protocol == 0,
        "Protocol standardization",
        f"{invalid_protocol:,} invalid protocols"
    )
)


# ============================================================
# 11. ACTION
# ============================================================

invalid_action = int(
    (
        df["action_clean"].notna()
        & ~df["action_clean"].apply(valid_action)
    ).sum()
)

results.append(
    check(
        invalid_action == 0,
        "Action standardization",
        f"{invalid_action:,} invalid actions"
    )
)


# ============================================================
# 12. THREAT FLAG
# ============================================================

invalid_threat_flag = int(
    (
        df["threat_flag_clean"].notna()
        & ~df["threat_flag_clean"].apply(valid_threat_flag)
    ).sum()
)

results.append(
    check(
        invalid_threat_flag == 0,
        "Threat flag validity",
        f"{invalid_threat_flag:,} invalid threat flags"
    )
)


# ============================================================
# 13. RAW COLUMN PRESERVATION
# ============================================================

expected_raw_columns = [
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

missing_raw_columns = [
    column
    for column in expected_raw_columns
    if column not in df.columns
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
    "timestamp_clean",
    "timestamp_valid",
    "src_ip_clean",
    "src_ip_valid",
    "dst_ip_clean",
    "dst_ip_valid",
    "src_port_clean",
    "src_port_valid",
    "dst_port_clean",
    "dst_port_valid",
    "bytes_sent_clean",
    "bytes_received_clean",
    "protocol_clean",
    "action_clean",
    "threat_flag_clean",
]

missing_clean_columns = [
    column
    for column in expected_clean_columns
    if column not in df.columns
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
# 15. VALIDATION FLAG CONSISTENCY
# ============================================================

flag_columns = [
    "timestamp_valid",
    "src_ip_valid",
    "dst_ip_valid",
    "src_port_valid",
    "dst_port_valid",
]

flag_failures = 0

for column in flag_columns:
    if column not in df.columns:
        flag_failures += 1
        continue

    # Validation flags may use semantic states:
    # valid, invalid, missing
    # Timestamp flags may also be boolean-like after CSV reload.
    values = (
        df[column]
        .dropna()
        .astype(str)
        .str.strip()
        .str.lower()
    )

    invalid_values = (
        ~values.isin({
            "valid",
            "invalid",
            "missing",
            "true",
            "false",
            "0",
            "1",
        })
    ).sum()

    flag_failures += int(invalid_values)

results.append(
    check(
        flag_failures == 0,
        "Validation flag consistency",
        f"{flag_failures:,} invalid flag values"
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
    print("\nRESULT: ALL FIREWALL VALIDATION CHECKS PASSED")
else:
    print("\nRESULT: VALIDATION FAILURES FOUND")

    print("\nFailed checks:")
    print(
        results_df[
            results_df["status"] == "FAIL"
        ].to_string(index=False)
    )

print("=" * 70)