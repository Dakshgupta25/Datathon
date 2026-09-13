import pandas as pd
import numpy as np
import ipaddress
import re
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

RAW_FILE = Path("data/raw/track2_firewall_logs.csv")
CLEANED_DIR = Path("data/cleaned")
REPORT_DIR = Path("reports")

CLEANED_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_ip(value):
    """Validate and normalize an IP address."""

    if pd.isna(value):
        return pd.NA

    text = str(value).strip()

    if not text:
        return pd.NA

    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return pd.NA


def validate_ip(value):
    """Return valid / invalid / missing status."""

    if pd.isna(value):
        return "missing"

    text = str(value).strip()

    if not text:
        return "missing"

    try:
        ipaddress.ip_address(text)
        return "valid"
    except ValueError:
        return "invalid"


def normalize_port(value):
    """
    Normalize network port values.

    Valid range:
        1-65535

    Port 0 is treated as invalid because it is not a valid
    TCP/UDP endpoint port for this dataset.
    """

    if pd.isna(value):
        return np.nan

    try:
        number = float(value)

        if not number.is_integer():
            return np.nan

        number = int(number)

        if 1 <= number <= 65535:
            return number

        return np.nan

    except (ValueError, TypeError):
        return np.nan


def validate_port(value):
    """Return valid / invalid / missing status."""

    if pd.isna(value):
        return "missing"

    try:
        number = float(value)

        if number.is_integer() and 0 <= number <= 65535:
            return "valid"

        return "invalid"

    except (ValueError, TypeError):
        return "invalid"


def parse_bytes(value):
    """
    Convert byte values into numeric bytes.

    Supported:
        1024
        20.48 MB
        500 KB
        1.5 GB
        100 B

    Negative byte values are treated as invalid.
    """

    if pd.isna(value):
        return np.nan

    text = str(value).strip().upper()

    if not text:
        return np.nan

    # Plain numeric value
    try:
        number = float(text)

        if number < 0:
            return np.nan

        return number

    except ValueError:
        pass

    # Values with units
    match = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)?)\s*(B|KB|MB|GB)",
        text
    )

    if not match:
        return np.nan

    number = float(match.group(1))
    unit = match.group(2)

    multipliers = {
        "B": 1,
        "KB": 1024,
        "MB": 1024 ** 2,
        "GB": 1024 ** 3,
    }

    return number * multipliers[unit]


def normalize_protocol(value):
    """Standardize protocol representations."""

    if pd.isna(value):
        return pd.NA

    text = str(value).strip().upper()

    mapping = {
        "TCP": "TCP",
        "TCP/6": "TCP",
        "6": "TCP",

        "UDP": "UDP",
        "UDP/17": "UDP",
        "17": "UDP",

        "ICMP": "ICMP",
        "PING": "ICMP",
        "1": "ICMP",
    }

    return mapping.get(text, pd.NA)


def normalize_action(value):
    """Standardize firewall actions."""

    if pd.isna(value):
        return pd.NA

    text = str(value).strip().upper()

    mapping = {
        "PERMIT": "ALLOW",
        "PASS": "ALLOW",
        "ALLOW": "ALLOW",

        "DENY": "DENY",
        "DROP": "DENY",
        "BLOCK": "DENY",
    }

    return mapping.get(text, pd.NA)


def normalize_boolean(value):
    """Standardize Boolean representations."""

    if pd.isna(value):
        return pd.NA

    text = str(value).strip().lower()

    true_values = {
        "true",
        "y",
        "yes",
        "1"
    }

    false_values = {
        "false",
        "n",
        "no",
        "0"
    }

    if text in true_values:
        return True

    if text in false_values:
        return False

    return pd.NA


def parse_timestamp(value):
    """Parse mixed timestamp formats safely."""

    if pd.isna(value):
        return pd.NaT

    text = str(value).strip()

    if not text:
        return pd.NaT

    return pd.to_datetime(
        text,
        errors="coerce",
        format="mixed",
        utc=True
    )


# ============================================================
# MAIN CLEANING FUNCTION
# ============================================================

def clean_firewall():

    print("\n" + "=" * 70)
    print("FIREWALL CLEANING")
    print("=" * 70)

    # --------------------------------------------------------
    # LOAD RAW DATA
    # --------------------------------------------------------

    df = pd.read_csv(RAW_FILE)

    original_rows = len(df)

    print(
        f"Raw rows loaded: {original_rows:,}"
    )

    # --------------------------------------------------------
    # PRESERVE RAW VALUES
    # --------------------------------------------------------

    df["timestamp_raw"] = df["timestamp"]
    df["src_ip_raw"] = df["src_ip"]
    df["dst_ip_raw"] = df["dst_ip"]
    df["src_port_raw"] = df["src_port"]
    df["dst_port_raw"] = df["dst_port"]
    df["bytes_sent_raw"] = df["bytes_sent"]
    df["bytes_received_raw"] = df["bytes_received"]
    df["protocol_raw"] = df["protocol"]
    df["action_raw"] = df["action"]
    df["threat_flag_raw"] = df["threat_flag"]

    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    df["timestamp_clean"] = df["timestamp"].apply(
        parse_timestamp
    )

    # IMPORTANT:
    # Use nullable Boolean dtype from the beginning.
    timestamp_valid = pd.Series(
        pd.array(
            df["timestamp_clean"].notna(),
            dtype="boolean"
        ),
        index=df.index
    )

    timestamp_valid.loc[
        df["timestamp"].isna()
    ] = pd.NA

    df["timestamp_valid"] = timestamp_valid

    # --------------------------------------------------------
    # SOURCE IP
    # --------------------------------------------------------

    df["src_ip_clean"] = df["src_ip"].apply(
        normalize_ip
    )

    df["src_ip_valid"] = df["src_ip"].apply(
        validate_ip
    )

    # --------------------------------------------------------
    # DESTINATION IP
    # --------------------------------------------------------

    df["dst_ip_clean"] = df["dst_ip"].apply(
        normalize_ip
    )

    df["dst_ip_valid"] = df["dst_ip"].apply(
        validate_ip
    )

    # --------------------------------------------------------
    # SOURCE PORT
    # --------------------------------------------------------

    df["src_port_clean"] = df["src_port"].apply(
        normalize_port
    )

    df["src_port_valid"] = df["src_port"].apply(
        validate_port
    )

    # --------------------------------------------------------
    # DESTINATION PORT
    # --------------------------------------------------------

    df["dst_port_clean"] = df["dst_port"].apply(
        normalize_port
    )

    df["dst_port_valid"] = df["dst_port"].apply(
        validate_port
    )

    # --------------------------------------------------------
    # BYTES
    # --------------------------------------------------------

    df["bytes_sent_clean"] = df["bytes_sent"].apply(
        parse_bytes
    )

    df["bytes_received_clean"] = df["bytes_received"].apply(
        parse_bytes
    )

    # --------------------------------------------------------
    # PROTOCOL
    # --------------------------------------------------------

    df["protocol_clean"] = df["protocol"].apply(
        normalize_protocol
    )

    # --------------------------------------------------------
    # ACTION
    # --------------------------------------------------------

    df["action_clean"] = df["action"].apply(
        normalize_action
    )

    # --------------------------------------------------------
    # THREAT FLAG
    # --------------------------------------------------------

    df["threat_flag_clean"] = (
        df["threat_flag"]
        .apply(normalize_boolean)
        .astype("boolean")
    )

    # --------------------------------------------------------
    # EXACT DUPLICATE REMOVAL
    # --------------------------------------------------------
    #
    # Raw data remains untouched.
    #
    # Only exact duplicate rows are removed.
    #
    # --------------------------------------------------------

    duplicate_mask = df.duplicated(
        keep="first"
    )

    exact_duplicates_removed = int(
        duplicate_mask.sum()
    )

    df = df.loc[
        ~duplicate_mask
    ].copy()

    # --------------------------------------------------------
    # CLEANING SUMMARY
    # --------------------------------------------------------

    summary = {
        "dataset": "FIREWALL",

        "raw_rows": original_rows,

        "cleaned_rows": len(df),

        "exact_duplicate_rows_removed":
            exact_duplicates_removed,

        "timestamp_missing":
            int(df["timestamp_raw"].isna().sum()),

        "timestamp_invalid_after_cleaning":
            int(
                (
                    df["timestamp_raw"].notna()
                    & df["timestamp_clean"].isna()
                ).sum()
            ),

        "src_ip_missing":
            int(df["src_ip_raw"].isna().sum()),

        "src_ip_invalid":
            int(
                (
                    df["src_ip_raw"].notna()
                    & df["src_ip_clean"].isna()
                ).sum()
            ),

        "dst_ip_missing":
            int(df["dst_ip_raw"].isna().sum()),

        "dst_ip_invalid":
            int(
                (
                    df["dst_ip_raw"].notna()
                    & df["dst_ip_clean"].isna()
                ).sum()
            ),

        "src_port_missing":
            int(df["src_port_raw"].isna().sum()),

        "src_port_invalid":
            int(
                (
                    df["src_port_raw"].notna()
                    & df["src_port_clean"].isna()
                ).sum()
            ),

        "dst_port_missing":
            int(df["dst_port_raw"].isna().sum()),

        "dst_port_invalid":
            int(
                (
                    df["dst_port_raw"].notna()
                    & df["dst_port_clean"].isna()
                ).sum()
            ),

        "bytes_sent_missing":
            int(df["bytes_sent_raw"].isna().sum()),

        "bytes_sent_invalid":
            int(
                (
                    df["bytes_sent_raw"].notna()
                    & df["bytes_sent_clean"].isna()
                ).sum()
            ),

        "bytes_received_missing":
            int(df["bytes_received_raw"].isna().sum()),

        "bytes_received_invalid":
            int(
                (
                    df["bytes_received_raw"].notna()
                    & df["bytes_received_clean"].isna()
                ).sum()
            ),
    }

    summary_df = pd.DataFrame([summary])

    # --------------------------------------------------------
    # SAVE CLEANED DATA
    # --------------------------------------------------------

    output_file = (
        CLEANED_DIR / "firewall_cleaned.csv"
    )

    df.to_csv(
        output_file,
        index=False
    )

    # --------------------------------------------------------
    # SAVE CLEANING SUMMARY
    # --------------------------------------------------------

    summary_file = (
        REPORT_DIR /
        "firewall_cleaning_summary.csv"
    )

    summary_df.to_csv(
        summary_file,
        index=False
    )

    # --------------------------------------------------------
    # PRINT RESULTS
    # --------------------------------------------------------

    print("\nCleaning results:")

    print(
        f"Raw rows                 : "
        f"{original_rows:,}"
    )

    print(
        f"Exact duplicates removed : "
        f"{exact_duplicates_removed:,}"
    )

    print(
        f"Cleaned rows             : "
        f"{len(df):,}"
    )

    print(
        f"Timestamp invalid        : "
        f"{summary['timestamp_invalid_after_cleaning']:,}"
    )

    print(
        f"Source IP invalid        : "
        f"{summary['src_ip_invalid']:,}"
    )

    print(
        f"Destination IP invalid   : "
        f"{summary['dst_ip_invalid']:,}"
    )

    print(
        f"Source port invalid      : "
        f"{summary['src_port_invalid']:,}"
    )

    print(
        f"Destination port invalid : "
        f"{summary['dst_port_invalid']:,}"
    )

    print(
        f"Bytes sent invalid       : "
        f"{summary['bytes_sent_invalid']:,}"
    )

    print(
        f"Bytes received invalid   : "
        f"{summary['bytes_received_invalid']:,}"
    )

    print("\nGenerated:")
    print(f"  {output_file}")
    print(f"  {summary_file}")

    print("\n" + "=" * 70)
    print("FIREWALL CLEANING COMPLETE")
    print("=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    clean_firewall()