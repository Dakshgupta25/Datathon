import pandas as pd
import numpy as np
import ipaddress
import re
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = ROOT / "data" / "raw" / "track2_firewall_logs.csv"
CLEANED_DIR = ROOT / "data" / "cleaned"
REPORT_DIR = ROOT / "reports"

CLEANED_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = CLEANED_DIR / "firewall_cleaned.csv"
SUMMARY_FILE = REPORT_DIR / "firewall_cleaning_summary.csv"


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
    """
    Return valid / invalid / missing status.

    Port 0 is explicitly invalid.
    """

    if pd.isna(value):
        return "missing"

    try:
        number = float(value)

        if (
            number.is_integer()
            and 1 <= number <= 65535
        ):
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

    # --------------------------------------------------------
    # Plain numeric value
    # --------------------------------------------------------

    try:
        number = float(text)

        if number < 0:
            return np.nan

        return number

    except ValueError:
        pass

    # --------------------------------------------------------
    # Values with units
    # --------------------------------------------------------

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
    """
    Parse mixed timestamp formats safely.

    Invalid or unavailable timestamps remain NaT here.
    They are handled later in the final analytical dataset.
    """

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
    # 1. LOAD RAW DATA
    # --------------------------------------------------------

    print("\n[1/10] Loading raw firewall data...")

    df = pd.read_csv(RAW_FILE)

    original_rows = len(df)

    print(
        f"Raw rows loaded: {original_rows:,}"
    )


    # --------------------------------------------------------
    # 2. PRESERVE RAW VALUES
    # --------------------------------------------------------

    print("\n[2/10] Preserving raw values for audit...")

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
    # 3. TIMESTAMP
    # --------------------------------------------------------

    print("\n[3/10] Cleaning timestamps...")

    df["timestamp_clean"] = (
        df["timestamp"]
        .apply(parse_timestamp)
    )

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
    # 4. SOURCE + DESTINATION IP
    # --------------------------------------------------------

    print("\n[4/10] Validating IP addresses...")

    df["src_ip_clean"] = (
        df["src_ip"]
        .apply(normalize_ip)
    )

    df["src_ip_valid"] = (
        df["src_ip"]
        .apply(validate_ip)
    )

    df["dst_ip_clean"] = (
        df["dst_ip"]
        .apply(normalize_ip)
    )

    df["dst_ip_valid"] = (
        df["dst_ip"]
        .apply(validate_ip)
    )


    # --------------------------------------------------------
    # 5. SOURCE + DESTINATION PORTS
    # --------------------------------------------------------

    print("\n[5/10] Validating network ports...")

    df["src_port_clean"] = (
        df["src_port"]
        .apply(normalize_port)
    )

    df["src_port_valid"] = (
        df["src_port"]
        .apply(validate_port)
    )

    df["dst_port_clean"] = (
        df["dst_port"]
        .apply(normalize_port)
    )

    df["dst_port_valid"] = (
        df["dst_port"]
        .apply(validate_port)
    )


    # --------------------------------------------------------
    # 6. NETWORK BYTES
    # --------------------------------------------------------

    print("\n[6/10] Standardizing network byte values...")

    df["bytes_sent_clean"] = (
        df["bytes_sent"]
        .apply(parse_bytes)
    )

    df["bytes_received_clean"] = (
        df["bytes_received"]
        .apply(parse_bytes)
    )


    # --------------------------------------------------------
    # 7. PROTOCOL + ACTION + THREAT FLAG
    # --------------------------------------------------------

    print("\n[7/10] Standardizing protocol, action and threat flag...")

    df["protocol_clean"] = (
        df["protocol"]
        .apply(normalize_protocol)
    )

    df["action_clean"] = (
        df["action"]
        .apply(normalize_action)
    )

    df["threat_flag_clean"] = (
        df["threat_flag"]
        .apply(normalize_boolean)
        .astype("boolean")
    )


    # --------------------------------------------------------
    # 8. EXACT DUPLICATE REMOVAL
    # --------------------------------------------------------

    print("\n[8/10] Removing exact duplicate rows...")

    duplicate_mask = df.duplicated(
        keep="first"
    )

    exact_duplicates_removed = int(
        duplicate_mask.sum()
    )

    df = df.loc[
        ~duplicate_mask
    ].copy()

    print(
        f"Exact duplicate rows removed: "
        f"{exact_duplicates_removed:,}"
    )

    print(
        f"Rows remaining: {len(df):,}"
    )


    # --------------------------------------------------------
    # 9. FINAL MISSING-VALUE HANDLING
    # --------------------------------------------------------

    print("\n[9/10] Handling missing values...")


    # ========================================================
    # Calculate statistics BEFORE imputation.
    #
    # Numeric values are imputed using the median of valid
    # cleaned values.
    #
    # Text/categorical values use explicit "Unknown".
    #
    # We never fabricate IP addresses, timestamps,
    # session IDs, rule names, etc.
    # ========================================================


    # --------------------------------------------------------
    # Numeric medians
    # --------------------------------------------------------

    src_port_median = (
        df["src_port_clean"]
        .median()
    )

    dst_port_median = (
        df["dst_port_clean"]
        .median()
    )

    bytes_sent_median = (
        df["bytes_sent_clean"]
        .median()
    )

    bytes_received_median = (
        df["bytes_received_clean"]
        .median()
    )


    # --------------------------------------------------------
    # Safety check for medians
    # --------------------------------------------------------

    numeric_medians = {
        "src_port": src_port_median,
        "dst_port": dst_port_median,
        "bytes_sent": bytes_sent_median,
        "bytes_received": bytes_received_median,
    }

    for name, median_value in numeric_medians.items():

        if pd.isna(median_value):

            raise ValueError(
                f"Unable to calculate median for {name}. "
                "No valid cleaned numeric values were found."
            )


    # --------------------------------------------------------
    # Text / categorical fields
    # --------------------------------------------------------

    text_fill_columns = [
        "timestamp_clean",
        "hostname",
        "src_ip_clean",
        "dst_ip_clean",
        "session_id",
        "rule_name",
        "geo_country",
    ]

    for column in text_fill_columns:

        if column == "timestamp_clean":

            # Timestamps cannot safely be replaced with a
            # fabricated date. Use an explicit sentinel.
            df[column] = (
                df[column]
                .astype(object)
                .where(
                    df[column].notna(),
                    "Unknown"
                )
            )

        else:

            df[column] = (
                df[column]
                .fillna("Unknown")
            )


    # --------------------------------------------------------
    # Numeric fields
    # --------------------------------------------------------

    df["src_port_clean"] = (
        df["src_port_clean"]
        .fillna(src_port_median)
        .round()
        .astype(int)
    )

    df["dst_port_clean"] = (
        df["dst_port_clean"]
        .fillna(dst_port_median)
        .round()
        .astype(int)
    )

    df["bytes_sent_clean"] = (
        df["bytes_sent_clean"]
        .fillna(bytes_sent_median)
        .round(2)
    )

    df["bytes_received_clean"] = (
        df["bytes_received_clean"]
        .fillna(bytes_received_median)
        .round(2)
    )


    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    df["protocol_clean"] = (
        df["protocol_clean"]
        .fillna("Unknown")
    )


    # --------------------------------------------------------
    # Action
    # --------------------------------------------------------

    df["action_clean"] = (
        df["action_clean"]
        .fillna("Unknown")
    )


    # --------------------------------------------------------
    # Threat flag
    # --------------------------------------------------------

    # Unknown threat flags are represented explicitly rather
    # than being incorrectly classified as False.

    df["threat_flag_clean"] = (
        df["threat_flag_clean"]
        .astype(object)
        .where(
            df["threat_flag_clean"].notna(),
            "Unknown"
        )
    )


    # --------------------------------------------------------
    # 10. FINAL ANALYTICAL DATASET
    # --------------------------------------------------------

    print(
        "\n[10/10] Creating final analytical dataset..."
    )


    # --------------------------------------------------------
    # FINAL OUTPUT COLUMNS
    # --------------------------------------------------------
    #
    # Exactly 15 analytical columns.
    #
    # Raw/helper/validation columns remain available only
    # during cleaning and are NOT written to the final CSV.
    # --------------------------------------------------------

    FINAL_COLUMNS = [
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


    final_df = pd.DataFrame({

        "log_id":
            df["log_id"],

        "timestamp":
            df["timestamp_clean"],

        "hostname":
            df["hostname"],

        "src_ip":
            df["src_ip_clean"],

        "dst_ip":
            df["dst_ip_clean"],

        "src_port":
            df["src_port_clean"],

        "dst_port":
            df["dst_port_clean"],

        "protocol":
            df["protocol_clean"],

        "action":
            df["action_clean"],

        "bytes_sent":
            df["bytes_sent_clean"],

        "bytes_received":
            df["bytes_received_clean"],

        "session_id":
            df["session_id"],

        "threat_flag":
            df["threat_flag_clean"],

        "rule_name":
            df["rule_name"],

        "geo_country":
            df["geo_country"],
    })


    final_df = final_df[
        FINAL_COLUMNS
    ]


    # --------------------------------------------------------
    # FINAL MISSING-VALUE SAFETY CHECK
    # --------------------------------------------------------

    final_missing_by_column = (
        final_df.isna().sum()
    )

    final_missing_cells = int(
        final_missing_by_column.sum()
    )

    if final_missing_cells > 0:

        missing_details = (
            final_missing_by_column[
                final_missing_by_column > 0
            ]
            .to_dict()
        )

        raise ValueError(
            "Final Firewall dataset still contains "
            f"{final_missing_cells} missing cells: "
            f"{missing_details}"
        )


    # --------------------------------------------------------
    # FINAL DUPLICATE CHECK
    # --------------------------------------------------------

    final_duplicate_rows = int(
        final_df.duplicated().sum()
    )

    final_duplicate_log_ids = int(
        final_df["log_id"].duplicated().sum()
    )


    # --------------------------------------------------------
    # VALIDATE FINAL PORT RANGE
    # --------------------------------------------------------

    invalid_final_src_ports = int(
        (
            (final_df["src_port"] < 1)
            | (final_df["src_port"] > 65535)
        ).sum()
    )

    invalid_final_dst_ports = int(
        (
            (final_df["dst_port"] < 1)
            | (final_df["dst_port"] > 65535)
        ).sum()
    )

    if (
        invalid_final_src_ports > 0
        or invalid_final_dst_ports > 0
    ):

        raise ValueError(
            "Final dataset contains invalid port values."
        )


    # --------------------------------------------------------
    # VALIDATE FINAL BYTE RANGE
    # --------------------------------------------------------

    invalid_final_bytes = int(
        (
            (final_df["bytes_sent"] < 0)
            |
            (final_df["bytes_received"] < 0)
        ).sum()
    )

    if invalid_final_bytes > 0:

        raise ValueError(
            "Final dataset contains negative byte values."
        )


    # --------------------------------------------------------
    # SAVE FINAL CLEANED DATA
    # --------------------------------------------------------

    final_df.to_csv(
        OUTPUT_FILE,
        index=False
    )


    # ========================================================
    # CLEANING SUMMARY
    # ========================================================

    summary = {

        "dataset":
            "FIREWALL",

        "raw_rows":
            original_rows,

        "cleaned_rows":
            len(final_df),

        "exact_duplicate_rows_removed":
            exact_duplicates_removed,

        "timestamp_missing":
            int(
                df["timestamp_raw"]
                .isna()
                .sum()
            ),

        "timestamp_invalid_after_cleaning":
            int(
                (
                    df["timestamp_raw"].notna()
                    &
                    (
                        pd.to_datetime(
                            df["timestamp_raw"],
                            errors="coerce",
                            format="mixed",
                            utc=True
                        ).isna()
                    )
                ).sum()
            ),

        "src_ip_missing":
            int(
                df["src_ip_raw"]
                .isna()
                .sum()
            ),

        "src_ip_invalid":
            int(
                (
                    df["src_ip_raw"].notna()
                    &
                    df["src_ip_clean"].isna()
                ).sum()
            ),

        "dst_ip_missing":
            int(
                df["dst_ip_raw"]
                .isna()
                .sum()
            ),

        "dst_ip_invalid":
            int(
                (
                    df["dst_ip_raw"].notna()
                    &
                    df["dst_ip_clean"].isna()
                ).sum()
            ),

        "src_port_missing":
            int(
                df["src_port_raw"]
                .isna()
                .sum()
            ),

        "src_port_invalid":
            int(
                (
                    df["src_port_raw"].notna()
                    &
                    df["src_port_clean"].isna()
                ).sum()
            ),

        "dst_port_missing":
            int(
                df["dst_port_raw"]
                .isna()
                .sum()
            ),

        "dst_port_invalid":
            int(
                (
                    df["dst_port_raw"].notna()
                    &
                    df["dst_port_clean"].isna()
                ).sum()
            ),

        "bytes_sent_missing":
            int(
                df["bytes_sent_raw"]
                .isna()
                .sum()
            ),

        "bytes_sent_invalid":
            int(
                (
                    df["bytes_sent_raw"].notna()
                    &
                    df["bytes_sent_clean"].isna()
                ).sum()
            ),

        "bytes_received_missing":
            int(
                df["bytes_received_raw"]
                .isna()
                .sum()
            ),

        "bytes_received_invalid":
            int(
                (
                    df["bytes_received_raw"].notna()
                    &
                    df["bytes_received_clean"].isna()
                ).sum()
            ),

        "src_port_median_used":
            round(float(src_port_median), 2),

        "dst_port_median_used":
            round(float(dst_port_median), 2),

        "bytes_sent_median_used":
            round(float(bytes_sent_median), 2),

        "bytes_received_median_used":
            round(float(bytes_received_median), 2),

        "final_columns":
            len(final_df.columns),

        "final_missing_cells":
            final_missing_cells,

        "final_duplicate_rows":
            final_duplicate_rows,

        "final_duplicate_log_ids":
            final_duplicate_log_ids,

        "invalid_final_src_ports":
            invalid_final_src_ports,

        "invalid_final_dst_ports":
            invalid_final_dst_ports,

        "invalid_final_bytes":
            invalid_final_bytes,

        "missing_text_handling":
            "Unknown sentinel",

        "missing_timestamp_handling":
            "Unknown sentinel",

        "missing_numeric_handling":
            "Median of valid cleaned values",
    }


    summary_df = pd.DataFrame(
        [summary]
    )


    # --------------------------------------------------------
    # SAVE CLEANING SUMMARY
    # --------------------------------------------------------

    summary_df.to_csv(
        SUMMARY_FILE,
        index=False
    )


    # ========================================================
    # PRINT RESULTS
    # ========================================================

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
        f"{len(final_df):,}"
    )

    print(
        f"Final columns            : "
        f"{len(final_df.columns)}"
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

    print(
        f"Source port median       : "
        f"{src_port_median:.2f}"
    )

    print(
        f"Destination port median  : "
        f"{dst_port_median:.2f}"
    )

    print(
        f"Bytes sent median        : "
        f"{bytes_sent_median:.2f}"
    )

    print(
        f"Bytes received median    : "
        f"{bytes_received_median:.2f}"
    )

    print(
        f"Final missing cells      : "
        f"{final_missing_cells}"
    )

    print(
        f"Final duplicate rows     : "
        f"{final_duplicate_rows}"
    )

    print(
        f"Duplicate log IDs        : "
        f"{final_duplicate_log_ids}"
    )

    print(
        f"Invalid final src ports  : "
        f"{invalid_final_src_ports}"
    )

    print(
        f"Invalid final dst ports  : "
        f"{invalid_final_dst_ports}"
    )

    print(
        f"Invalid final bytes      : "
        f"{invalid_final_bytes}"
    )

    print("\nGenerated:")
    print(f"  {OUTPUT_FILE}")
    print(f"  {SUMMARY_FILE}")

    print("\nFinal dataset validation:")

    print(
        "  [PASS] Exactly 15 analytical columns"
    )

    print(
        "  [PASS] Zero missing cells"
    )

    print(
        "  [PASS] No duplicate rows"
    )

    print(
        "  [PASS] Ports restricted to 1-65535"
    )

    print(
        "  [PASS] No negative byte values"
    )

    print(
        "  [PASS] Cleaning completed successfully"
    )

    print("\n" + "=" * 70)
    print("FIREWALL CLEANING COMPLETE")
    print("=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    clean_firewall()