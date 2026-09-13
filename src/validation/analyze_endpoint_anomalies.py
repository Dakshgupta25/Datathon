from pathlib import Path
import pandas as pd
import re

ROOT = Path(__file__).resolve().parents[2]

RAW_FILE = ROOT / "data" / "raw" / "track2_endpoint_alerts.xlsx"
REPORT_DIR = ROOT / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def parse_timestamp(value):
    """
    Try common timestamp representations without silently changing
    ambiguous values.
    """
    if pd.isna(value):
        return pd.NaT

    value = str(value).strip()

    if not value:
        return pd.NaT

    # Try pandas mixed-format parsing.
    try:
        parsed = pd.to_datetime(value, format="mixed", errors="coerce")
        if pd.notna(parsed):
            return parsed
    except Exception:
        pass

    # Explicit common formats.
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ]

    for fmt in formats:
        try:
            parsed = pd.to_datetime(value, format=fmt, errors="coerce")
            if pd.notna(parsed):
                return parsed
        except Exception:
            pass

    return pd.NaT


def sha256_status(value):
    """
    Classify SHA-256 values without modifying them.
    """
    if pd.isna(value):
        return "missing"

    value = str(value).strip()

    if not value:
        return "missing"

    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return "valid_sha256"

    lowered = value.lower()

    placeholders = {
        "na",
        "n/a",
        "none",
        "null",
        "unknown",
        "not available",
        "not_available",
        "-",
        "nan",
    }

    if lowered in placeholders:
        return "placeholder"

    if len(value) != 64:
        return "invalid_length"

    return "invalid_characters"


print("=" * 60)
print("ENDPOINT ANOMALY ANALYSIS")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load raw data
# ------------------------------------------------------------

print("\n[1/4] Loading raw endpoint data...")

df = pd.read_excel(RAW_FILE)

print(f"Raw rows: {len(df):,}")

# ------------------------------------------------------------
# 2. Timestamp anomalies
# ------------------------------------------------------------

print("\n[2/4] Analysing timestamps...")

for column in ["detected_timestamp", "resolved_timestamp"]:

    parsed = df[column].apply(parse_timestamp)

    invalid_mask = df[column].notna() & parsed.isna()

    invalid_values = (
        df.loc[invalid_mask, column]
        .astype(str)
        .value_counts()
        .reset_index()
    )

    invalid_values.columns = ["raw_value", "count"]

    output_file = (
        REPORT_DIR /
        f"endpoint_{column}_invalid_values.csv"
    )

    invalid_values.to_csv(output_file, index=False)

    print(f"\n{column}")
    print(f"  Missing       : {df[column].isna().sum():,}")
    print(f"  Parseable     : {parsed.notna().sum():,}")
    print(f"  Invalid       : {invalid_mask.sum():,}")

    print("\n  Top invalid values:")
    print(invalid_values.head(20).to_string(index=False))

# ------------------------------------------------------------
# 3. Chronology anomalies
# ------------------------------------------------------------

print("\n[3/4] Analysing chronology...")

detected = df["detected_timestamp"].apply(parse_timestamp)
resolved = df["resolved_timestamp"].apply(parse_timestamp)

chronology_mask = (
    detected.notna()
    & resolved.notna()
    & (resolved < detected)
)

chronology = df.loc[
    chronology_mask,
    [
        "alert_id",
        "detected_timestamp",
        "resolved_timestamp",
        "user_id",
        "hostname",
        "severity",
        "status",
    ]
].copy()

chronology["detected_parsed"] = detected[chronology_mask]
chronology["resolved_parsed"] = resolved[chronology_mask]

chronology["duration_hours"] = (
    chronology["resolved_parsed"]
    - chronology["detected_parsed"]
).dt.total_seconds() / 3600

chronology.to_csv(
    REPORT_DIR / "endpoint_chronology_anomalies.csv",
    index=False
)

print(f"Chronology anomalies: {len(chronology):,}")

print("\nTop chronology examples:")
if len(chronology) > 0:
    print(
        chronology[
            [
                "alert_id",
                "detected_timestamp",
                "resolved_timestamp",
                "duration_hours",
            ]
        ]
        .head(20)
        .to_string(index=False)
    )
else:
    print("None found.")

# ------------------------------------------------------------
# 4. SHA-256 anomalies
# ------------------------------------------------------------

print("\n[4/4] Analysing SHA-256 values...")

sha_status = df["sha256"].apply(sha256_status)

sha_summary = (
    sha_status
    .value_counts()
    .rename_axis("sha256_status")
    .reset_index(name="count")
)

sha_summary.to_csv(
    REPORT_DIR / "endpoint_sha256_validation.csv",
    index=False
)

print("\nSHA-256 status:")
print(sha_summary.to_string(index=False))

invalid_sha_mask = ~sha_status.isin(
    ["valid_sha256", "missing"]
)

invalid_sha = (
    df.loc[invalid_sha_mask, "sha256"]
    .astype(str)
    .value_counts()
    .reset_index()
)

invalid_sha.columns = ["raw_value", "count"]

invalid_sha.to_csv(
    REPORT_DIR / "endpoint_sha256_invalid_values.csv",
    index=False
)

print("\nTop invalid SHA-256 values:")
print(invalid_sha.head(20).to_string(index=False))

print("\n" + "=" * 60)
print("ENDPOINT ANOMALY ANALYSIS COMPLETE")
print("=" * 60)

print("\nGenerated reports:")
print("  reports/endpoint_detected_timestamp_invalid_values.csv")
print("  reports/endpoint_resolved_timestamp_invalid_values.csv")
print("  reports/endpoint_chronology_anomalies.csv")
print("  reports/endpoint_sha256_validation.csv")
print("  reports/endpoint_sha256_invalid_values.csv")