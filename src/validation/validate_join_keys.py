import pandas as pd
import re
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

RAW_DIR = Path("data/raw")
REPORT_DIR = Path("reports")

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# USER ID NORMALIZATION
# ============================================================

def normalize_user_id(value):
    """
    Normalize known employee ID formatting variants.

    Examples:
        EMP12345
        emp12345
        EMP-12345
        EMP 12345
        12345

    Canonical result:
        EMP12345

    Invalid/unrecognized values return <NA>.
    """

    if pd.isna(value):
        return pd.NA

    text = str(value).strip().upper()

    if not text:
        return pd.NA

    # Remove known separators
    text = re.sub(r"[\s\-_]", "", text)

    # EMP-prefixed ID
    if text.startswith("EMP"):

        digits = text[3:]

        if digits.isdigit():
            return f"EMP{digits}"

        return pd.NA

    # Numeric-only employee ID
    if text.isdigit():
        return f"EMP{text}"

    # Unknown format
    return pd.NA


# ============================================================
# DATASET ANALYSIS
# ============================================================

def analyze_dataset(df, dataset_name, column):
    """
    Create a validation dataframe containing:
        - original user_id
        - normalized user_id
        - normalization status
    """

    raw = df[column]

    clean = raw.apply(normalize_user_id)

    result = pd.DataFrame({
        "raw_user_id": raw,
        "user_id_clean": clean
    })

    # Use string dtype so status values remain consistent
    result["normalization_status"] = "normalized"

    # Missing raw IDs
    result.loc[
        raw.isna(),
        "normalization_status"
    ] = "missing"

    # Non-null but unrecognized IDs
    result.loc[
        raw.notna() & clean.isna(),
        "normalization_status"
    ] = "invalid"

    return result


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # LOAD RAW DATA
    # ========================================================

    print("\nLoading datasets...")

    iam = pd.read_json(
        RAW_DIR / "track2_iam_audit_trail.json"
    )

    endpoint = pd.read_excel(
        RAW_DIR / "track2_endpoint_alerts.xlsx"
    )

    identity = pd.read_csv(
        RAW_DIR / "track2_identity_asset_master.csv"
    )

    print("Datasets loaded successfully.")

    # ========================================================
    # NORMALIZE USER IDs
    # ========================================================

    print("\nNormalizing user IDs...")

    iam_result = analyze_dataset(
        iam,
        "IAM",
        "user_id"
    )

    endpoint_result = analyze_dataset(
        endpoint,
        "ENDPOINT",
        "user_id"
    )

    identity_result = analyze_dataset(
        identity,
        "IDENTITY",
        "user_id"
    )

    # ========================================================
    # IDENTITY MASTER CANONICAL KEYS
    # ========================================================

    identity_keys = set(
        identity_result["user_id_clean"]
        .dropna()
        .unique()
    )

    # ========================================================
    # IAM → IDENTITY MATCHING
    # ========================================================

    iam_result["identity_match"] = (
        iam_result["user_id_clean"]
        .isin(identity_keys)
        .astype("boolean")
    )

    # Missing/invalid user IDs are not matchable
    iam_result.loc[
        iam_result["user_id_clean"].isna(),
        "identity_match"
    ] = pd.NA

    # ========================================================
    # ENDPOINT → IDENTITY MATCHING
    # ========================================================

    endpoint_result["identity_match"] = (
        endpoint_result["user_id_clean"]
        .isin(identity_keys)
        .astype("boolean")
    )

    # Missing/invalid user IDs are not matchable
    endpoint_result.loc[
        endpoint_result["user_id_clean"].isna(),
        "identity_match"
    ] = pd.NA

    # ========================================================
    # SUMMARY
    # ========================================================

    print("\n" + "=" * 70)
    print("JOIN KEY VALIDATION")
    print("=" * 70)

    # --------------------------------------------------------
    # IAM
    # --------------------------------------------------------

    print("\nIAM")
    print("-" * 40)

    iam_total = len(iam_result)

    iam_normalized = (
        iam_result["user_id_clean"]
        .notna()
        .sum()
    )

    iam_missing_invalid = (
        iam_result["user_id_clean"]
        .isna()
        .sum()
    )

    iam_matched = (
        iam_result["identity_match"]
        .eq(True)
        .sum()
    )

    iam_unmatched = (
        iam_result["identity_match"]
        .eq(False)
        .sum()
    )

    print(
        f"Total rows             : {iam_total:,}"
    )

    print(
        f"Normalized user IDs    : {iam_normalized:,}"
    )

    print(
        f"Missing/invalid IDs    : {iam_missing_invalid:,}"
    )

    print(
        f"Matched Identity IDs   : {iam_matched:,}"
    )

    print(
        f"Unmatched Identity IDs : {iam_unmatched:,}"
    )

    # --------------------------------------------------------
    # ENDPOINT
    # --------------------------------------------------------

    print("\nENDPOINT")
    print("-" * 40)

    endpoint_total = len(endpoint_result)

    endpoint_normalized = (
        endpoint_result["user_id_clean"]
        .notna()
        .sum()
    )

    endpoint_missing_invalid = (
        endpoint_result["user_id_clean"]
        .isna()
        .sum()
    )

    endpoint_matched = (
        endpoint_result["identity_match"]
        .eq(True)
        .sum()
    )

    endpoint_unmatched = (
        endpoint_result["identity_match"]
        .eq(False)
        .sum()
    )

    print(
        f"Total rows             : {endpoint_total:,}"
    )

    print(
        f"Normalized user IDs    : {endpoint_normalized:,}"
    )

    print(
        f"Missing/invalid IDs    : {endpoint_missing_invalid:,}"
    )

    print(
        f"Matched Identity IDs   : {endpoint_matched:,}"
    )

    print(
        f"Unmatched Identity IDs : {endpoint_unmatched:,}"
    )

    # --------------------------------------------------------
    # IDENTITY
    # --------------------------------------------------------

    print("\nIDENTITY")
    print("-" * 40)

    identity_total = len(identity_result)

    identity_normalized = (
        identity_result["user_id_clean"]
        .notna()
        .sum()
    )

    identity_missing_invalid = (
        identity_result["user_id_clean"]
        .isna()
        .sum()
    )

    print(
        f"Total rows             : {identity_total:,}"
    )

    print(
        f"Normalized user IDs    : {identity_normalized:,}"
    )

    print(
        f"Missing/invalid IDs    : {identity_missing_invalid:,}"
    )

    # ========================================================
    # DUPLICATE CANONICAL IDs IN IDENTITY MASTER
    # ========================================================

    duplicate_identity_ids = (
        identity_result["user_id_clean"]
        .dropna()
        .value_counts()
    )

    duplicate_identity_ids = (
        duplicate_identity_ids[
            duplicate_identity_ids > 1
        ]
        .rename("row_count")
        .reset_index()
    )

    duplicate_identity_ids.columns = [
        "user_id_clean",
        "row_count"
    ]

    print(
        "\nIdentity duplicate canonical IDs:"
    )

    print(
        f"{len(duplicate_identity_ids):,}"
    )

    # ========================================================
    # NORMALIZATION STATUS SUMMARY
    # ========================================================

    print("\nNormalization status:")
    print(
        iam_result["normalization_status"]
        .value_counts()
        .to_string()
    )

    print("\nEndpoint normalization status:")
    print(
        endpoint_result["normalization_status"]
        .value_counts()
        .to_string()
    )

    print("\nIdentity normalization status:")
    print(
        identity_result["normalization_status"]
        .value_counts()
        .to_string()
    )

    # ========================================================
    # SAVE DETAILED REPORTS
    # ========================================================

    iam_result.to_csv(
        REPORT_DIR / "iam_join_key_validation.csv",
        index=False
    )

    endpoint_result.to_csv(
        REPORT_DIR / "endpoint_join_key_validation.csv",
        index=False
    )

    identity_result.to_csv(
        REPORT_DIR / "identity_join_key_validation.csv",
        index=False
    )

    duplicate_identity_ids.to_csv(
        REPORT_DIR / "identity_duplicate_canonical_ids.csv",
        index=False
    )

    # ========================================================
    # SAVE UNMATCHED IDs
    # ========================================================

    iam_unmatched = iam_result[
        iam_result["identity_match"] == False
    ].copy()

    endpoint_unmatched = endpoint_result[
        endpoint_result["identity_match"] == False
    ].copy()

    iam_unmatched.to_csv(
        REPORT_DIR / "iam_unmatched_identity_ids.csv",
        index=False
    )

    endpoint_unmatched.to_csv(
        REPORT_DIR / "endpoint_unmatched_identity_ids.csv",
        index=False
    )

    # ========================================================
    # FINAL MESSAGE
    # ========================================================

    print("\n" + "=" * 70)
    print("STEP 7 COMPLETE")
    print("=" * 70)

    print("\nGenerated reports:")

    print(
        "  reports/iam_join_key_validation.csv"
    )

    print(
        "  reports/endpoint_join_key_validation.csv"
    )

    print(
        "  reports/identity_join_key_validation.csv"
    )

    print(
        "  reports/identity_duplicate_canonical_ids.csv"
    )

    print(
        "  reports/iam_unmatched_identity_ids.csv"
    )

    print(
        "  reports/endpoint_unmatched_identity_ids.csv"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()