from pathlib import Path
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]
RAW_DIR = BASE_DIR / "data" / "raw"
REPORT_DIR = BASE_DIR / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# DATASET LOADERS
# ============================================================

def load_datasets():
    datasets = {}

    datasets["firewall"] = pd.read_csv(
        RAW_DIR / "track2_firewall_logs.csv"
    )

    datasets["iam"] = pd.read_json(
        RAW_DIR / "track2_iam_audit_trail.json"
    )

    datasets["endpoint"] = pd.read_excel(
        RAW_DIR / "track2_endpoint_alerts.xlsx"
    )

    datasets["identity"] = pd.read_csv(
        RAW_DIR / "track2_identity_asset_master.csv"
    )

    return datasets


# ============================================================
# BASIC PROFILE
# ============================================================

def profile_dataset(name, df):
    profile = []

    for column in df.columns:
        profile.append({
            "dataset": name,
            "column": column,
            "rows": len(df),
            "dtype": str(df[column].dtype),
            "missing_count": int(df[column].isna().sum()),
            "missing_percentage": round(
                df[column].isna().mean() * 100, 2
            ),
            "unique_count": int(df[column].nunique(dropna=True)),
        })

    return pd.DataFrame(profile)


# ============================================================
# DUPLICATE PROFILE
# ============================================================

def duplicate_profile(name, df):
    return pd.DataFrame([{
        "dataset": name,
        "total_rows": len(df),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_percentage": round(
            df.duplicated().mean() * 100, 2
        ),
    }])


# ============================================================
# VALUE VARIATIONS
# ============================================================

def value_profile(name, df):
    records = []

    for column in df.columns:

        # Only profile relatively small categorical columns.
        if df[column].dtype == "object":
            value_counts = (
                df[column]
                .value_counts(dropna=False)
                .head(50)
            )

            for value, count in value_counts.items():
                records.append({
                    "dataset": name,
                    "column": column,
                    "value": str(value),
                    "count": int(count),
                })

    return pd.DataFrame(records)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("RAW DATA BASELINE PROFILING")
    print("=" * 70)

    datasets = load_datasets()

    all_profiles = []
    all_duplicates = []
    all_values = []

    for name, df in datasets.items():

        print(f"\n{name.upper()}")
        print("-" * 70)

        print(f"Rows    : {len(df):,}")
        print(f"Columns : {len(df.columns)}")
        print(
            f"Missing : {df.isna().sum().sum():,}"
        )
        print(
            f"Duplicate rows : {df.duplicated().sum():,}"
        )

        all_profiles.append(
            profile_dataset(name, df)
        )

        all_duplicates.append(
            duplicate_profile(name, df)
        )

        all_values.append(
            value_profile(name, df)
        )

    # Combine results
    profile_df = pd.concat(
        all_profiles,
        ignore_index=True
    )

    duplicate_df = pd.concat(
        all_duplicates,
        ignore_index=True
    )

    values_df = pd.concat(
        all_values,
        ignore_index=True
    )

    # Save reports
    profile_df.to_csv(
        REPORT_DIR / "raw_data_profile.csv",
        index=False
    )

    duplicate_df.to_csv(
        REPORT_DIR / "duplicate_summary.csv",
        index=False
    )

    values_df.to_csv(
        REPORT_DIR / "value_variations.csv",
        index=False
    )

    print("\n" + "=" * 70)
    print("PROFILING COMPLETE")
    print("=" * 70)

    print("\nReports generated:")

    print("1. reports/raw_data_profile.csv")
    print("2. reports/duplicate_summary.csv")
    print("3. reports/value_variations.csv")


if __name__ == "__main__":
    main()