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
# LOAD DATASETS
# ============================================================

def load_datasets():

    return {
        "firewall": pd.read_csv(
            RAW_DIR / "track2_firewall_logs.csv"
        ),

        "iam": pd.read_json(
            RAW_DIR / "track2_iam_audit_trail.json"
        ),

        "endpoint": pd.read_excel(
            RAW_DIR / "track2_endpoint_alerts.xlsx"
        ),

        "identity": pd.read_csv(
            RAW_DIR / "track2_identity_asset_master.csv"
        ),
    }


# ============================================================
# MISSING VALUE ANALYSIS
# ============================================================

def analyze_missing(name, df):

    records = []

    for column in df.columns:

        missing_count = int(df[column].isna().sum())
        total_count = len(df)

        records.append({
            "dataset": name,
            "column": column,
            "total_rows": total_count,
            "missing_count": missing_count,
            "missing_percentage": round(
                (missing_count / total_count) * 100,
                2
            ),
            "non_missing_count": total_count - missing_count,
        })

    return pd.DataFrame(records)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("MISSING VALUE ANALYSIS")
    print("=" * 70)

    datasets = load_datasets()

    all_results = []

    for name, df in datasets.items():

        result = analyze_missing(name, df)

        all_results.append(result)

        print(f"\n{name.upper()}")
        print("-" * 70)

        print(
            result[
                result["missing_count"] > 0
            ].sort_values(
                "missing_percentage",
                ascending=False
            ).to_string(index=False)
        )

    final_report = pd.concat(
        all_results,
        ignore_index=True
    )

    final_report = final_report.sort_values(
        ["dataset", "missing_percentage"],
        ascending=[True, False]
    )

    output_file = REPORT_DIR / "missing_values.csv"

    final_report.to_csv(
        output_file,
        index=False
    )

    print("\n" + "=" * 70)
    print("MISSING VALUE ANALYSIS COMPLETE")
    print("=" * 70)

    print(f"\nReport saved to:")
    print(output_file)


if __name__ == "__main__":
    main()