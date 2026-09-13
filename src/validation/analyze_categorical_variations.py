import pandas as pd
from pathlib import Path


RAW_DIR = Path("data/raw")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_file(filename):
    path = RAW_DIR / filename

    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)

    if path.suffix.lower() == ".json":
        return pd.read_json(path)

    if path.suffix.lower() in [".xlsx", ".xls"]:
        return pd.read_excel(path)

    raise ValueError(f"Unsupported file: {filename}")


# Fields where controlled standardization is expected
FIELDS = {
    "FIREWALL": {
        "file": "track2_firewall_logs.csv",
        "columns": [
            "protocol",
            "action",
            "threat_flag",
        ],
    },

    "IAM": {
        "file": "track2_iam_audit_trail.json",
        "columns": [
            "user_id",
            "department",
            "event_type",
            "mfa_passed",
        ],
    },

    "ENDPOINT": {
        "file": "track2_endpoint_alerts.xlsx",
        "columns": [
            "severity",
            "status",
            "device_criticality",
            "endpoint_product",
        ],
    },

    "IDENTITY": {
        "file": "track2_identity_asset_master.csv",
        "columns": [
            "department",
            "status",
        ],
    },
}


def main():

    all_variations = []

    for dataset, config in FIELDS.items():

        df = load_file(config["file"])

        print("\n" + "=" * 70)
        print(dataset)
        print("=" * 70)

        for column in config["columns"]:

            if column not in df.columns:
                print(f"WARNING: {column} not found")
                continue

            series = df[column]

            # Keep missing separate
            values = (
                series
                .dropna()
                .astype(str)
                .str.strip()
            )

            counts = (
                values
                .value_counts()
                .reset_index()
            )

            counts.columns = [
                "raw_value",
                "frequency"
            ]

            print(f"\n{column}")
            print(f"Unique non-null values: {len(counts)}")

            # Print all values for smaller categorical fields
            if len(counts) <= 100:
                print(
                    counts.to_string(index=False)
                )
            else:
                print(
                    counts.head(30)
                    .to_string(index=False)
                )

            for _, row in counts.iterrows():

                all_variations.append({
                    "dataset": dataset,
                    "column": column,
                    "raw_value": row["raw_value"],
                    "frequency": int(row["frequency"]),
                })

    result = pd.DataFrame(all_variations)

    result = result.sort_values(
        ["dataset", "column", "frequency"],
        ascending=[True, True, False]
    )

    output = REPORT_DIR / "categorical_variations_full.csv"

    result.to_csv(
        output,
        index=False
    )

    print("\n" + "=" * 70)
    print("STEP 6A COMPLETE")
    print("=" * 70)

    print(f"\nGenerated:")
    print(f"  {output}")


if __name__ == "__main__":
    main()