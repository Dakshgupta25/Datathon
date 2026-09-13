import pandas as pd
from pathlib import Path


RAW_DIR = Path("data/raw")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


FILES = {
    "FIREWALL": ("track2_firewall_logs.csv", ["timestamp"]),
    "IAM": ("track2_iam_audit_trail.json", ["timestamp"]),
    "ENDPOINT": (
        "track2_endpoint_alerts.xlsx",
        ["detected_timestamp", "resolved_timestamp"],
    ),
    "IDENTITY": (
        "track2_identity_asset_master.csv",
        ["hire_date", "termination_date"],
    ),
}


def load_file(path):
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    elif path.suffix.lower() == ".json":
        return pd.read_json(path)
    elif path.suffix.lower() in [".xlsx", ".xls"]:
        return pd.read_excel(path)
    else:
        raise ValueError(f"Unsupported file type: {path}")


def profile_column(df, dataset, column):
    series = df[column]

    raw_missing = series.isna().sum()

    # Convert to string only for parsing non-null values
    non_null = series.dropna().astype(str).str.strip()

    parsed = pd.to_datetime(
        non_null,
        errors="coerce",
        format="mixed",
        utc=True
    )

    parse_failures = parsed.isna().sum()
    parseable = parsed.notna().sum()

    return {
        "dataset": dataset,
        "column": column,
        "original_dtype": str(series.dtype),
        "total_rows": len(series),
        "raw_missing": int(raw_missing),
        "non_missing": int(len(non_null)),
        "parseable_values": int(parseable),
        "parse_failures": int(parse_failures),
        "parse_success_rate_pct": round(
            (parseable / len(non_null)) * 100, 2
        ) if len(non_null) else 0,
        "unique_raw_values": int(non_null.nunique()),
    }


def main():

    datatype_results = []
    parse_failure_examples = []
    chronology_results = []

    for dataset, (filename, timestamp_columns) in FILES.items():

        path = RAW_DIR / filename
        df = load_file(path)

        print(f"\n{'=' * 60}")
        print(f"{dataset}")
        print(f"{'=' * 60}")

        print(f"Rows    : {len(df):,}")
        print(f"Columns : {len(df.columns)}")

        # Check every column's dtype
        for column in df.columns:
            print(
                f"{column:25} -> "
                f"{df[column].dtype}"
            )

        # Timestamp/date profiling
        for column in timestamp_columns:

            if column not in df.columns:
                print(f"WARNING: {column} not found in {dataset}")
                continue

            result = profile_column(
                df,
                dataset,
                column
            )

            datatype_results.append(result)

            print(
                f"\n{column}"
                f"\n  Raw missing       : {result['raw_missing']:,}"
                f"\n  Parseable         : {result['parseable_values']:,}"
                f"\n  Parse failures    : {result['parse_failures']:,}"
                f"\n  Success rate      : {result['parse_success_rate_pct']}%"
            )

            # Save examples of values that failed parsing
            series = df[column]

            non_null = series.dropna().astype(str).str.strip()

            parsed = pd.to_datetime(
                non_null,
                errors="coerce",
                format="mixed",
                utc=True
            )

            failures = non_null[parsed.isna()]

            for value in failures.drop_duplicates().head(100):
                parse_failure_examples.append({
                    "dataset": dataset,
                    "column": column,
                    "raw_value": value
                })

        # Endpoint chronology validation
        if dataset == "ENDPOINT":

            detected = pd.to_datetime(
                df["detected_timestamp"],
                errors="coerce",
                format="mixed",
                utc=True
            )

            resolved = pd.to_datetime(
                df["resolved_timestamp"],
                errors="coerce",
                format="mixed",
                utc=True
            )

            impossible = (
                detected.notna()
                & resolved.notna()
                & (resolved < detected)
            )

            count = int(impossible.sum())

            chronology_results.append({
                "dataset": dataset,
                "check": "resolved_before_detected",
                "affected_rows": count
            })

            print(
                f"\nChronology issue - "
                f"resolved before detected: {count:,}"
            )

    # Save reports
    datatype_df = pd.DataFrame(datatype_results)
    datatype_df.to_csv(
        REPORT_DIR / "datatype_timestamp_summary.csv",
        index=False
    )

    failure_df = pd.DataFrame(parse_failure_examples)
    failure_df.to_csv(
        REPORT_DIR / "timestamp_parse_failure_examples.csv",
        index=False
    )

    chronology_df = pd.DataFrame(chronology_results)
    chronology_df.to_csv(
        REPORT_DIR / "timestamp_chronology_issues.csv",
        index=False
    )

    print("\n" + "=" * 60)
    print("STEP 4 COMPLETE")
    print("=" * 60)

    print(
        "\nGenerated reports:"
        "\n  reports/datatype_timestamp_summary.csv"
        "\n  reports/timestamp_parse_failure_examples.csv"
        "\n  reports/timestamp_chronology_issues.csv"
    )


if __name__ == "__main__":
    main()