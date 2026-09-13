from pathlib import Path
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = ROOT / "reports"

IDENTITY_REPORT = REPORTS_DIR / "identity_cleaning_summary.csv"
IAM_REPORT = REPORTS_DIR / "iam_cleaning_summary.csv"
ENDPOINT_REPORT = REPORTS_DIR / "endpoint_cleaning_summary.csv"
FIREWALL_REPORT = REPORTS_DIR / "firewall_cleaning_summary.csv"

OUTPUT = REPORTS_DIR / "before_after_summary.csv"


def load_single_row(path: Path) -> dict:
    df = pd.read_csv(path)

    if len(df) != 1:
        raise ValueError(
            f"Expected exactly one summary row in {path}, found {len(df)}"
        )

    return df.iloc[0].to_dict()


def main():
    identity = load_single_row(IDENTITY_REPORT)
    iam = load_single_row(IAM_REPORT)
    endpoint = load_single_row(ENDPOINT_REPORT)
    firewall = load_single_row(FIREWALL_REPORT)

    rows = [
        {
            "dataset": "Identity",
            "raw_rows": int(identity["raw_rows"]),
            "exact_duplicates_removed": int(identity["exact_duplicates_removed"]),
            "cleaned_rows": int(identity["cleaned_rows"]),
        },
        {
            "dataset": "IAM",
            "raw_rows": int(iam["raw_rows"]),
            "exact_duplicates_removed": int(iam["exact_duplicate_rows_removed"]),
            "cleaned_rows": int(iam["cleaned_rows"]),
        },
        {
            "dataset": "Endpoint",
            "raw_rows": int(endpoint["raw_rows"]),
            "exact_duplicates_removed": int(endpoint["exact_duplicates_removed"]),
            "cleaned_rows": int(endpoint["cleaned_rows"]),
        },
        {
            "dataset": "Firewall",
            "raw_rows": int(firewall["raw_rows"]),
            "exact_duplicates_removed": int(
                firewall["exact_duplicate_rows_removed"]
            ),
            "cleaned_rows": int(firewall["cleaned_rows"]),
        },
    ]

    result = pd.DataFrame(rows)

    result["rows_retained_percent"] = (
        result["cleaned_rows"] / result["raw_rows"] * 100
    ).round(2)

    result["rows_removed_percent"] = (
        result["exact_duplicates_removed"] / result["raw_rows"] * 100
    ).round(2)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUTPUT, index=False)

    print(f"Created: {OUTPUT}")
    print()
    print(result.to_string(index=False))


if __name__ == "__main__":
    main()