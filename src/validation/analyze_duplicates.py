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
# PRIMARY KEY / ID COLUMNS
# ============================================================

ID_COLUMNS = {
    "firewall": "log_id",
    "iam": "event_id",
    "endpoint": "alert_id",
    "identity": "user_id",
}


# ============================================================
# EXACT DUPLICATES
# ============================================================

def analyze_exact_duplicates(name, df):

    duplicate_mask = df.duplicated(keep=False)

    duplicate_rows = df[duplicate_mask].copy()

    return {
        "dataset": name,
        "total_rows": len(df),
        "exact_duplicate_rows": len(duplicate_rows),
        "exact_duplicate_groups": (
            duplicate_rows.drop_duplicates().shape[0]
            if not duplicate_rows.empty
            else 0
        ),
        "duplicate_percentage": round(
            len(duplicate_rows) / len(df) * 100,
            2
        ),
    }


# ============================================================
# DUPLICATE ID ANALYSIS
# ============================================================

def analyze_duplicate_ids(name, df, id_column):

    id_counts = df[id_column].value_counts(
        dropna=False
    )

    duplicated_ids = id_counts[
        id_counts > 1
    ]

    affected_rows = int(
        duplicated_ids.sum()
    )

    return {
        "dataset": name,
        "id_column": id_column,
        "unique_ids": int(
            df[id_column].nunique(dropna=True)
        ),
        "duplicate_id_values": len(
            duplicated_ids
        ),
        "rows_with_duplicate_ids": affected_rows,
    }


# ============================================================
# CONFLICTING DUPLICATE IDs
# ============================================================

def find_conflicting_ids(name, df, id_column):

    duplicate_ids = (
        df[id_column]
        .value_counts()
        .loc[lambda x: x > 1]
        .index
    )

    records = []

    for value in duplicate_ids:

        if pd.isna(value):
            continue

        group = df[
            df[id_column] == value
        ]

        # Number of distinct rows for this ID
        distinct_rows = len(
            group.drop_duplicates()
        )

        if distinct_rows > 1:

            records.append({
                "dataset": name,
                "id_column": id_column,
                "id_value": value,
                "row_count": len(group),
                "distinct_row_count": distinct_rows,
            })

    return pd.DataFrame(records)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("DUPLICATE ANALYSIS")
    print("=" * 70)

    datasets = load_datasets()

    exact_results = []
    id_results = []
    conflict_results = []

    for name, df in datasets.items():

        id_column = ID_COLUMNS[name]

        print(f"\n{name.upper()}")
        print("-" * 70)

        # Exact duplicates
        exact = analyze_exact_duplicates(
            name,
            df
        )

        exact_results.append(exact)

        print(
            f"Exact duplicate rows : "
            f"{exact['exact_duplicate_rows']:,}"
        )

        # Duplicate IDs
        duplicate_ids = analyze_duplicate_ids(
            name,
            df,
            id_column
        )

        id_results.append(
            duplicate_ids
        )

        print(
            f"Duplicate {id_column} values : "
            f"{duplicate_ids['duplicate_id_values']:,}"
        )

        print(
            f"Rows with duplicate IDs : "
            f"{duplicate_ids['rows_with_duplicate_ids']:,}"
        )

        # Conflicting IDs
        conflicts = find_conflicting_ids(
            name,
            df,
            id_column
        )

        if not conflicts.empty:
            conflict_results.append(conflicts)

            print(
                f"Conflicting duplicate IDs : "
                f"{len(conflicts):,}"
            )
        else:
            print(
                "Conflicting duplicate IDs : 0"
            )

    # ========================================================
    # SAVE REPORTS
    # ========================================================

    pd.DataFrame(exact_results).to_csv(
        REPORT_DIR / "exact_duplicate_summary.csv",
        index=False
    )

    pd.DataFrame(id_results).to_csv(
        REPORT_DIR / "duplicate_id_summary.csv",
        index=False
    )

    if conflict_results:

        pd.concat(
            conflict_results,
            ignore_index=True
        ).to_csv(
            REPORT_DIR / "conflicting_duplicate_ids.csv",
            index=False
        )

    else:

        pd.DataFrame(
            columns=[
                "dataset",
                "id_column",
                "id_value",
                "row_count",
                "distinct_row_count",
            ]
        ).to_csv(
            REPORT_DIR / "conflicting_duplicate_ids.csv",
            index=False
        )

    print("\n" + "=" * 70)
    print("DUPLICATE ANALYSIS COMPLETE")
    print("=" * 70)

    print("\nReports generated:")
    print(
        "1. reports/exact_duplicate_summary.csv"
    )
    print(
        "2. reports/duplicate_id_summary.csv"
    )
    print(
        "3. reports/conflicting_duplicate_ids.csv"
    )


if __name__ == "__main__":
    main()