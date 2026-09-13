import pandas as pd
import numpy as np
import ipaddress
import re
from pathlib import Path


RAW_DIR = Path("data/raw")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_csv(filename):
    return pd.read_csv(RAW_DIR / filename)


def validate_ip(value):
    if pd.isna(value):
        return "missing"

    value = str(value).strip()

    if not value:
        return "missing"

    try:
        ipaddress.ip_address(value)
        return "valid"
    except ValueError:
        return "invalid"


def validate_port(value):
    if pd.isna(value):
        return "missing"

    try:
        value = float(value)

        if value.is_integer() and 0 <= value <= 65535:
            return "valid"

        return "invalid"

    except (ValueError, TypeError):
        return "invalid"


def parse_bytes(value):
    if pd.isna(value):
        return np.nan

    text = str(value).strip().upper()

    if not text:
        return np.nan

    # Plain numeric bytes
    try:
        return float(text)
    except ValueError:
        pass

    # Values such as:
    # 20.48 MB
    # 500 KB
    # 1.5 GB
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


def profile_ip(df, dataset, column):

    status = df[column].apply(validate_ip)

    return {
        "dataset": dataset,
        "field": column,
        "type": "IP address",
        "missing": int((status == "missing").sum()),
        "valid": int((status == "valid").sum()),
        "invalid": int((status == "invalid").sum()),
    }


def profile_port(df, dataset, column):

    status = df[column].apply(validate_port)

    return {
        "dataset": dataset,
        "field": column,
        "type": "Port",
        "missing": int((status == "missing").sum()),
        "valid": int((status == "valid").sum()),
        "invalid": int((status == "invalid").sum()),
    }


def profile_bytes(df, dataset, column):

    parsed = df[column].apply(parse_bytes)

    non_missing = df[column].notna()

    return {
        "dataset": dataset,
        "field": column,
        "type": "Bytes",
        "missing": int(df[column].isna().sum()),
        "valid": int((parsed.notna() & non_missing).sum()),
        "invalid": int((parsed.isna() & non_missing).sum()),
    }


def analyze_risk_score(df):

    results = []

    series = df["risk_score"]

    for value in series:

        if pd.isna(value):
            category = "missing"
            numeric = np.nan

        else:
            text = str(value).strip()

            # Direct numeric
            try:
                numeric = float(text)
                category = "numeric"

            except ValueError:

                # Values such as 78/100
                match = re.fullmatch(
                    r"\s*([0-9]+(?:\.[0-9]+)?)\s*/\s*100\s*",
                    text
                )

                if match:
                    numeric = float(match.group(1))
                    category = "numeric_fraction"

                elif text.lower() in {"high", "medium", "low"}:
                    numeric = np.nan
                    category = "categorical_risk"

                else:
                    numeric = np.nan
                    category = "invalid"

        results.append({
            "raw_value": value,
            "category": category,
            "numeric_value": numeric
        })

    result_df = pd.DataFrame(results)

    return result_df


def main():

    summary = []

    # ==========================================================
    # FIREWALL
    # ==========================================================

    firewall = load_csv("track2_firewall_logs.csv")

    print("\n" + "=" * 60)
    print("FIREWALL")
    print("=" * 60)

    for column in ["src_ip", "dst_ip"]:

        result = profile_ip(
            firewall,
            "FIREWALL",
            column
        )

        summary.append(result)

        print(
            f"{column}: "
            f"valid={result['valid']:,}, "
            f"invalid={result['invalid']:,}, "
            f"missing={result['missing']:,}"
        )

    for column in ["src_port", "dst_port"]:

        result = profile_port(
            firewall,
            "FIREWALL",
            column
        )

        summary.append(result)

        print(
            f"{column}: "
            f"valid={result['valid']:,}, "
            f"invalid={result['invalid']:,}, "
            f"missing={result['missing']:,}"
        )

    for column in ["bytes_sent", "bytes_received"]:

        result = profile_bytes(
            firewall,
            "FIREWALL",
            column
        )

        summary.append(result)

        print(
            f"{column}: "
            f"valid={result['valid']:,}, "
            f"invalid={result['invalid']:,}, "
            f"missing={result['missing']:,}"
        )

    # ==========================================================
    # IAM
    # ==========================================================

    iam = pd.read_json(
        RAW_DIR / "track2_iam_audit_trail.json"
    )

    print("\n" + "=" * 60)
    print("IAM")
    print("=" * 60)

    result = profile_ip(
        iam,
        "IAM",
        "source_ip"
    )

    summary.append(result)

    print(
        f"source_ip: "
        f"valid={result['valid']:,}, "
        f"invalid={result['invalid']:,}, "
        f"missing={result['missing']:,}"
    )

    # Risk score analysis
    risk_df = analyze_risk_score(iam)

    print("\nRisk score categories:")
    print(
        risk_df["category"]
        .value_counts(dropna=False)
        .to_string()
    )

    # Numeric risk range
    numeric_risk = risk_df["numeric_value"].dropna()

    print("\nNumeric risk score:")
    print(f"Numeric values : {len(numeric_risk):,}")

    if len(numeric_risk) > 0:
        print(f"Minimum        : {numeric_risk.min()}")
        print(f"Maximum        : {numeric_risk.max()}")

        outside = (
            (numeric_risk < 0)
            | (numeric_risk > 100)
        ).sum()

        print(f"Outside 0-100  : {outside:,}")

    # ==========================================================
    # SAVE REPORTS
    # ==========================================================

    summary_df = pd.DataFrame(summary)

    summary_df.to_csv(
        REPORT_DIR / "network_numeric_validation.csv",
        index=False
    )

    risk_df.to_csv(
        REPORT_DIR / "risk_score_analysis.csv",
        index=False
    )

    print("\n" + "=" * 60)
    print("STEP 5 COMPLETE")
    print("=" * 60)

    print(
        "\nGenerated reports:"
        "\n  reports/network_numeric_validation.csv"
        "\n  reports/risk_score_analysis.csv"
    )


if __name__ == "__main__":
    main()