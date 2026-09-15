"""
TraceONE Master Data Pipeline Runner
Phases A-G: RAW -> CLEANING -> CANONICAL -> FEATURES -> BASELINES -> RISK ENGINE -> TEMPORAL -> VALIDATION -> PROCESSED

Reproducibly executes all data cleaning, canonical transformation, feature engineering, behavioral baseline generation, risk engine calculation, temporal correlation, and validation scripts.
"""

from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]

CLEANING_SCRIPTS = [
    "src/cleaning/clean_identity.py",
    "src/cleaning/clean_iam.py",
    "src/cleaning/clean_endpoint.py",
    "src/cleaning/clean_firewall.py",
]

TRANSFORMATION_SCRIPTS = [
    "src/transformations/canonical_events.py",
    "src/transformations/feature_tables.py",
    "src/transformations/behavioral_baselines.py",
    "src/transformations/risk_engine.py",
    "src/transformations/temporal_engine.py",
    "src/graph/graph_builder.py",
    "src/transformations/advanced_insights.py",
]

VALIDATION_SCRIPTS = [
    "src/validation/validate_identity_cleaned.py",
    "src/validation/validate_iam_cleaned.py",
    "src/validation/validate_endpoint_cleaned.py",
    "src/validation/validate_firewall_cleaned.py",
    "src/validation/validate_cleaned_joins.py",
    "src/validation/validate_canonical_model.py",
    "src/validation/validate_features.py",
    "src/validation/validate_baselines.py",
    "src/validation/validate_risk_engine.py",
    "src/validation/validate_temporal.py",
    "src/validation/validate_graph.py",
    "src/validation/validate_advanced_insights.py",
    "src/validation/validate_dashboard.py",
    "src/validation/validate_investigation_center.py",
    "src/validation/validate_data_trust_center.py",
    "src/validation/validate_ai_investigator.py",
]



def run_script(rel_path):
    abs_path = PROJECT_ROOT / rel_path
    print(f"\n[{rel_path}] Executing...")
    res = subprocess.run([sys.executable, str(abs_path)], cwd=PROJECT_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"FAILED: {rel_path}")
        print("STDERR:\n", res.stderr)
        raise RuntimeError(f"Script failed: {rel_path}")
    print(f"SUCCESS: {rel_path}")


def main():
    print("=" * 70)
    print("TRACEONE MASTER PIPELINE EXECUTION (PHASE G ENRICHED)")
    print("=" * 70)

    print("\n--- PHASE 1: DATA CLEANING ---")
    for script in CLEANING_SCRIPTS:
        run_script(script)

    print("\n--- PHASE 2: CANONICAL TRANSFORMATIONS & FEATURES ---")
    for script in TRANSFORMATION_SCRIPTS:
        run_script(script)

    print("\n--- PHASE 3: DATA QUALITY & FEATURE VALIDATION ---")
    for script in VALIDATION_SCRIPTS:
        run_script(script)

    print("\n" + "=" * 70)
    print("TRACEONE PIPELINE COMPLETED SUCCESSFULLY (100% REPRODUCIBLE)")
    print("=" * 70)


if __name__ == "__main__":
    main()
