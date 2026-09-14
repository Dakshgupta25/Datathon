# TransOrg AgentIQ Datathon — Track 2

## Zero-Trust Telemetry & Insider Threat Logs

### Data Rescue, Cleaning & Analytics-Ready Data Layer

This repo holds the data engineering side of our work for Track 2: Cybersecurity — Zero-Trust Telemetry & Insider Threat Logs — data rescue, cleaning, validation, and the quality documentation that goes with it.

The idea for this stage was pretty simple to state, if not to do: take the messy cybersecurity datasets we were handed, clean and standardize them, check the quality of what came out, keep the raw source data around, write down every major cleaning decision we made, and end up with consistent datasets that are actually ready for analysis.

> **Scope:** This repo covers Phase 1 and Phase 2 only — data rescue, cleaning, validation, data-quality documentation, and the analytics-ready data layer. The dashboard and the AI agent are separate efforts and not part of this repo.

---

# 1. Project Objective

The data we started with had basically every real-world data-quality problem you'd expect to run into:

- duplicate records
- inconsistent categorical values
- inconsistent user ID representations
- inconsistent hostname representations
- missing values
- malformed IP addresses
- invalid network ports
- invalid byte values
- mixed timestamp formats
- malformed SHA-256 values
- inconsistent authentication and MFA representations
- invalid or out-of-range risk scores
- cross-dataset join-key inconsistencies
- gaps in source data coverage

Our objective was to turn all of that into consistent, validated data we could actually build on — without ever inventing information the source data didn't support.

---

# 2. Source Datasets

We worked through four datasets in total.

| Dataset | Purpose | Raw Rows | Cleaned Rows | Exact Duplicates Removed |
|---|---|---:|---:|---:|
| Identity | Employee identity and asset master | 3,090 | 3,000 | 90 |
| IAM | Identity and access management telemetry | 20,500 | 20,000 | 500 |
| Endpoint | Endpoint security alerts | 8,240 | 8,000 | 240 |
| Firewall | Network firewall telemetry | 30,600 | 30,000 | 600 |

That comes out to **58,000** cleaned telemetry/event records in total, plus **3,000** cleaned Identity master records.

---

# 3. Final Cleaned Data

The final analytical datasets live here:

```
data/cleaned/
├── identity_cleaned.csv
├── iam_cleaned.csv
├── endpoint_cleaned.csv
└── firewall_cleaned.csv
```