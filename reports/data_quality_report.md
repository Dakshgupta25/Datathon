# Data Quality Report

## 1. Purpose

This report provides consolidated evidence of the data rescue, cleaning, standardization and validation performed on the four Track 2 cybersecurity datasets.

The objective is to produce consistent, validated and analytics-ready datasets while preserving raw source data and documenting known source-data limitations.

Raw source files are not modified.

---

# 2. Dataset Overview

| Dataset | Purpose | Raw Rows | Cleaned Rows | Exact Duplicates Removed |
|---|---|---:|---:|---:|
| Identity | Employee identity and asset master | 3,090 | 3,000 | 90 |
| IAM | Identity and access management telemetry | 20,500 | 20,000 | 500 |
| Endpoint | Endpoint security alerts | 8,240 | 8,000 | 240 |
| Firewall | Network firewall telemetry | 30,600 | 30,000 | 600 |

Total cleaned telemetry/event records: **58,000**

Cleaned Identity master records: **3,000**

---

# 3. Duplicate Validation

Exact duplicate records were removed from each dataset.

| Dataset | Raw Rows | Exact Duplicates Removed | Cleaned Rows |
|---|---:|---:|---:|
| Identity | 3,090 | 90 | 3,000 |
| IAM | 20,500 | 500 | 20,000 |
| Endpoint | 8,240 | 240 | 8,000 |
| Firewall | 30,600 | 600 | 30,000 |

After cleaning, dataset-specific validation confirmed that exact duplicate rows and duplicate primary identifiers were removed according to the implemented validation rules.

Duplicate records were not removed using a blanket `dropna()` or arbitrary identifier-based deletion.

---

# 4. Identity Quality Validation

Identity cleaning validation result:

**15/15 checks PASS**

Key results:

- Cleaned rows: 3,000
- Duplicate cleaned user IDs: 0
- Invalid user IDs: 0
- Unmapped departments: 0
- Unmapped statuses: 0
- Invalid hostnames: 0
- Invalid hire dates: 0
- Invalid termination dates: 0
- Active records with termination dates: 0
- Hire date after termination date: 0
- Terminated-like records missing termination date: 66

The 66 terminated-like records with missing termination dates were retained and flagged.

No termination date was fabricated.

---

# 5. IAM Quality Validation

IAM cleaning validation result:

**12/12 checks PASS**

Key results:

- Raw rows: 20,500
- Exact duplicates removed: 500
- Cleaned rows: 20,000
- Invalid user IDs: 0
- Unmapped departments: 0
- Unmapped event types: 0
- Invalid MFA values: 0
- Invalid timestamps: 4,395
- Invalid source IP values: 10,117
- Out-of-range risk scores: 2,607
- Invalid risk-score format: 0
- Categorical risk values: 1,353
- Missing risk values: 1,037

Risk scores were not artificially converted from categorical labels into numeric values.

Numeric risk scores were validated against the expected 0–100 range.

---

# 6. Endpoint Quality Validation

Endpoint cleaning validation result:

**12/12 checks PASS**

Key results:

- Raw rows: 8,240
- Exact duplicates removed: 240
- Cleaned rows: 8,000
- Invalid user IDs: 0
- Unmapped severity values: 0
- Unmapped status values: 0
- Unmapped device criticality values: 0
- Invalid detected timestamps: 0
- Invalid resolved timestamps: 0
- Chronology anomalies: 263
- Invalid SHA-256 values: 799
- Invalid hostnames: 0

Chronology anomalies were flagged rather than automatically correcting or swapping timestamps.

Malformed SHA-256 values were not padded, regenerated or fabricated.

---

# 7. Firewall Quality Validation

Firewall cleaning validation result:

**16/16 checks PASS**

Key results:

- Raw rows: 30,600
- Exact duplicates removed: 600
- Cleaned rows: 30,000
- Invalid timestamps: 2,986
- Invalid source IP values: 13,471
- Invalid destination IP values: 12,756
- Invalid source ports: 3,608
- Invalid destination ports: 3,556
- Invalid bytes-sent values: 5,101
- Invalid bytes-received values: 5,086

Network ports were validated using the valid range:

**1–65,535**

Port `0`, negative values and other out-of-range values were treated as invalid.

Negative byte counts were also treated as invalid.

---

# 8. Standardization Validation

The cleaning pipeline standardized repeated categorical representations into canonical analytical values.

Examples include:

### Identity

- Department variants → canonical department values
- Status variants → Active, Disabled, Terminated, On Leave, Blocked

### IAM

- Event-type variants → canonical event types/categories
- MFA representations → boolean values
- Department variants → canonical departments

### Endpoint

- Severity variants → Critical, High, Medium, Low
- Status variants → canonical alert lifecycle states
- Device criticality → Critical, High, Medium, Low

### Firewall

- Protocol variants → canonical protocol values
- Action variants → canonical firewall actions
- Threat flags → boolean values

No unmapped values remained for the validated categorical fields reported by the dataset-specific validators.

---

# 9. Timestamp Validation

Timestamps were parsed using the supported representations implemented in the cleaning pipeline.

The original timestamp values are retained for traceability.

Unparseable values were not guessed or replaced with fabricated timestamps.

Important results:

| Dataset | Timestamp Result |
|---|---|
| Identity | Hire/termination date validation passed |
| IAM | 4,395 invalid timestamps identified |
| Endpoint | 0 invalid detected timestamps; 0 invalid resolved timestamps |
| Firewall | 2,986 invalid timestamps identified |

Endpoint chronology was validated separately.

A total of **263 chronology anomalies** were flagged and retained.

---

# 10. Network Field Validation

Network-related fields were validated before being used as analytical values.

### IP addresses

Malformed source/destination IP values are not treated as valid IP indicators.

### Ports

Ports are valid only when they fall within:

`1–65535`

### Bytes

Byte fields are converted to numeric analytical values where valid.

Negative and otherwise invalid values are not fabricated.

This prevents invalid network measurements from being silently interpreted as legitimate telemetry.

---

# 11. Hash Validation

Endpoint SHA-256 values were validated against the expected:

- 64-character length
- hexadecimal character format

Invalid or incomplete hashes were not repaired by padding or regenerated.

Result:

- Invalid SHA-256 values identified: 799

The original hash value remains available through the corresponding raw field.

---

# 12. Join-Key Validation

Cleaned join keys were normalized before integration checks.

## Passed joins

### IAM → Identity using user ID

**PASS**

- 20,000 matched
- 0 unmatched
- 20,000 usable IDs

### Endpoint → Identity using user ID

**PASS**

- 8,000 matched
- 0 unmatched
- 8,000 usable IDs

## Hostname integration

### Endpoint → Identity using hostname

**REQUIRES REVIEW**

- 7,037 matched
- 482 unmatched
- 7,519 usable hostnames

### Firewall → Identity using hostname

**REQUIRES REVIEW**

- 26,665 matched
- 1,578 unmatched
- 28,243 usable hostnames

The unmatched hostname records were not assigned synthetic Identity records.

These unmatched records represent source-data coverage limitations.

## IAM → Firewall session coverage

**INFORMATIONAL**

- 261 matched
- 11,263 unmatched
- 11,524 usable session IDs

This check is treated as informational because complete session-level coverage across the supplied telemetry sources is not guaranteed.

---

# 13. Cleaned Identity Key Validation

The cleaned Identity master was checked for key uniqueness.

Results:

- Duplicate cleaned user IDs: 0
- Duplicate cleaned hostnames: 0

This provides a stable reference key structure for downstream integration.

---

# 14. Raw Data Preservation

The cleaning pipeline follows a raw-data preservation strategy.

Raw datasets remain under:

`data/raw/`

Cleaned outputs are generated under:

`data/cleaned/`

Raw/source representations are retained in cleaned datasets through fields such as:

- `*_raw`

Standardized analytical values are represented through fields such as:

- `*_clean`

Validation information is represented through:

- `*_valid`
- `*_status`
- `*_issue`
- `*_reason`

This provides traceability from an analytical value back to its original source representation.

---

# 15. Known Data Quality Limitations

The following limitations remain intentionally visible:

1. Some IAM timestamps are unparseable.
2. Some IAM source IP values are invalid.
3. Some Firewall source and destination IP values are invalid.
4. Some Firewall port values are invalid.
5. Some Firewall byte values are invalid.
6. Some Endpoint SHA-256 values are malformed or incomplete.
7. Some Endpoint records contain detected/resolved timestamp chronology anomalies.
8. Some terminated-like Identity records have no termination date.
9. Some Endpoint hostnames have no corresponding Identity master record.
10. Some Firewall hostnames have no corresponding Identity master record.
11. IAM-to-Firewall session coverage is incomplete.

These limitations are reported rather than hidden or artificially corrected.

---

# 16. Validation Summary

| Validation Area | Result |
|---|---|
| Identity validation | 15/15 PASS |
| IAM validation | 12/12 PASS |
| Endpoint validation | 12/12 PASS |
| Firewall validation | 16/16 PASS |
| IAM → Identity user ID | PASS |
| Endpoint → Identity user ID | PASS |
| Identity user ID uniqueness | PASS |
| Identity hostname uniqueness | PASS |
| Endpoint → Identity hostname | 482 unmatched; source coverage limitation |
| Firewall → Identity hostname | 1,578 unmatched; source coverage limitation |
| IAM → Firewall session coverage | Informational |

---

# 17. Conclusion

The four datasets have been cleaned and independently validated using reproducible Python-based cleaning and validation scripts.

The cleaning process:

- removes exact duplicate records
- standardizes equivalent categorical representations
- validates timestamps
- validates network fields
- validates endpoint hashes
- preserves raw values for traceability
- avoids fabricated values
- normalizes cross-dataset join keys
- documents source-data coverage limitations

The resulting cleaned datasets are suitable as the input layer for the next analytics stage.

Known quality limitations remain explicitly documented so that downstream analysis can distinguish cleaned data from source-data gaps.