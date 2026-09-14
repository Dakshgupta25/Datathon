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
- Invalid final hire dates: 0
- Invalid final termination dates: 0
- Active-like records with source termination dates: 208 flagged for review
- Hire date after termination date: 6 source anomalies flagged
- Terminated-like records missing termination date: 66

The 66 terminated-like records with missing termination dates were retained and flagged.

No termination date was fabricated.

For the final analytical dataset, unavailable textual/date values are represented using documented semantic values such as `Unknown` or `Not Terminated`, so the final dataset contains zero missing cells.

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
- Unresolved timestamps represented as `Unknown`: 4,395
- Invalid or unavailable source IP values handled deterministically
- Final invalid risk scores: 0
- Categorical risk labels were not converted into unsupported numeric values
- Final missing cells: 0

Risk scores were validated against the expected **0–100** numeric range.

Missing or invalid numeric risk values were completed using the median of valid numeric risk scores.

Final median risk-score imputation value:

**50.0**

Categorical risk labels were not artificially converted into numeric scores because the source data did not provide a defensible numeric mapping.

For failure reasons:

- `Not Applicable` is used for successful or non-failure events where a failure reason does not apply.
- `Unknown` is used for login failures where the source does not provide a recoverable failure reason.

---

# 6. Endpoint Quality Validation

Endpoint cleaning validation result:

**16/16 checks PASS**

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
- Valid SHA-256 values: 5,763
- SHA-256 values represented as `Unknown`: 2,237
- Invalid SHA-256 values in final analytical field: 0
- Invalid hostnames: 0
- Final missing cells: 0

Chronology anomalies were flagged rather than automatically correcting or swapping timestamps.

Malformed SHA-256 values were not padded, regenerated or fabricated.

A SHA-256 value is considered valid only when it contains the expected 64 hexadecimal characters.

Unavailable or malformed hash values are represented as `Unknown` in the final analytical dataset.

Missing resolution-duration values were completed using the median of valid resolution durations.

---

# 7. Firewall Quality Validation

Firewall cleaning validation result:

**18/18 checks PASS**

Key results:

- Raw rows: 30,600
- Exact duplicates removed: 600
- Cleaned rows: 30,000
- Unknown timestamps in final analytical field: 6,503
- Final invalid source IP values: 0
- Final invalid destination IP values: 0
- Final invalid source ports: 0
- Final invalid destination ports: 0
- Final invalid bytes-sent values: 0
- Final invalid bytes-received values: 0
- Source port median used: 443
- Destination port median used: 443
- Bytes-sent median used: 24,819,643.22
- Bytes-received median used: 24,526,192.64
- Final missing cells: 0

Network ports were validated using the valid range:

**1–65,535**

Port `0`, negative values and other out-of-range values were treated as invalid.

Negative byte counts were also treated as invalid.

Invalid or unavailable numeric network values were not fabricated. Where required for the final complete analytical dataset, documented median imputation was applied.

---

# 8. Standardization Validation

The cleaning pipeline standardized repeated categorical representations into canonical analytical values.

Examples include:

## Identity

- Department variants → canonical department values
- Status variants → `Active`, `Disabled`, `Terminated`, `On Leave`, `Blocked`
- User ID variants → canonical user IDs
- Hostname variants → canonical hostnames

## IAM

- Event-type variants → canonical event types/categories
- MFA representations → boolean values
- Department variants → canonical departments
- User ID variants → canonical user IDs

## Endpoint

- Severity variants → `Critical`, `High`, `Medium`, `Low`
- Status variants → canonical alert lifecycle states
- Device criticality → `Critical`, `High`, `Medium`, `Low`
- Hostnames → canonical hostname representation

## Firewall

- Protocol variants → canonical protocol values
- Action variants → canonical firewall actions
- Threat flags → boolean values

No unmapped values remained for the validated categorical fields reported by the dataset-specific validators.

---

# 9. Timestamp Validation

Timestamps were parsed using the supported representations implemented in the cleaning pipeline.

The original source data remains preserved separately under `data/raw/`.

For the final analytical datasets, timestamp values that could not be reliably recovered are represented as the semantic value `Unknown`.

This does not represent a fabricated timestamp. It explicitly records that the source timestamp was unavailable or unrecoverable.

Important results:

| Dataset | Timestamp Result |
|---|---|
| Identity | Hire/termination date validation passed; source date anomalies were flagged |
| IAM | 4,395 timestamps represented as `Unknown` |
| Endpoint | 0 invalid detected timestamps; 0 invalid resolved timestamps |
| Firewall | 6,503 timestamps represented as `Unknown` |

Endpoint chronology was validated separately.

A total of **263 chronology anomalies** were flagged and retained.

No timestamps were swapped, guessed or fabricated.

---

# 10. Network Field Validation

Network-related fields were validated before being used as analytical values.

## IP addresses

Source and destination IP addresses were validated using IP address parsing.

Malformed or unavailable IP values are not treated as valid IP indicators.

Where required in the final analytical dataset, unavailable values are represented using the documented semantic value `Unknown`.

## Ports

Ports are valid only when they fall within:

`1–65535`

Port `0`, negative values and values outside the valid network-port domain are invalid.

The final analytical port fields contain no invalid values.

Unavailable numeric port values were completed using the documented median value.

## Bytes

Byte fields are converted to numeric analytical values where valid.

Supported unit representations are converted into numeric byte values.

Negative and otherwise invalid values are treated as invalid source measurements.

Where required for the final complete analytical dataset, unavailable numeric byte values were completed using documented median values.

This prevents invalid network measurements from being silently interpreted as legitimate telemetry.

---

# 11. Hash Validation

Endpoint SHA-256 values were validated against the expected:

- 64-character length
- hexadecimal character format

Invalid or incomplete hashes were not repaired by padding or regenerated.

Result:

- Valid SHA-256 values: **5,763**
- SHA-256 values represented as `Unknown`: **2,237**
- Invalid SHA-256 values remaining in final analytical field: **0**

Malformed or incomplete source hashes were not fabricated.

They are represented as `Unknown` in the final analytical dataset.

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

These results demonstrate complete user-ID coverage for the supplied IAM and Endpoint records against the cleaned Identity master.

---

## Hostname integration

### Endpoint → Identity using hostname

**INFORMATION / SOURCE COVERAGE LIMITATION**

- 6,404 matched
- 1,115 unmatched
- 7,519 usable hostnames
- 85.17% hostname coverage

### Firewall → Identity using hostname

**INFORMATION / SOURCE COVERAGE LIMITATION**

- 24,287 matched
- 3,956 unmatched
- 28,243 usable hostnames
- 85.99% hostname coverage

The unmatched hostname records were not assigned synthetic Identity records.

These unmatched records represent source-data coverage limitations rather than automatically correctable cleaning errors.

---

## IAM → Firewall session coverage

**INFORMATIONAL**

- 261 matched
- 11,263 unmatched
- 11,524 usable session IDs
- 2.26% session coverage

This check is treated as informational because complete session-level coverage across the supplied telemetry sources is not guaranteed.

No synthetic session relationships were created.

---

# 13. Cleaned Identity Key Validation

The cleaned Identity master was checked for key uniqueness.

Results:

- Duplicate cleaned user IDs: 0
- Duplicate cleaned hostnames: 0

This provides a stable reference key structure for downstream integration.

---

# 14. Raw Data Preservation and Traceability

The cleaning pipeline follows a raw-data preservation strategy.

Raw datasets remain under:

`data/raw/`

Raw source files are not modified by the cleaning process.

Cleaned analytical outputs are generated under:

`data/cleaned/`

The final cleaned datasets contain the analytical fields required for downstream analysis rather than retaining every intermediate cleaning column.

Traceability is maintained through:

- reproducible cleaning scripts under `src/cleaning/`
- independent validation scripts under `src/validation/`
- cleaning summaries under `reports/`
- cleaning decisions documented in `docs/cleaning_decisions.md`
- before/after summaries
- dataset-specific validation reports
- cleaned join validation reports

This separation keeps the final analytical datasets clean while preserving the evidence required to reproduce and audit the cleaning process.

---

# 15. Final Missing-Value Strategy

The final analytical datasets intentionally contain **zero missing cells**.

Missing values were not handled using blanket deletion or indiscriminate imputation.

The following deterministic rules were applied:

## Text and categorical fields

Unavailable or unrecoverable textual values are represented as:

`Unknown`

This explicitly indicates that a usable source value was not available.

## Termination dates

For employees who are not terminated, a missing termination date is represented as:

`Not Terminated`

For terminated-like records where the source does not provide a recoverable termination date:

`Unknown`

These values represent semantic states rather than fabricated dates.

## Numeric fields

Only selected numeric analytical fields use median imputation where required to produce complete analytical datasets.

Examples include:

- IAM risk score
- Endpoint resolution duration
- Firewall source port
- Firewall destination port
- Firewall bytes sent
- Firewall bytes received

Median values are calculated from valid source-derived numeric observations and documented in the cleaning outputs.

No unsupported numeric values are generated from categorical labels.

---

# 16. Known Data Quality Limitations

The following source-data limitations remain intentionally documented:

1. Some IAM timestamps could not be reliably recovered and are represented as `Unknown`.

2. Some IAM source IP values were malformed or unavailable and were handled deterministically.

3. Some Firewall source and destination IP values were malformed or unavailable.

4. Some Firewall port values were invalid or unavailable and were handled using validation plus documented median completion.

5. Some Firewall byte values were invalid or unavailable and were handled using validation plus documented median completion.

6. Some Endpoint SHA-256 values were malformed, incomplete or unavailable and are represented as `Unknown`.

7. Some Endpoint records contain detected/resolved timestamp chronology anomalies.

8. Some terminated-like Identity records have no termination date; these records remain flagged rather than having dates fabricated.

9. Some Endpoint hostnames have no corresponding Identity master record.

10. Some Firewall hostnames have no corresponding Identity master record.

11. IAM-to-Firewall session coverage is incomplete.

These limitations are explicitly documented rather than hidden.

No synthetic identity records, fabricated timestamps, fabricated hashes or unsupported categorical-to-numeric conversions were introduced.

---

# 17. Validation Summary

| Validation Area | Result |
|---|---|
| Identity validation | 15/15 PASS |
| IAM validation | 12/12 PASS |
| Endpoint validation | 16/16 PASS |
| Firewall validation | 18/18 PASS |
| IAM → Identity user ID | PASS |
| Endpoint → Identity user ID | PASS |
| Identity user ID uniqueness | PASS |
| Identity hostname uniqueness | PASS |
| Endpoint → Identity hostname | 6,404 matched / 1,115 unmatched; 85.17% coverage |
| Firewall → Identity hostname | 24,287 matched / 3,956 unmatched; 85.99% coverage |
| IAM → Firewall session coverage | 261 matched / 11,263 unmatched; 2.26% coverage |
| Final missing cells | 0 across all four cleaned datasets |
| Final exact duplicate rows | 0 across all four cleaned datasets |

---

# 18. Conclusion

The four datasets have been cleaned and independently validated using reproducible Python-based cleaning and validation scripts.

The cleaning process:

- removes exact duplicate records
- standardizes equivalent categorical representations
- canonicalizes user IDs and hostnames
- validates timestamps
- validates network fields
- validates endpoint hashes
- preserves raw source files separately from analytical outputs
- uses deterministic semantic handling for unavailable values
- uses documented median imputation only for selected numeric analytical fields
- avoids fabricating timestamps
- avoids fabricating hashes
- avoids fabricating identity records
- avoids unsupported categorical-to-numeric conversions
- normalizes cross-dataset join keys
- validates final analytical schemas
- documents source-data coverage limitations
- independently validates the final cleaned datasets

The resulting cleaned datasets contain **zero missing cells**, conform to their final analytical schemas, and are suitable as the input layer for the next analytics stage.

Known source-data limitations remain explicitly documented so that downstream analysis can distinguish cleaned data quality from source-data coverage limitations.