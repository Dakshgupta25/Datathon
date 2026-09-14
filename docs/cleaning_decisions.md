# Data Cleaning Decisions

## 1. Purpose

This document records the cleaning decisions applied to the four Track 2 cybersecurity datasets.

The objective is to convert the supplied raw telemetry and identity data into consistent, validated, analytics-ready datasets while maintaining traceability of transformations, validation decisions, missing-value handling, and source-data limitations.

Raw source files are never modified.

---

## 2. General Cleaning Principles

The cleaning pipeline follows these principles:

1. Raw source data is preserved and is never overwritten.

2. Exact duplicate records are removed only when the complete rows are identical.

3. Duplicate identifiers with conflicting records are not blindly deleted.

4. Equivalent categorical representations are standardized to canonical values using explicit mappings.

5. Invalid values are not guessed, fabricated, or silently forced into valid ranges.

6. Source values requiring validation or transformation are handled deterministically by the cleaning scripts.

7. Missing values are handled according to the semantic meaning and data type of the field.

8. The final analytical datasets intentionally contain zero missing cells.

9. Textual, categorical, unavailable, or invalid values that cannot be reliably recovered are represented as `Unknown`.

10. Semantically non-applicable values are represented using an explicit semantic value where appropriate, such as `Not Terminated`.

11. Selected numeric fields use documented median imputation when a valid analytical numeric value is required and the original value is missing or invalid.

12. Timestamps are parsed using supported representations. Values that cannot be reliably parsed are represented as `Unknown` in the final analytical dataset.

13. Network fields such as IP addresses, ports, and byte counts are validated against their expected domains.

14. Invalid network values are not fabricated. Where a final analytical value is required, the value is represented as `Unknown` or imputed using the documented numeric method.

15. Hash values are validated rather than repaired, padded, or generated.

16. Join keys are normalized consistently before integration checks.

17. Source-data coverage gaps are reported rather than being artificially resolved.

18. Validation is performed independently from the cleaning logic using dedicated validation scripts.

---

# 3. Identity Master Cleaning

## 3.1 Duplicate handling

The raw Identity dataset contained 3,090 rows.

There were 90 exact duplicate rows.

One copy of each exact duplicate record was retained.

Result:

- Raw rows: 3,090
- Exact duplicate rows removed: 90
- Cleaned rows: 3,000

The cleaned `user_id` is unique.

## 3.2 User ID standardization

User IDs appeared in multiple textual representations, including:

- `EMP12345`
- `emp12345`
- `EMP-12345`
- `EMP 12345`
- `EMP_12345`

Equivalent representations were normalized to a consistent canonical `EMP` identifier format.

Invalid user IDs after cleaning: 0.

## 3.3 Department standardization

Department values contained multiple representations of the same department.

Examples included:

- IT / Information Technology / information tech
- HR / Human Resource / Human Resources / People Team
- Marketing / Mktg
- Operations / Ops / Operations Dept
- Finance / Fin
- Procurement / Purchase / Purch
- Sales / Sales Team
- Customer Support / Customer Care
- R&D / RD / Research and Development

Equivalent representations were mapped to canonical department names using explicit mappings.

Unmapped department values after cleaning: 0.

## 3.4 Status standardization

Identity status values appeared in multiple forms.

Equivalent values were mapped to canonical states:

- Active
- Disabled
- Terminated
- On Leave
- Blocked

The `Blocked` state was retained as a distinct state rather than being incorrectly classified as inactive or terminated.

Unmapped status values after cleaning: 0.

## 3.5 Hostname standardization

Identity hostnames were normalized to a consistent canonical representation.

Normalization includes:

- trimming surrounding whitespace
- converting to uppercase
- converting underscores to hyphens
- removing the `.corp.local` suffix where applicable

The normalized hostname is used consistently for hostname-based join validation.

## 3.6 Date handling

`hire_date` and `termination_date` were parsed from supported date representations.

Invalid or unparseable dates were not fabricated.

For the final analytical dataset:

- `Unknown` represents a date that could not be reliably recovered.
- `Not Terminated` represents a semantically non-applicable termination date for a non-terminated employee.

The pipeline also checks for:

- terminated-like status with missing termination date
- active-like status with a termination date
- hire date after termination date

Source anomalies are retained and flagged rather than silently corrected.

Final Identity dataset:

- Rows: 3,000
- Final missing cells: 0
- Final duplicate rows: 0

---

# 4. IAM Cleaning

## 4.1 Duplicate handling

The raw IAM dataset contained 20,500 rows.

There were 500 exact duplicate rows.

One copy of each exact duplicate record was retained.

Result:

- Raw rows: 20,500
- Exact duplicate rows removed: 500
- Cleaned rows: 20,000

## 4.2 User ID standardization

IAM user IDs were normalized using the same canonical representation used by Identity.

This ensures consistent IAM → Identity joins.

Invalid user IDs after cleaning: 0.

## 4.3 Department standardization

IAM department values used multiple representations.

Equivalent values were mapped to the canonical department values used by the Identity master.

Unmapped department values after cleaning: 0.

## 4.4 Event type standardization

IAM event types contained multiple representations of authentication success and failure events.

Success variants were standardized to the canonical `login_success` category.

Failure variants were standardized to the canonical `login_failed` category.

Other operational events were retained as appropriate canonical event types.

Examples of source variants included:

- SSO success
- successful login
- authentication success
- login success
- login failed
- MFA failed
- authentication failed
- failed login

Unmapped event types after cleaning: 0.

## 4.5 MFA standardization

MFA values appeared as:

- True / False
- Y / N
- yes / no
- 1 / 0

These representations were converted to boolean analytical values.

Invalid MFA values after cleaning: 0.

## 4.6 Timestamp handling

IAM timestamps appeared in multiple textual formats.

Supported representations were parsed into a consistent timestamp representation.

Unparseable timestamps were not guessed.

For the final analytical dataset, timestamps that could not be reliably recovered are represented as `Unknown`.

Current cleaning result:

- Final unresolved/invalid timestamp cases represented as `Unknown`: 4,395

The original source values remain available in the raw dataset for traceability.

## 4.7 Source IP validation

IAM source IP values were validated as IP addresses.

Invalid IP values were not repaired or fabricated.

Invalid or unavailable analytical IP values are represented as `Unknown` in the final zero-missing dataset.

## 4.8 Risk score handling

IAM risk scores appeared in multiple forms, including:

- numeric values
- categorical labels such as High, Medium, and Low
- representations such as `78/100`
- numeric values outside the allowed 0–100 range

The pipeline distinguishes between:

- valid numeric risk scores within 0–100
- missing values
- categorical risk labels
- invalid numeric values outside the allowed range

Categorical labels are not converted into arbitrary numeric scores.

For the final analytical dataset, missing or invalid numeric risk scores are handled using the documented median-imputation strategy.

Final IAM risk-score median used: 50.0.

Final IAM dataset:

- Rows: 20,000
- Final missing cells: 0
- Final duplicate rows: 0

---

# 5. Endpoint Cleaning

## 5.1 Duplicate handling

The raw Endpoint dataset contained 8,240 rows.

There were 240 exact duplicate rows.

One copy of each exact duplicate record was retained.

Result:

- Raw rows: 8,240
- Exact duplicate rows removed: 240
- Cleaned rows: 8,000

## 5.2 Severity standardization

Endpoint severity contained multiple textual representations.

These were mapped to canonical severity levels:

- Critical
- High
- Medium
- Low

A corresponding numeric severity rank is retained for analytical use:

- Critical = 4
- High = 3
- Medium = 2
- Low = 1

Unmapped severity values after cleaning: 0.

## 5.3 Status standardization

Endpoint status values contained multiple representations.

Equivalent lifecycle states were standardized to canonical values including:

- New
- Open
- In Progress
- Investigating
- Resolved
- Closed
- False Positive
- Unassigned

`Active` was treated as `Open` for analytical lifecycle consistency.

Unmapped status values after cleaning: 0.

## 5.4 Device criticality

Device criticality values were standardized to:

- Critical
- High
- Medium
- Low

Unavailable criticality values are represented as `Unknown` in the final analytical dataset.

Unmapped values after cleaning: 0.

## 5.5 Hostname standardization

Endpoint hostnames were normalized using the same canonical hostname representation used by Identity:

- trim whitespace
- uppercase
- replace `_` with `-`
- remove `.corp.local`

This improves consistency for hostname-based joins.

## 5.6 Timestamp handling

Detected and resolved timestamps were parsed into consistent timestamp values.

Invalid or unavailable timestamps were not fabricated.

For the final analytical dataset, unrecoverable timestamp values are represented as `Unknown`.

The final validation found:

- Invalid detected timestamps: 0
- Invalid resolved timestamps: 0

## 5.7 Chronology anomalies

The relationship between detected and resolved timestamps was checked.

Where a resolved timestamp appeared earlier than the detected timestamp, the record was not automatically swapped or modified.

This avoids introducing fabricated chronology.

Result:

- Chronology anomalies flagged: 263

These records remain available for downstream review.

Chronology anomalies are treated as source-data quality flags rather than automatic cleaning failures.

## 5.8 SHA-256 validation

SHA-256 values were validated against the expected 64-character hexadecimal representation.

Malformed or incomplete hashes were not padded, regenerated, or otherwise fabricated.

For the final analytical dataset, unavailable or invalid hashes are represented as `Unknown`.

Final validation result:

- Valid SHA-256 values: 5,763
- Unknown SHA-256 values: 2,237
- Invalid SHA-256 values remaining in final data: 0

Final Endpoint dataset:

- Rows: 8,000
- Final missing cells: 0
- Final duplicate rows: 0

---

# 6. Firewall Cleaning

## 6.1 Duplicate handling

The raw Firewall dataset contained 30,600 rows.

There were 600 exact duplicate rows.

One copy of each exact duplicate record was retained.

Result:

- Raw rows: 30,600
- Exact duplicate rows removed: 600
- Cleaned rows: 30,000

## 6.2 Timestamp handling

Firewall timestamps were parsed and validated.

Unparseable timestamps were not fabricated.

For the final analytical dataset, unrecoverable timestamps are represented as `Unknown`.

Final cleaning result:

- Unknown timestamps: 6,503
- Invalid timestamps remaining in final data: 0

## 6.3 IP address validation

Source and destination IP addresses were validated using standard IPv4 validation.

Invalid values were not corrected through guessing.

Invalid or unavailable analytical IP values are represented as `Unknown`.

Final validation result:

- Invalid source IP values remaining: 0
- Invalid destination IP values remaining: 0

## 6.4 Port validation

Source and destination ports were validated against the valid TCP/UDP port range:

`1–65535`

Port `0` is treated as invalid.

Negative and otherwise out-of-range values are also invalid.

Invalid or unavailable numeric port values are handled using the documented median-imputation strategy.

Final medians used:

- Source port median: 443
- Destination port median: 443

Final validation result:

- Invalid source ports remaining: 0
- Invalid destination ports remaining: 0

## 6.5 Byte validation

`bytes_sent` and `bytes_received` were converted into analytical numeric values where valid.

Values expressed using supported textual units were parsed where possible.

Negative byte counts are treated as invalid.

Invalid or unavailable numeric byte values are handled using the documented median-imputation strategy.

Final medians used:

- Bytes sent median: 24,819,643.22
- Bytes received median: 24,526,192.64

Final validation result:

- Invalid bytes sent remaining: 0
- Invalid bytes received remaining: 0
- Negative byte values remaining: 0

## 6.6 Protocol standardization

Protocol values appeared in multiple representations, including textual names and protocol numbers.

Equivalent values were standardized to canonical protocol categories:

- TCP
- UDP
- ICMP

Unavailable protocol values are represented as `Unknown`.

## 6.7 Action standardization

Firewall action values appeared in multiple forms, including:

- permit / pass / allow
- deny / drop / block

Equivalent representations were standardized into canonical analytical action categories:

- Allow
- Deny
- Drop
- Block

Unavailable action values are represented as `Unknown`.

## 6.8 Threat flag standardization

Threat flag values appeared as:

- True / False
- Y / N
- yes / no
- 1 / 0

These were standardized into boolean analytical values.

Final invalid threat flag values: 0.

Final Firewall dataset:

- Rows: 30,000
- Final missing cells: 0
- Final duplicate rows: 0

---

# 7. Final Missing-Value Strategy

The final analytical datasets intentionally contain zero missing cells.

This does not mean that missing source information was invented.

Instead, missingness is represented using deterministic semantic rules.

## 7.1 Text and categorical fields

Unavailable text or categorical values are represented as:

`Unknown`

Examples include:

- hostname
- username
- department
- device ID
- location
- session ID
- file path
- process name
- rule name
- geo location
- hash values

## 7.2 Termination date

Termination date uses semantic handling:

- Non-terminated employee with no applicable termination date → `Not Terminated`
- Terminated employee with missing/unrecoverable termination date → `Unknown`

## 7.3 Numeric fields

Selected numeric fields are imputed using the median of valid analytical values when a numeric value is required for downstream analysis.

This is used for fields such as:

- IAM risk score
- Endpoint resolution duration
- Firewall ports
- Firewall byte counts

The imputation values are deterministic and documented in the generated cleaning reports.

## 7.4 Invalid source values

Invalid source values are not transformed into arbitrary valid values.

The final analytical representation is selected according to the field:

- semantic `Unknown`
- documented median imputation
- canonical categorical representation

The original raw source remains unchanged.

---

# 8. Join-Key Standardization and Integration Validation

The datasets are intended to be integrated using common identity and telemetry keys.

The expected relationships include:

- IAM ↔ Identity using `user_id`
- Endpoint ↔ Identity using `user_id`
- Endpoint ↔ Identity using `hostname`
- Firewall ↔ Identity using `hostname`
- IAM ↔ Firewall using `session_id`, with timestamp approximation where applicable

The join-key strategy follows the supplied dataset specification.

## 8.1 User ID joins

After canonical user ID normalization:

- IAM → Identity: 20,000 / 20,000 matched
- Endpoint → Identity: 8,000 / 8,000 matched

Both user ID joins pass validation.

## 8.2 Hostname joins

Canonical hostname normalization was applied consistently across datasets.

Current validation:

### Endpoint → Identity hostname

- 6,404 matched
- 1,115 unmatched
- 7,519 usable hostnames
- Coverage: 85.17%

### Firewall → Identity hostname

- 24,287 matched
- 3,956 unmatched
- 28,243 usable hostnames
- Coverage: 85.99%

Unmatched telemetry hostnames are retained.

No synthetic Identity records are created to force hostname joins to pass.

These unmatched records are treated as source-data coverage limitations and should be accounted for during downstream analytics.

## 8.3 IAM → Firewall session coverage

Session ID coverage is reported as an informational integration metric.

Current result:

- 261 matched
- 11,263 unmatched
- 11,524 usable session IDs
- Coverage: 2.26%

This is not treated as a cleaning failure because complete cross-dataset session coverage is not guaranteed by the supplied telemetry.

---

# 9. Validation Philosophy

The validation layer checks the final analytical datasets independently from the cleaning logic.

Current dataset-level validation results:

| Dataset | Validation Result |
|---|---|
| Identity | All checks PASS |
| IAM | All checks PASS |
| Endpoint | All checks PASS |
| Firewall | All checks PASS |

The final cleaned datasets also satisfy:

- expected analytical schemas
- zero final missing cells
- zero empty-string cells
- zero exact duplicate rows
- unique primary dataset identifiers
- valid standardized categorical values
- valid network ranges
- valid analytical timestamps
- documented source anomalies retained for review

The cleaned integration validation reports known hostname and session coverage limitations separately as informational results.

A limitation is not hidden merely to obtain a PASS result.

---

# 10. Final Cleaned Dataset Sizes

| Dataset | Raw Rows | Duplicates Removed | Cleaned Rows |
|---|---:|---:|---:|
| Identity | 3,090 | 90 | 3,000 |
| IAM | 20,500 | 500 | 20,000 |
| Endpoint | 8,240 | 240 | 8,000 |
| Firewall | 30,600 | 600 | 30,000 |

Total cleaned telemetry/event records:

`58,000`

Identity master records:

`3,000`

All four final datasets contain zero missing cells.

---

# 11. Traceability

The cleaning pipeline keeps raw source files separate from cleaned outputs.

Cleaning scripts are stored under:

- `src/cleaning/`

Validation scripts are stored under:

- `src/validation/`

Generated cleaned datasets are stored under:

- `data/cleaned/`

Generated profiling, cleaning, and validation evidence is stored under:

- `reports/`

The cleaning process is script-based and deterministic.

The raw source files are not manually edited.

The final analytical datasets are generated from the raw inputs by the cleaning scripts.

---

# 12. Known Data Quality Limitations

The following source-data limitations are intentionally preserved and documented:

1. Some IAM timestamps cannot be reliably parsed.

2. Some source IP values are invalid or unavailable.

3. Some Firewall ports and byte values are invalid or unavailable in the source data.

4. Some Endpoint SHA-256 values are malformed, incomplete, or unavailable.

5. Some Endpoint timestamp pairs contain chronology anomalies.

6. Some Identity records contain termination-date anomalies.

7. Some Endpoint hostnames have no corresponding Identity master record.

8. Some Firewall hostnames have no corresponding Identity master record.

9. IAM-to-Firewall session coverage is incomplete.

These limitations are not hidden or artificially corrected.

---

# 13. Final Decision

The cleaned datasets are considered suitable for the next analytics stage because:

- duplicate records have been handled consistently
- categorical representations have been standardized
- invalid values have been validated rather than fabricated
- missing values have been handled using documented semantic and numeric rules
- final analytical datasets contain zero missing cells
- timestamps have been parsed and invalid/unrecoverable values represented deterministically
- network fields have been validated against their expected domains
- join keys have been normalized
- dataset-specific validation checks pass
- join coverage limitations have been explicitly measured
- source-data anomalies have been retained rather than silently corrected
- raw source data remains separate from cleaned analytical outputs
- cleaning and validation are implemented through reproducible scripts