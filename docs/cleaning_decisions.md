# Data Cleaning Decisions

## 1. Purpose

This document records the cleaning decisions applied to the four Track 2 cybersecurity datasets.

The objective is to convert the supplied raw telemetry and identity data into consistent, validated, analytics-ready datasets while preserving the original raw values wherever a transformation or validation decision was required.

Raw files are not modified.

---

## 2. General Cleaning Principles

The cleaning pipeline follows these principles:

1. Raw source data is preserved and is never overwritten.
2. Exact duplicate records are removed only when the complete rows are identical.
3. Duplicate identifiers with conflicting records are not blindly deleted.
4. Equivalent categorical representations are standardized to canonical values.
5. Invalid values are not fabricated or guessed.
6. Where possible, the original raw value is retained alongside the cleaned value.
7. Missing values are handled according to the meaning of the field rather than by blindly dropping rows.
8. Timestamps are parsed using supported formats; values that cannot be reliably parsed are treated as invalid.
9. Network fields such as IP addresses, ports and byte counts are validated against their expected domains.
10. Hash values are validated rather than repaired or generated.
11. Join keys are normalized consistently before integration checks.
12. Source-data coverage gaps are reported rather than being artificially resolved.

---

# 3. Identity Master Cleaning

## 3.1 Duplicate handling

The raw Identity dataset contained 3,090 rows.

There were 90 groups of exact duplicate records, representing 180 rows.

One copy of each exact duplicate record was retained.

Result:

- Raw rows: 3,090
- Exact duplicate rows removed: 90
- Cleaned rows: 3,000

The cleaned `user_id` is unique.

## 3.2 User ID standardization

User IDs appeared in multiple textual representations, including variations such as:

- `EMP12345`
- `emp12345`
- `EMP-12345`
- `EMP 12345`

These representations were normalized to a consistent canonical format.

Invalid user IDs were not found after cleaning.

## 3.3 Department standardization

Department values contained multiple representations of the same department.

Examples included variations of:

- IT / Information Technology
- HR / Human Resource / Human Resources
- Marketing / Mktg
- Operations / Ops
- Finance / Fin
- Procurement / Purchase
- Sales / Sales Team
- Customer Support / Customer Care

Equivalent representations were mapped to canonical department names using explicit mappings.

Unmapped department values after cleaning: 0.

## 3.4 Status standardization

Identity status values appeared in multiple forms.

Equivalent values were mapped to canonical states including:

- Active
- Disabled
- Terminated
- On Leave
- Blocked

The `Blocked` state was retained as a distinct state rather than being incorrectly classified as inactive or terminated.

Unmapped status values after cleaning: 0.

## 3.5 Hostname standardization

Identity hostnames were normalized to a consistent representation.

Normalization includes:

- trimming surrounding whitespace
- converting to uppercase
- converting underscores to hyphens
- removing the `.corp.local` suffix where applicable

The cleaned hostname is retained as a canonical join key.

## 3.6 Date handling

`hire_date` and `termination_date` were parsed from supported date representations.

Invalid dates were not fabricated.

Semantic missingness was preserved.

For example, a missing termination date can be valid for an employee who has not been terminated.

The pipeline additionally checks for:

- terminated-like status with missing termination date
- active status with a termination date
- hire date after termination date

There were 66 terminated-like records with a missing termination date. These records were retained and flagged rather than assigning an artificial termination date.

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

IAM user IDs were normalized using the same canonical user ID representation used for Identity.

This ensures consistent IAM → Identity joins.

Invalid user IDs after cleaning: 0.

## 4.3 Department standardization

IAM department values used multiple representations.

Equivalent values were mapped to the same canonical department values used in the Identity master.

Unmapped department values after cleaning: 0.

## 4.4 Event type standardization

IAM event types contained multiple representations of authentication success and failure events.

Equivalent variants were mapped to canonical event categories.

Examples of success variants included representations such as:

- SSO success
- successful login
- authentication success
- login success

Failure variants included representations such as:

- login failed
- MFA failed
- authentication failed
- failed login

Other operational events were retained as separate canonical event types where appropriate.

Unmapped event types after cleaning: 0.

## 4.5 MFA standardization

MFA values appeared as:

- True / False
- Y / N
- yes / no
- 1 / 0

These representations were converted to boolean values.

Invalid MFA values after cleaning: 0.

## 4.6 Timestamp handling

IAM timestamps appeared in multiple textual formats.

Supported representations were parsed into a consistent timestamp representation.

Unparseable timestamps were not guessed or replaced.

Result:

- Invalid IAM timestamps: 4,395

The original values are preserved for traceability.

## 4.7 Source IP validation

IAM source IP values were validated as IP addresses.

Invalid IP values were not repaired or fabricated.

The raw value is retained while the cleaned analytical value is treated as invalid/missing where appropriate.

Result:

- Invalid source IP values: 10,117

## 4.8 Risk score handling

IAM risk scores appeared in multiple forms, including numeric values, categorical labels and representations such as `78/100`.

The pipeline distinguishes between:

- valid numeric risk scores within 0–100
- missing values
- categorical risk labels
- invalid numeric values outside the allowed range

Invalid numeric values are not forced into the valid range.

Result:

- Invalid risk range: 2,607
- Categorical risk values: 1,353
- Missing risk values: 1,037

No unsupported numeric score was invented from a categorical label.

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

A corresponding severity ranking is also available for analytical use.

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

Missing criticality values were preserved as missing.

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

Invalid timestamps were not fabricated.

Both timestamps are retained with validation information.

No invalid detected timestamps or invalid resolved timestamps remained after cleaning.

## 5.7 Chronology anomalies

The relationship between detected and resolved timestamps was checked.

Where a resolved timestamp appeared earlier than the detected timestamp, the record was not automatically swapped or modified.

This is because timestamp anomalies may result from source-data precision or formatting differences, and automatically changing the event chronology would introduce fabricated information.

Result:

- Chronology anomalies flagged: 263

These records are retained for downstream review.

## 5.8 SHA-256 validation

SHA-256 values were validated against the expected 64-character hexadecimal representation.

Malformed or incomplete hashes were not padded, regenerated or otherwise fabricated.

Invalid hashes are treated as invalid analytical values while the original value remains available for traceability.

Result:

- Invalid SHA-256 values after cleaning: 799

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

Result:

- Invalid timestamps after cleaning: 2,986

Missing timestamps are distinguished from invalid timestamps.

## 6.3 IP address validation

Source and destination IP addresses were validated using standard IP address parsing.

Invalid values are not corrected through guessing.

The original values are retained while invalid analytical values are treated as missing/invalid.

Results:

- Invalid source IP values: 13,471
- Invalid destination IP values: 12,756

## 6.4 Port validation

Source and destination ports were validated against the valid TCP/UDP port range:

`1–65535`

Port `0` is therefore treated as invalid rather than as a valid network port.

Negative and otherwise out-of-range values are also invalid.

Results:

- Invalid source ports: 3,608
- Invalid destination ports: 3,556

## 6.5 Byte validation

`bytes_sent` and `bytes_received` were converted into analytical numeric values where valid.

Values expressed using supported textual units were parsed where possible.

Negative byte counts are treated as invalid.

Invalid values are not replaced with arbitrary numbers.

Results:

- Invalid bytes sent: 5,101
- Invalid bytes received: 5,086

## 6.6 Protocol standardization

Protocol values appeared in multiple representations, including textual names and protocol numbers.

Equivalent values were standardized to canonical protocol categories such as:

- TCP
- UDP
- ICMP

## 6.7 Action standardization

Firewall action values appeared in multiple forms, including:

- permit / pass / allow
- deny / drop / block

Equivalent representations were standardized into canonical analytical action categories.

## 6.8 Threat flag standardization

Threat flag values appeared as:

- True / False
- Y / N
- yes / no
- 1 / 0

These were standardized into boolean analytical values.

---

# 7. Join-Key Standardization and Integration Validation

The datasets are intended to be integrated using common identity and telemetry keys.

The expected relationships include:

- IAM ↔ Identity using `user_id`
- Endpoint ↔ Identity using `user_id`
- Endpoint ↔ Identity using `hostname`
- Firewall ↔ Identity using `hostname`
- IAM ↔ Firewall using `session_id`, with timestamp approximation where applicable

The join-key strategy follows the supplied dataset specification.

## 7.1 User ID joins

After canonical user ID normalization:

- IAM → Identity: 20,000 / 20,000 matched
- Endpoint → Identity: 8,000 / 8,000 matched

These joins pass validation.

## 7.2 Hostname joins

Canonical hostname normalization improved hostname matching substantially.

However, some telemetry records contain hostnames that do not exist in the Identity master.

Current validation:

- Endpoint → Identity hostname:
  - 7,037 matched
  - 482 unmatched
- Firewall → Identity hostname:
  - 26,665 matched
  - 1,578 unmatched

These unmatched records are retained.

No synthetic Identity records are created to force the joins to pass.

The unmatched records are treated as a source-data coverage limitation and are documented for downstream analytics.

## 7.3 IAM → Firewall session coverage

Session ID coverage is reported as an informational integration metric.

Current result:

- 261 matched
- 11,263 unmatched
- 11,524 usable session IDs

This check is not treated as a cleaning failure because the supplied telemetry does not guarantee complete cross-dataset session coverage.

---

# 8. Validation Philosophy

The validation layer checks the cleaned datasets independently from the cleaning logic.

The current dataset-level validation results are:

| Dataset | Validation |
|---|---|
| Identity | 15/15 PASS |
| IAM | 12/12 PASS |
| Endpoint | 12/12 PASS |
| Firewall | 16/16 PASS |

The cleaned integration validation additionally reports the known hostname coverage gaps described above.

A validation failure or limitation is not hidden merely to obtain a PASS result.

---

# 9. Final Cleaned Dataset Sizes

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

---

# 10. Traceability

The cleaning pipeline keeps raw source files separate from cleaned outputs.

Cleaning and validation scripts are stored under:

- `src/cleaning/`
- `src/validation/`

Generated cleaned datasets are stored under:

- `data/cleaned/`

Generated profiling, cleaning and validation evidence is stored under:

- `reports/`

The pipeline is designed so that cleaning decisions can be reproduced from the raw inputs without manually editing the source datasets.

---

# 11. Known Data Quality Limitations

The following limitations are intentionally preserved rather than hidden:

1. Some IAM timestamps cannot be parsed reliably.
2. Some IAM and Firewall IP addresses are invalid.
3. Some Firewall ports and byte values are invalid.
4. Some Endpoint SHA-256 values are malformed or incomplete.
5. Some Endpoint timestamp pairs have chronology anomalies.
6. Some terminated-like Identity records have no termination date.
7. Some Endpoint and Firewall hostnames have no corresponding Identity master record.
8. IAM-to-Firewall session coverage is incomplete.

These limitations are reported so downstream analytics can distinguish genuine data quality issues from cleaned values.

---

## 12. Final Decision

The cleaned datasets are considered suitable for the next analytics stage because:

- duplicate records have been handled consistently
- categorical representations have been standardized
- invalid values have been validated rather than fabricated
- timestamps have been parsed and flagged where necessary
- join keys have been normalized
- cleaned datasets have passed their dataset-specific validation checks
- known integration limitations have been explicitly retained and documented
- raw source values remain available for traceability