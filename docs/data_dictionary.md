# Data Dictionary

## Purpose

This document describes the final analytical schemas produced by the Track 2 cybersecurity cleaning pipeline.

It documents the actual columns present in the cleaned datasets under:

`data/cleaned/`

The final cleaned datasets are designed for downstream analytics and contain zero missing cells.

Raw source files are preserved separately under:

`data/raw/`

Cleaning decisions, validation results, and transformation evidence are documented in:

- `docs/cleaning_decisions.md`
- `reports/cleaning_log.csv`
- `reports/data_quality_report.md`
- dataset-specific cleaning summaries
- `reports/cleaned_join_validation_summary.csv`

---

# 1. Identity Master

**File:** `data/cleaned/identity_cleaned.csv`

**Rows:** 3,000

**Columns:** 12

**Purpose:** Employee identity and asset master used as the reference dataset for downstream joins.

| Column | Type / Role | Meaning | Cleaning / Validation |
|---|---|---|---|
| `user_id` | Identifier | Employee/user identifier | Canonicalized and validated; unique in final Identity master |
| `username` | Identifier/Text | Employee username | Unavailable values represented as `Unknown` |
| `department` | Categorical | Employee department | Standardized using explicit mappings |
| `status` | Categorical | Employee/account lifecycle status | Standardized to `Active`, `Disabled`, `Terminated`, `On Leave`, or `Blocked` |
| `hire_date` | Date / Text | Employee hire date | Supported date formats parsed; unrecoverable values represented as `Unknown` |
| `termination_date` | Date / Text | Employee termination date | Non-terminated records use `Not Terminated`; unrecoverable terminated dates use `Unknown` |
| `manager_username` | Identifier/Text | Employee manager username | Unavailable values represented as `Unknown` |
| `device_id` | Identifier/Text | Device associated with employee | Unavailable values represented as `Unknown` |
| `location` | Text | Employee location | Unavailable values represented as `Unknown` |
| `hostname` | Identifier | Employee/device hostname | Canonicalized for reliable hostname joins |
| `full_name` | Text | Employee full name | Unavailable values represented as `Unknown` |
| `role` | Text/Categorical | Employee job role | Unavailable values represented as `Unknown` |

### Identity canonicalization

User IDs are normalized to remove formatting differences such as:

- spaces
- hyphens
- underscores
- case differences

Hostname normalization includes:

- trimming whitespace
- uppercase conversion
- replacing `_` with `-`
- removing `.corp.local`

### Identity validation

Final validation:

- 3,000 cleaned rows
- 0 duplicate user IDs
- 0 duplicate rows
- 0 invalid user IDs
- 0 unmapped departments
- 0 unmapped statuses
- 0 invalid hostnames
- 0 final missing cells

Source-data anomalies are still documented, including:

- 66 terminated-like records with missing termination dates
- 208 active-like records with source termination dates
- 6 hire-after-termination anomalies

---

# 2. IAM Authentication and Access Events

**File:** `data/cleaned/iam_cleaned.csv`

**Rows:** 20,000

**Columns:** 15

**Purpose:** Identity and access management telemetry used for authentication, MFA, session, risk, and access analysis.

| Column | Type / Role | Meaning | Cleaning / Validation |
|---|---|---|---|
| `event_id` | Identifier | Unique IAM event identifier | Exact duplicates removed; final IDs unique |
| `timestamp` | Date / Text | IAM event timestamp | Supported representations parsed; unrecoverable values represented as `Unknown` |
| `user_id` | Identifier | User associated with IAM event | Canonicalized for Identity joins |
| `username` | Identifier/Text | Username associated with event | Unavailable values represented as `Unknown` |
| `department` | Categorical | Department associated with event | Standardized using explicit mappings |
| `event_type` | Categorical | IAM event/action type | Equivalent authentication/access variants standardized |
| `auth_method` | Categorical | Authentication method used | Source representation preserved where available |
| `source_ip` | IP address/Text | Source IP associated with event | Validated; unavailable/invalid analytical values represented as `Unknown` |
| `hostname` | Identifier/Text | Hostname associated with event | Source representation used for telemetry analysis |
| `device_id` | Identifier/Text | Device associated with event | Unavailable values represented as `Unknown` |
| `session_id` | Identifier/Text | Authentication/session identifier | Used for cross-telemetry session analysis; unavailable values represented as `Unknown` |
| `mfa_passed` | Boolean | Whether MFA was passed | `True/False`, `Y/N`, `yes/no`, and `1/0` standardized to boolean |
| `failure_reason` | Text/Categorical | Reason associated with authentication failure | `Not Applicable` for login-success/other events; `Unknown` for unresolved login-failure reasons |
| `risk_score` | Numeric | Numeric risk score | Validated to 0–100; missing/invalid numeric values completed using median 50.0 |
| `geo_location` | Text | Geographic location associated with event | Unavailable values represented as `Unknown` |

### IAM event-type standardization

Equivalent authentication representations are mapped into canonical analytical categories.

Examples include success representations such as:

- `SSO_SUCCESS`
- `success_login`
- `AUTH_SUCCESS`
- `LOGIN_SUCCESS`
- `Successful Login`
- `Login Success`
- `LOGON_SUCCESS`

These are standardized into the canonical success category.

Failure representations such as:

- `LOGIN_FAILED`
- `MFA_FAILED`
- `LOGON_FAILURE`
- `AUTH_FAILED`
- `FAILED_LOGIN`
- `Login Failed`
- `invalid_credentials`
- `failed logon`

are standardized into the canonical login-failure category.

Other operational events remain represented as their appropriate analytical event categories.

### IAM risk score

Valid numeric risk scores must fall within:

`0–100`

Categorical risk representations such as `Low`, `Medium`, and `High` are not artificially converted into numeric scores.

Missing or invalid numeric risk values use the median of valid numeric risk observations:

**50.0**

### IAM validation

Final validation:

- 20,000 cleaned rows
- 0 duplicate event IDs
- 0 invalid user IDs
- 0 unmapped departments
- 0 unmapped event types
- 0 invalid MFA values
- 0 invalid final risk scores
- 0 final missing cells

---

# 3. Endpoint Security Alerts

**File:** `data/cleaned/endpoint_cleaned.csv`

**Rows:** 8,000

**Columns:** 17

**Purpose:** Endpoint security alerts used for severity, lifecycle, affected-device, file/process, hash, and resolution analysis.

| Column | Type / Role | Meaning | Cleaning / Validation |
|---|---|---|---|
| `alert_id` | Identifier | Unique endpoint alert identifier | Exact duplicates removed; final IDs unique |
| `detected_timestamp` | Date / Text | Time alert was detected | Supported timestamp representations parsed; unrecoverable values represented as `Unknown` |
| `resolved_timestamp` | Date / Text | Time alert was resolved | Supported timestamp representations parsed; unrecoverable values represented as `Unknown` |
| `hostname` | Identifier/Text | Affected endpoint hostname | Canonicalized for hostname joins |
| `user_id` | Identifier | User associated with endpoint alert | Canonicalized for Identity joins |
| `endpoint_product` | Categorical | Endpoint security product/source | Source category retained |
| `alert_name` | Text | Name/type of security alert | Source value retained |
| `severity` | Categorical | Security alert severity | Standardized to `Critical`, `High`, `Medium`, or `Low` |
| `status` | Categorical | Alert lifecycle status | Standardized to canonical lifecycle states |
| `description` | Text | Alert description | Unavailable values represented as `Unknown` |
| `file_path` | Text | File path associated with alert | Unavailable values represented as `Unknown` |
| `process_name` | Text | Process associated with alert | Unavailable values represented as `Unknown` |
| `sha256` | Hash/Text | SHA-256 indicator associated with alert | Validated using 64-character hexadecimal rule; unavailable/malformed values represented as `Unknown` |
| `assigned_to` | Identifier/Text | Person/team assigned to alert | Unavailable values represented as `Unknown` |
| `device_criticality` | Categorical | Criticality of affected device | Standardized to canonical criticality values; unavailable values represented as `Unknown` |
| `severity_rank` | Numeric | Numeric analytical severity ranking | `Critical=4`, `High=3`, `Medium=2`, `Low=1` |
| `resolution_duration_hours` | Numeric | Time between detection and resolution | Derived from valid timestamps; missing values completed using median valid duration |

### Endpoint severity

Canonical severity values:

| Severity | Rank |
|---|---:|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |

### Endpoint status

Known lifecycle representations are standardized into canonical alert states, including:

- `New`
- `Open`
- `In Progress`
- `Investigating`
- `Resolved`
- `Closed`
- `False Positive`
- `Unassigned`

`Active` source representations are treated as `Open` for lifecycle analysis.

### SHA-256 validation

A valid SHA-256 analytical value must contain:

- exactly 64 characters
- hexadecimal characters only

Final Endpoint SHA-256 state:

- 5,763 valid hashes
- 2,237 values represented as `Unknown`
- 0 invalid final hashes

Malformed hashes are not padded, regenerated, or fabricated.

### Endpoint chronology

Detected and resolved timestamps are not automatically swapped.

Chronology anomalies are flagged for analysis.

Final result:

**263 chronology anomalies**

### Endpoint validation

Final validation:

- 8,000 cleaned rows
- 0 duplicate alert IDs
- 0 invalid user IDs
- 0 unmapped severity values
- 0 unmapped status values
- 0 unmapped device criticality values
- 0 invalid final timestamps
- 263 chronology anomalies flagged
- 0 invalid final SHA-256 values
- 0 final missing cells

---

# 4. Firewall Network Telemetry

**File:** `data/cleaned/firewall_cleaned.csv`

**Rows:** 30,000

**Columns:** 15

**Purpose:** Network firewall telemetry used for traffic, actions, threats, sessions, IP addresses, ports, protocols, and byte-volume analysis.

| Column | Type / Role | Meaning | Cleaning / Validation |
|---|---|---|---|
| `log_id` | Identifier | Unique firewall log identifier | Exact duplicates removed; final IDs unique |
| `timestamp` | Date / Text | Firewall event timestamp | Supported representations parsed; unrecoverable values represented as `Unknown` |
| `hostname` | Identifier/Text | Hostname associated with network event | Canonicalized for Identity integration |
| `src_ip` | IP address/Text | Source IP address | Validated; unavailable/invalid analytical values represented as `Unknown` |
| `dst_ip` | IP address/Text | Destination IP address | Validated; unavailable/invalid analytical values represented as `Unknown` |
| `src_port` | Integer | Source network port | Valid range: 1–65,535; unavailable numeric values use documented median |
| `dst_port` | Integer | Destination network port | Valid range: 1–65,535; unavailable numeric values use documented median |
| `protocol` | Categorical | Network protocol | Equivalent representations standardized |
| `action` | Categorical | Firewall action | Equivalent representations standardized |
| `bytes_sent` | Numeric | Bytes sent | Parsed into numeric bytes; unavailable values use documented median |
| `bytes_received` | Numeric | Bytes received | Parsed into numeric bytes; unavailable values use documented median |
| `session_id` | Identifier/Text | Network session identifier | Used for session-level integration |
| `threat_flag` | Boolean | Whether traffic was flagged as a threat | Standardized to boolean |
| `rule_name` | Text/Categorical | Firewall rule that processed traffic | Unavailable values represented as `Unknown` |
| `geo_country` | Text/Categorical | Geographic country associated with traffic | Unavailable values represented as `Unknown` |

### Firewall port validation

Valid network ports are:

`1–65,535`

The following are invalid:

- port `0`
- negative ports
- values above `65,535`
- non-numeric port values

Final analytical port fields contain zero invalid values.

Median values used for unavailable numeric ports:

- Source port: **443**
- Destination port: **443**

### Firewall byte validation

Byte values are converted to numeric values where supported.

Negative byte values are invalid.

Final median values used:

- Bytes sent: **24,819,643.22**
- Bytes received: **24,526,192.64**

### Firewall validation

Final validation:

- 30,000 cleaned rows
- 0 duplicate log IDs
- 0 invalid final source IP values
- 0 invalid final destination IP values
- 0 invalid final source ports
- 0 invalid final destination ports
- 0 invalid final byte values
- 0 final missing cells

---

# 5. Missing-Value Representation

The final analytical datasets intentionally contain zero missing cells.

Missing values are handled according to field semantics.

## `Unknown`

`Unknown` means that a usable source value was unavailable, unrecoverable, or could not safely be represented as an analytical value.

It is used primarily for:

- unavailable text
- unavailable identifiers
- unrecoverable timestamps
- unavailable IP values
- malformed/unavailable SHA-256 values

`Unknown` does not mean that the source actually contained the literal word `Unknown`.

## `Not Terminated`

`Not Terminated` is used for Identity termination dates where termination does not apply based on the employee lifecycle status.

It represents a semantic state rather than a fabricated date.

---

# 6. Numeric Imputation

Median imputation is used only for selected numeric analytical fields where a complete analytical column is required.

Current documented median values include:

| Dataset | Field | Median |
|---|---|---:|
| IAM | `risk_score` | 50.0 |
| Endpoint | `resolution_duration_hours` | 62.99 |
| Firewall | `src_port` | 443 |
| Firewall | `dst_port` | 443 |
| Firewall | `bytes_sent` | 24,819,643.22 |
| Firewall | `bytes_received` | 24,526,192.64 |

The medians are calculated from valid source-derived numeric observations.

Categorical values are not converted into numeric values unless a documented analytical mapping exists.

---

# 7. Cross-Dataset Join Keys

The following keys are used for integration.

| Relationship | Join Key | Purpose |
|---|---|---|
| IAM → Identity | `user_id` | Link IAM events to employee identity |
| Endpoint → Identity | `user_id` | Link endpoint alerts to employee identity |
| Endpoint → Identity | `hostname` | Link endpoint telemetry to employee/device master |
| Firewall → Identity | `hostname` | Link network activity to employee/device master |
| IAM → Firewall | `session_id` | Identify possible cross-telemetry sessions |

## User ID normalization

User IDs are canonicalized consistently across datasets by removing formatting differences such as:

- spaces
- hyphens
- underscores
- case differences

## Hostname normalization

Hostnames are normalized by:

1. trimming whitespace
2. converting to uppercase
3. replacing `_` with `-`
4. removing `.corp.local`

No synthetic Identity records are created to force unmatched telemetry records into the master dataset.

---

# 8. Final Join Validation

## IAM → Identity

**PASS**

- 20,000 matched
- 0 unmatched
- 100% coverage

## Endpoint → Identity using user ID

**PASS**

- 8,000 matched
- 0 unmatched
- 100% coverage

## Endpoint → Identity using hostname

**INFO**

- 6,404 matched
- 1,115 unmatched
- 7,519 usable hostnames
- 85.17% coverage

## Firewall → Identity using hostname

**INFO**

- 24,287 matched
- 3,956 unmatched
- 28,243 usable hostnames
- 85.99% coverage

## IAM → Firewall using session ID

**INFO**

- 261 matched
- 11,263 unmatched
- 11,524 usable session IDs
- 2.26% coverage

Unmatched records are retained as source-data coverage limitations.

Synthetic relationships are not created.

---

# 9. Final Schema Summary

| Dataset | Rows | Columns | Missing Cells | Duplicate Rows |
|---|---:|---:|---:|---:|
| Identity | 3,000 | 12 | 0 | 0 |
| IAM | 20,000 | 15 | 0 | 0 |
| Endpoint | 8,000 | 17 | 0 | 0 |
| Firewall | 30,000 | 15 | 0 | 0 |

Total cleaned telemetry/event records:

**58,000**

Cleaned Identity master records:

**3,000**

---

# 10. Traceability

The final cleaned datasets contain only the final analytical columns required for downstream analysis.

Traceability is maintained through the repository's supporting artifacts:

```text
data/raw/
    ↓
src/cleaning/
    ↓
data/cleaned/
    ↓
src/validation/
    ↓
reports/
    ↓
docs/