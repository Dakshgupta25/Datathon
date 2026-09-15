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

**Columns:** 23 (Phase B Data Trust Enriched)

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
| `risk_score` | Numeric | Median-imputed risk score | Legacy 0-missing analytical score for backward compatibility |
| `risk_score_raw` | Text | Original unmodified risk score string | Preserves verbatim raw string from telemetry (e.g. `"78"`, `"High"`, `"Missing"`) |
| `risk_score_numeric` | Numeric / Text | Valid numeric risk score | Strict float `[0.0 - 100.0]`; `Unknown` if missing, out of range, or categorical |
| `risk_score_valid` | Boolean | Validity flag for numeric risk score | `True` if raw score was valid numeric or `x/100`; `False` otherwise |
| `risk_label` | Categorical | Categorical risk rating | Preserved strings (`High`, `Medium`, `Low`, `Invalid`, `Missing`) |
| `risk_quality_flag` | Categorical | Quality lineage flag | `VALID_NUMERIC`, `PARSED_PERCENTAGE`, `CATEGORICAL_PRESERVED`, `OUT_OF_RANGE`, `MISSING` |
| `geo_location` | Text | Geographic location associated with event | Unavailable values represented as `Unknown` |
| `data_quality_status` | Categorical | Overall record quality classification | State: `VALID`, `REPAIRED`, `IMPUTED`, `UNKNOWN` |
| `is_imputed` | Boolean | Imputation indicator | `True` if median risk score was imputed; `False` otherwise |
| `is_repaired` | Boolean | Transformation repair indicator | `True` if user_id or hostname formatting was normalized; `False` otherwise |

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
src/transformations/
    ↓
data/processed/ (Canonical, Features, Baselines, Deviations, Clustering Prep)
    ↓
src/validation/
    ↓
reports/
    ↓
docs/
```

---

# 11. Behavioral Baselines & Deviation Tables (Phase E)

The Phase E transformation layer generates 5 analytical outputs under `data/processed/`:

### 11.1 User Behavior Baselines (`user_behavior_baselines.csv`)
- **Rows:** 3,000
- **Columns:** 47
- **Key Fields:** `user_id`, `eligibility_status`, `baseline_confidence`, `observation_count`, `valid_timestamp_count`, `unknown_timestamp_count`, `distinct_active_days`, `historical_span_days`, `timestamp_quality_score`, `baseline_method`, `baseline_window`, department peer medians/MADs for failed logins, auth failure rates, off-hours activity, and endpoint alerts.

### 11.2 Host Behavior Baselines (`host_behavior_baselines.csv`)
- **Rows:** 8,413
- **Columns:** 32
- **Key Fields:** `hostname`, `is_managed`, `eligibility_status`, `baseline_confidence`, `observation_count`, `valid_timestamp_count`, `unknown_timestamp_count`, `distinct_active_days`, `historical_span_days`, `timestamp_quality_score`, `baseline_method`, population medians/MADs for firewall denies, deny ratios, byte transfers, and endpoint alerts.

### 11.3 User Behavior Deviations (`user_behavior_deviations.csv`)
- **Rows:** 3,000
- **Columns:** 35
- **Key Fields:** `user_id`, `eligibility_status`, `baseline_confidence`, self-deviations (`failed_login_abs_dev`, `rel_dev`, `zscore`), dimension anomaly scores (`authentication_deviation`, `network_deviation`, `endpoint_deviation`, `off_hours_deviation`), neutral dimension statuses (`NORMAL`, `UNUSUAL`, `ELEVATED`, `OUTLIER`), `behavior_deviation_score`, and `multi_signal_deviation_count` (0 to 4).

### 11.4 Host Behavior Deviations (`host_behavior_deviations.csv`)
- **Rows:** 8,413
- **Columns:** 26
- **Key Fields:** `hostname`, `eligibility_status`, `baseline_confidence`, self-deviations (`firewall_deny_zscore`, `ratio_zscore`, `bytes_zscore`), dimension anomaly scores (`network_deviation`, `endpoint_deviation`, `volume_deviation`), neutral dimension statuses, `behavior_deviation_score`, and `multi_signal_deviation_count` (0 to 3).

### 11.5 Clustering Prepared Feature Matrix (`clustering_prepared_features.csv`)
- **Rows:** 11,413 (3,000 Users + 8,413 Hosts)
- **Columns:** 14
- **Key Fields:** `entity_id`, `entity_type` (`USER` / `HOST`), scaled Robust Z-scores across all behavioral dimensions, `behavior_deviation_score`, `multi_signal_deviation_count`. Clean numeric matrix with zero NaNs, ready for downstream clustering.

---

# 12. Risk Engine Outputs (Phase F)

The Phase F transformation layer generates 6 analytical outputs under `data/processed/`:

### 12.1 User Risk Scores (`user_risk_scores.csv`)
- **Rows:** 3,000
- **Columns:** 15
- **Key Fields:** `user_id`, `username`, `department`, `traceone_risk_score`, `risk_level` (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`), `risk_confidence_score` ($0.0 - 1.0$), `risk_confidence_level`, `independent_signal_count`, `multi_signal_multiplier`, `source_iam_risk_indicator` (Legacy IAM score strictly preserved), `source_iam_risk_quality`, `counter_evidence`, `primary_hypothesis`.

### 12.2 Host Risk Scores (`host_risk_scores.csv`)
- **Rows:** 8,413
- **Columns:** 15
- **Key Fields:** `hostname`, `traceone_risk_score`, `risk_level`, `risk_confidence_score`, `risk_confidence_level`, `independent_signal_count`, `multi_signal_multiplier`, `counter_evidence`, `primary_hypothesis`.

### 12.3 Combined TraceONE Risk Scores (`traceone_risk_scores.csv`)
- **Rows:** 11,413 (3,000 Users + 8,413 Hosts)
- **Columns:** 15
- **Key Fields:** Complete unified entity risk register for all canonical users and hosts.

### 12.4 Risk Contributor Breakdown (`risk_contributors.csv`)
- **Rows:** 11,413
- **Columns:** 8
- **Key Fields:** `entity_id`, `entity_type`, `traceone_risk_score`, `auth_contribution`, `network_contribution`, `endpoint_contribution`, `operational_contribution`, `multi_signal_boost`.

### 12.5 Security Hypotheses (`security_hypotheses.csv`)
- **Rows:** 11,413
- **Columns:** 8
- **Key Fields:** `entity_id`, `entity_type`, `hypothesis`, `traceone_risk_score`, `confidence_score`, `supporting_signals`, `counter_evidence`, `limitations`.

### 12.6 Normalized Evidence Table (`normalized_evidence_table.csv`)
- **Rows:** 15,000
- **Columns:** 11
- **Key Fields:** `entity_id`, `entity_type`, `event_id`, `source_dataset`, `source_record_id`, `event_category`, `event_timestamp`, `severity`, `action`, `data_quality_status`, `resolution_confidence`. Serves as the primary evidence lookup index for SOC triage and explainable reasoning.

---

# 13. Temporal Security Engine Outputs (Phase G)

The Phase G transformation layer generates 5 analytical outputs under `data/processed/`:

### 13.1 Temporal Sequences (`temporal_sequences.csv`)
- **Rows:** 2,412
- **Columns:** 14
- **Key Fields:** `sequence_id`, `entity_id`, `entity_type`, `sequence_type`, `start_time`, `end_time`, `duration_seconds`, `event_count`, `event_ids`, `source_datasets`, `temporal_window_minutes`, `sequence_confidence` ($0.0 - 1.0$), `sequence_strength` ($0.0 - 100.0$), `counter_evidence`.

### 13.2 Temporal Evidence Linkage (`temporal_evidence.csv`)
- **Rows:** 25,863
- **Columns:** 9
- **Key Fields:** `sequence_id`, `entity_id`, `entity_type`, `event_id`, `source_dataset`, `source_record_id`, `event_timestamp`, `event_category`, `role_in_sequence`. Provides complete row-level lineage linking sequences to canonical events.

### 13.3 Sequence Pattern Frequency (`sequence_pattern_frequency.csv`)
- **Rows:** 5
- **Columns:** 5
- **Key Fields:** `sequence_type`, `pattern_occurrence_count`, `unique_entities`, `avg_event_count`, `avg_duration_sec`, `rarity_category` (`COMMON`, `UNUSUAL`, `RARE`).

### 13.4 User Temporal Signals (`user_temporal_signals.csv`)
- **Rows:** 3,000
- **Columns:** 6
- **Key Fields:** `user_id`, `username`, `temporal_sequence_count`, `strongest_sequence_strength`, `temporal_evidence_count`, `temporal_confidence`, `temporal_signal_present`. Standalone temporal signals for users (Phase F risk scores preserved).

### 13.5 Host Temporal Signals (`host_temporal_signals.csv`)
- **Rows:** 8,413
- **Columns:** 6
- **Key Fields:** `hostname`, `temporal_sequence_count`, `strongest_sequence_strength`, `temporal_evidence_count`, `temporal_confidence`, `temporal_signal_present`. Standalone temporal signals for hosts.

---

# 14. Investigation Graph Outputs (Phase H)

The Phase H transformation layer generates 3 graph analytical outputs under `data/processed/`:

### 14.1 Graph Nodes Table (`graph_nodes.csv`)
- **Rows:** 138,931
- **Columns:** 5
- **Key Fields:** `node_id`, `node_type` (`USER`, `HOST`, `SESSION`, `IP`, `EVENT`, `DEPARTMENT`, `TEMPORAL_SEQUENCE`, `RISK_ASSESSMENT`), `label`, `key_attributes`, `source_reference`.

### 14.2 Graph Edges Table (`graph_edges.csv`)
- **Rows:** 79,224
- **Columns:** 8
- **Key Fields:** `edge_id`, `source_node`, `target_node`, `relationship_type` (`BELONGS_TO`, `ASSOCIATED_WITH_HOST`, `AUTHENTICATED_VIA`, `CONNECTED_FROM_IP`, `COMMUNICATED_WITH_IP`, `HAS_RISK_ASSESSMENT`, `SUPPORTED_BY_EVIDENCE`, `INVOLVED_IN_SEQUENCE`, `SEQUENCE_INCLUDES_EVENT`), `confidence` (`EXACT`, `PROBABLE`, `UNMATCHED`), `source_dataset`, `source_record_id`, `evidence_type`.

### 14.3 Investigation Scenarios (`investigation_scenarios.json`)
- **Format:** JSON structure containing 5 deterministic, evidence-backed SOC investigation scenarios derived directly from processed telemetry and risk assessments.

---

# 15. Advanced Security Insights Outputs (Phase I)

The Phase I transformation layer generates 7 analytical outputs under `data/processed/`:

### 15.1 User Behavior Clusters (`user_behavior_clusters.csv`)
- **Rows:** 3,000
- **Columns:** 10
- **Key Fields:** `user_id`, `username`, `department`, `cluster_id`, `cluster_label` (`NORMAL_BUSINESS_ACTIVITY`, `IRREGULAR_AUTHENTICATION_BEHAVIOR`, `HIGH_ENDPOINT_ALERT_PROFILE`, `SECURITY_SENSITIVE_OUTLIERS`), `distance_to_centroid`, `silhouette_width`, `behavior_deviation_score`, `traceone_risk_score`, `risk_level`.

### 15.2 Cluster Profiles (`cluster_profiles.csv`)
- **Rows:** 4
- **Columns:** 13
- **Key Fields:** `cluster_id`, `cluster_label`, `population_count`, `population_percent`, mean robust Z-scores for features, `avg_risk_score`, `high_risk_count`, `dominant_features`.

### 15.3 Behavioral Drift (`behavioral_drift.csv`)
- **Rows:** 3,000
- **Columns:** 9
- **Key Fields:** `user_id`, `username`, `assigned_cluster`, `cluster_label`, `drift_distance`, `drift_score`, `drift_confidence`, `drift_category` (`STABLE`, `MODERATE_DRIFT`, `HIGH_DRIFT`), `cluster_changed`.

### 15.4 Multi-Dimensional Outliers (`multi_dimension_outliers.csv`)
- **Rows:** 11,413 (3,000 Users + 8,413 Hosts)
- **Columns:** 11
- **Key Fields:** `entity_id`, `entity_type`, `outlier_dimension_count`, `active_dimensions`, `auth_zscore`, `network_zscore`, `endpoint_zscore`, `off_hours_zscore`, `multi_dimension_outlier_score`, `outlier_confidence`, `is_multi_dimensional_outlier`.

### 15.5 Peer-Group Outliers (`peer_group_outliers.csv`)
- **Rows:** 3,000
- **Columns:** 8
- **Key Fields:** `user_id`, `username`, `department`, `global_behavior_score`, `dept_peer_behavior_score`, `peer_deviation_delta`, `global_vs_peer_behavior` (`NORMAL_GLOBALLY_NORMAL_PEER`, `NORMAL_GLOBALLY_ANOMALOUS_PEER`, `ANOMALOUS_GLOBALLY_NORMAL_PEER`, `ANOMALOUS_GLOBALLY_ANOMALOUS_PEER`), `peer_outlier_flag`.

### 15.6 Temporal Bursts (`temporal_bursts.csv`)
- **Rows:** 3 (High-density sliding-window event spikes)
- **Columns:** 11
- **Key Fields:** `burst_id`, `entity_id`, `entity_type`, `burst_start`, `burst_end`, `burst_duration_sec`, `event_count`, `event_density_per_min`, `source_diversity_count`, `burst_category`, `severity_level`.

### 15.7 Advanced Insight Summary (`advanced_insight_summary.json`)
- **Format:** Machine-readable JSON summary containing cluster metrics, outlier counts, forecasting decision metadata, and 5 ranked top security discoveries with empirical evidence and security significance.

---

# 16. AI Investigator & Safety Data Models (Phase M)

The Phase M Agentic Graph AI layer uses structured, deterministic schemas for reasoning, evidence packaging, and explainability:

### 16.1 AI Evidence Package (`EvidencePackage`)
- **Format:** In-memory structured dataclass/JSON passed to `qwen3:8b` for response synthesis.
- **Key Fields:** `query`, `intent`, `resolved_entity_id`, `resolved_entity_type`, `tools_called`, `retrieved_evidence` (dict of deterministic tool outputs), `confidence_assessment`, `limitations`, `counter_evidence`, `provenance_sources`.

### 16.2 "Why Flagged" Explanations (`why_flagged_explanations.json`)
- **Rows:** All entities with TraceONE Risk $\ge 50.0$.
- **Key Fields:** `entity_id`, `entity_type`, `overall_risk`, `risk_level`, `confidence`, `confidence_score`, `top_contributors`, `multi_signal_corroboration`, `counter_evidence`, `primary_hypothesis`.

### 16.3 AI Intent Dictionary & Visualization Registry (`ai_investigator_intents.json`)
- **Key Fields:** 15 canonical intent mappings, 14 tool bindings, entity extraction regex rules, and 11 visualization component selectors (`RISK_GAUGE`, `TIMELINE_CHART`, `BEHAVIOR_SPIDER`, `PEER_SCATTER`, `GRAPH_NETWORK`, `CLUSTER_3D`, `DATA_TRUST_KPI`, `provenance_tree`, `BURST_TIMELINE`, `COUNTER_EVIDENCE_CARD`, `EVIDENCE_TABLE`).



