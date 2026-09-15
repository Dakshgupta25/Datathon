# TRACEONE
### From Messy Telemetry to Explainable Threat Intelligence

> **Core Philosophy**: *"No claim without evidence."*

TRACEONE transforms messy, heterogeneous firewall, IAM, endpoint, and identity telemetry into an evidence-first security investigation platform. By combining deterministic data engineering, robust behavioral analytics, temporal correlation, and an evidence-backed graph model with a read-only local Agentic AI (`qwen3:8b`), TRACEONE provides SOC analysts with 100% auditable, explainable threat intelligence.

---

## 1. System Architecture & Information Pipeline

```
+---------------------------------------------------------------------------------------------------+
|                                      TRACEONE SYSTEM PIPELINE                                     |
+---------------------------------------------------------------------------------------------------+
  RAW TELEMETRY DATA (62,430 Records across Identity, IAM, Endpoint, Firewall)
       │
       ▼
  DATA RESCUE & CLEANING (1,430 Exact Duplicates Removed, 0 Missing Cells, 77 Cleaning Rules)
       │
       ▼
  CANONICAL SECURITY MODEL (58,000 Schema-Standardized Canonical Security Events)
       │
       ▼
  OBSERVABLE SECURITY FEATURES (3,000 Users, 8,413 Hosts, 36,433 Sessions Feature Matrices)
       │
       ▼
  BEHAVIORAL BASELINES & DEVIATIONS (Robust MAD & Non-Parametric Z-Scores against Departmental Peers)
       │
       ▼
  EXPLAINABLE RISK ENGINE (0-100 TraceONE Risk Score, 4 Behavioral Dimensions, Multi-Signal Multiplier)
       │
       ▼
  TEMPORAL CORRELATION ENGINE (Sliding 60-Minute Windows, 2,412 Chronological Event Sequences)
       │
       ▼
  INVESTIGATION GRAPH (138,931 Nodes, 79,224 Provenance Edges across 8 Entity Types)
       │
       ▼
  ADVANCED SECURITY INSIGHTS (K-Means Clustering, CLUSTER_3 76.92% Risk Concentration, Peer Outliers)
       │
       ▼
  SOC USER INTERFACES (Command Center, Investigation Center, Data Trust & Lineage Center)
       │
       ▼
  AGENTIC GRAPH AI / AI INVESTIGATOR (Ollama qwen3:8b, 15 Intents, 14 Deterministic Read-Only Tools)
+---------------------------------------------------------------------------------------------------+
```

### Deterministic Backend vs AI Orchestration vs Visualization
- **Deterministic Analytics (Source of Truth)**: TRACEONE's Python/DuckDB data pipelines perform all data cleaning, baseline math, Z-score calculations, risk scoring, temporal windowing, and graph traversals. The backend is the sole source of truth.
- **AI Reasoning Layer (Orchestrator)**: The local LLM (`qwen3:8b` via Ollama) routes user queries to intent plans, invokes deterministic tools, and synthesizes natural language explanations strictly from retrieved evidence packages.
- **Visualization Component Selector**: The UI engine dynamically renders interactive widgets (risk gauges, temporal timelines, network graphs, 3D cluster profiles) matched to the query intent.
- **Provenance Tracker**: Every metric, edge, and explanation maintains explicit file-and-line lineage back to the underlying CSV records in `data/cleaned/`.

---

## 2. Key System Metrics & Authoritative Data Volume

All metrics displayed across TRACEONE are 100% grounded and traceable to repository outputs:

| Dimension / Metric | Authoritative Value | Data Source / Artifact Location |
| :--- | :--- | :--- |
| **Raw Telemetry Input** | **62,430 records** | `data/raw/*` (Identity: 3.09k, IAM: 20.5k, EP: 8.24k, FW: 30.6k) |
| **Cleaned Telemetry Volume** | **61,000 records** | `data/cleaned/*.csv` (1,430 exact duplicate rows removed) |
| **Canonical Security Events**| **58,000 events** | `data/processed/canonical_events.csv` |
| **Monitored Entities** | **3,000 Users / 8,413 Hosts** | `data/cleaned/identity_cleaned.csv` |
| **Valid Timestamp Coverage** | **82.9%** (48,097 valid) | Preserved UTC timestamps; 9,903 unknown preserved (17.1%) |
| **High / Critical Risk Users**| **78 accounts** (66 Critical, 12 High)| `data/processed/user_risk_scores.csv` (Risk $\ge 60.0$) |
| **Session Linkage Overlap** | **2.26%** (261 / 11,524 sessions)| `reports/cleaned_join_validation_summary.csv` |
| **Investigation Graph Topology**| **138,931 Nodes / 79,224 Edges**| `data/processed/graph_nodes.csv`, `graph_edges.csv` |
| **Temporal Event Sequences** | **2,412 sequences** | `data/processed/temporal_sequences.csv` |
| **Cluster Risk Concentration**| **76.92% in CLUSTER_3** | `data/processed/cluster_profiles.csv` (60 / 78 High/Crit accounts) |
| **Multi-Dimensional Outliers**| **446 entities** (201 Users, 245 Hosts)| `data/processed/multi_dimension_outliers.csv` |
| **Hidden Peer Outliers** | **79 accounts** | `data/processed/peer_group_outliers.csv` |

---

## 3. Core Engine Specifications

### 3.1 Data Trust & Lineage Engineering (Phase B & Phase L)
Data quality is treated as a core security feature:
- **Duplicate Rescue**: Identified and removed 1,430 exact duplicate rows across telemetry datasets.
- **Sentinel & Missing Values**: 0 missing cells (NaNs) in clean datasets; unparseable fields use explicit `Unknown` tags or sentinel values.
- **Timestamp Integrity**: 48,097 timestamps parsed to standard UTC ISO-8601. 9,903 unknown timestamps are preserved without synthetic fabrication.
- **Linkage Transparency**: 100% User ID match across IAM and Endpoint; 85.6% Hostname match; session overlap constraint (2.26%) explicitly disclosed.

### 3.2 Explainable Risk Engine (Phase F)
> [!IMPORTANT]
> **Risk is an investigative prioritization signal, not proof of compromise.**

- **Behavioral Dimensions**: Evaluates 4 distinct signal families: Authentication ($S_{\text{auth}}$), Network ($S_{\text{net}}$), Endpoint ($S_{\text{ep}}$), and Operational Off-Hours ($S_{\text{ops}}$), max 25 points each.
- **Robust-Z Methodology**: Uses median and Median Absolute Deviation ($\text{MAD}$) scaling to resist extreme outlier distortion:
  $$\text{Robust } Z = \frac{X - \text{Median}(X)}{1.4826 \times \text{MAD}(X)}$$
- **Multi-Signal Multiplier**: Multiplies base risk score by $1.00\times \rightarrow 1.75\times$ when anomalies occur across multiple independent signal families.
- **Risk vs Confidence**: Decouples behavioral risk score ($0.0-100.0$) from evidence confidence ($0.0-1.0$).
- **Threshold Tiers**: `CRITICAL` ($\ge 80.0$), `HIGH` ($\ge 60.0$), `MEDIUM` ($\ge 40.0$), `LOW` ($< 40.0$).
- **Legacy IAM Risk**: Source IAM risk indicators are kept completely separate from the TraceONE Risk Score.

### 3.3 Temporal Intelligence Engine (Phase G)
> [!IMPORTANT]
> **A temporal sequence is evidence of correlated activity, not automatically an attack.**

- **Sliding Time Windows**: Reconstructs cross-source sequences across 60-minute sliding observation windows per entity.
- **Correlated Transition Patterns**:
  - `AUTH_TO_ENDPOINT_ANOMALY`: Off-hours login followed by endpoint process execution.
  - `FIREWALL_DENY_TO_ENDPOINT_EXECUTION`: High firewall deny bursts followed by local executable execution.
  - `HOST_ANCHORED_CHAINS`: Multi-stage temporal progressions anchored to internal hostnames.
- **Tie-Breaking & Exclusions**: Deterministic sorting by `(valid_timestamp ASC, canonical_event_id ASC)`; events with unknown timestamps are excluded from sequence ordering.

### 3.4 Evidence-Backed Investigation Graph (Phase H)
- **8 Node Taxonomy**: `USER`, `HOST`, `SESSION`, `IP`, `EVENT`, `DEPARTMENT`, `TEMPORAL_SEQUENCE`, `RISK_ASSESSMENT`.
- **Edge Provenance & Confidence Tiers**:
  - `EXACT` ($1.00$): Unique primary key linkage (e.g. `USER` $\rightarrow$ `ASSIGNED_TO` $\rightarrow$ `HOST`).
  - `PROBABLE` ($0.70-0.85$): Standardized entity resolution matches.
  - `UNMATCHED` ($0.00$): Unlinked relationships.
- **`NO_VERIFIED_RELATIONSHIP`**: Discloses missing or unlinked relationships rather than visually guessing connections.

### 3.5 Advanced Security Insights (Phase I)
- **User Behavioral Clustering**: Deterministic K-Means ($K=4$, Silhouette = 0.6412). `CLUSTER_3` (`SECURITY_SENSITIVE_OUTLIERS`) represents 2.0% of users (60 accounts) but captures **76.92% of all High/Critical risk accounts** in the organization.
- **Multi-Dimensional Outliers**: **446 entities** (201 Users + 245 Hosts) exhibit concurrent anomalies across 2+ independent dimensions.
- **Hidden Peer-Group Outliers**: **79 accounts** classified as `NORMAL_GLOBALLY_ANOMALOUS_PEER` (appear normal globally, but deviate sharply within their department).
- **Temporal Bursts**: **3 high-density sliding-window event spikes**.

---

## 4. Agentic Graph AI / AI Investigator (Phase M & Phase N)

TRACEONE features a local, evidence-first AI Investigator powered by `qwen3:8b` via Ollama:

```
 User Question: "Why is EMP10194 high risk?"
       │
       ▼
 Ollama / Qwen3:8B (Intent Routing & Query Plan Formulation)
       │
       ▼
 14 Read-Only Deterministic TraceONE Tools (Python / DuckDB Analytical Engine)
       │
       ▼
 Structured EvidencePackage (Risk Scores, Contributor Weights, Temporal Sequences, Graph Edges)
       │
       ▼
 Prompt Injection Shield & Evidence-Grounding Guardrail (Sanitizes input, blocks ungrounded claims)
       │
       ▼
 Synthesized Grounded Response + Visualization Component Selector (Risk Gauge, Timeline, Graph)
```

### Core AI Safety Principles
1. **"The LLM is not the source of truth."** All facts come from TraceONE's deterministic tools.
2. **"Zero arbitrary code execution."** No `eval()`, `exec()`, shell execution, or arbitrary SQL query execution paths exist.
3. **"Read-only tool sandbox."** The AI layer cannot mutate backend datasets, change risk formulas, or delete records.

---

## 5. Walkthrough Demo: "Why is EMP10194 high risk?"

The central demonstration workflow illustrates the observable, evidence-backed investigation trace:

1. **User Query**: Analyst inputs *"Why is EMP10194 high risk?"* in the AI Investigator.
2. **Entity Resolution**: `EntityResolver` matches `EMP10194` $\rightarrow$ `RESOLVED` (Entity Type: `USER`, Department: `Finance`).
3. **Risk Profile Retrieval**: `get_user_risk_profile("EMP10194")` returns TraceONE Risk Score `82.5` (`CRITICAL`), Confidence `0.92` (`HIGH`).
4. **Behavioral Contributor Breakdown**:
   - Authentication Contribution: `25.0` / 25.0
   - Network Contribution: `21.88` / 25.0
   - Endpoint Contribution: `18.75` / 25.0
   - Operational Off-Hours: `0.0` / 25.0
   - Multi-Signal Multiplier: `1.50x` (3 active elevated signal families).
5. **Temporal Sequence Correlation**: Sequence `SEQ_AUTH_EP_0042` links an off-hours authentication event to a subsequent endpoint process execution on host `LPT-10194`.
6. **Graph Topology Traversal**: Graph query exposes shared network connection to `IP-10.225.61.0` (shared proxy node).
7. **Counter-Evidence Evaluation**: Flags `ZERO_MFA_FAILURES_OBSERVED` (No MFA bypass detected in telemetry).
8. **Lineage Provenance**: Cites exact records in `data/cleaned/iam_cleaned.csv` (Row 402) and `data/cleaned/endpoint_cleaned.csv` (Row 189).
9. **Grounded Synthesis & UI Rendering**: `qwen3:8b` generates a concise report paired with dynamic UI widgets (`RISK_GAUGE`, `TIMELINE_CHART`, `GRAPH_NETWORK`).

---

## 6. Key Competition Differentiators

1. **Evidence-First AI Architecture**: The LLM synthesizes evidence; it never invents security findings.
2. **100% Privacy & Local Execution**: Uses local Ollama instance with open `qwen3:8b` model.
3. **Deterministic Backend Sandbox**: 14 read-only tools with zero dynamic code compilation or shell access.
4. **Graph Topology & Lineage**: 138,931 nodes and 79,224 edges with explicit provenance tracking.
5. **Temporal Correlation Engine**: Reconstructs chronological event chains across sliding time windows.
6. **Data Trust & Auditability**: Exposes pipeline DAG health, rescue logs, and validation scoreboards.
7. **Explainable Risk Math**: Bounded 0-100 score driven by robust MAD statistics and multi-signal multipliers.
8. **Decoupled Risk vs Confidence**: Distinguishes behavioral abnormality from data completeness.
9. **Prompt Injection Shield**: Input sanitizer and instruction barriers protect against adversarial manipulation.
10. **100% Reproducibility**: Complete pipeline, test suite (116 tests), and dashboard launch in a single command.

---

## 7. Repository Structure

```text
track2_cybersecurity_dataset_files/
├── data/
│   ├── raw/                      # Preserved raw source telemetry CSVs
│   ├── cleaned/                  # Rescued, cleaned datasets (0 NaNs, 61,000 rows)
│   └── processed/                # Canonical events, features, baselines, risk scores, graph, insights
├── src/
│   ├── cleaning/                 # Phase B source cleaning & rescue scripts
│   ├── transformations/          # Canonical data model, feature extractors, baseline calculators
│   ├── risk/                     # Phase F TraceONE Risk Engine scoring logic
│   ├── temporal/                 # Phase G sliding-window temporal correlation engine
│   ├── graph/                    # Phase H investigation graph builder & query engine
│   ├── insights/                 # Phase I K-Means clustering & multi-dimensional outlier routines
│   ├── ai/                       # Phase M Agentic AI (intents, tools, resolver, safety shield)
│   ├── dashboard/                # Data loaders, state managers, and component engines
│   └── validation/               # Validation test suites across all phases
├── scripts/
│   └── run_pipeline.py           # Master end-to-end automated pipeline executor
├── tests/                        # 116 automated pytest unit & adversarial test cases
├── docs/                         # Technical architecture specifications & reproducibility guides
│   ├── architecture.md           # End-to-end system flow & core philosophy
│   ├── ai_investigator.md        # Ollama integration, tool dictionary, execution traces
│   ├── risk_engine.md            # Risk score range, robust Z-scores, multipliers, thresholds
│   ├── temporal_intelligence.md  # Time windows, sequence patterns, timestamp handling
│   ├── investigation_graph.md   # Node taxonomy, edge provenance, EXACT/PROBABLE tiers
│   ├── advanced_insights.md      # Clustering, concentration, peer outliers, temporal bursts
│   ├── security_model.md         # Read-only AI safety model, injection shield, sandbox rules
│   ├── reproducibility.md        # Step-by-step verified setup & execution instructions
│   ├── limitations.md            # Responsible threat interpretation & operational boundaries
│   ├── demo_script.md            # 3-5 minute presentation script for competition judges
│   ├── presentation.md           # 10-slide deck content with speaker notes & visual recommendations
│   └── demo_checklist.md         # 10 key screenshot capture points for live demo
├── reports/                      # Validation matrix, audit reports, cleaning logs
│   ├── validation_matrix.md      # Phase-by-phase verification matrix (116 / 116 PASS)
│   └── data_trust_center_design.md# Data trust technical design report
├── app.py                        # Streamlit multi-module SOC application entrypoint
└── requirements.txt              # Python package dependencies
```

---

## 8. Verified Quick Start Guide

### Step 1: Environment Setup
```bash
git clone https://github.com/Dakshgupta25/Datathon.git
cd track2_cybersecurity_dataset_files

python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### Step 2: Start Ollama & Pull `qwen3:8b`
```bash
# Verify Ollama is running locally
ollama list

# Pull the qwen3:8b model
ollama pull qwen3:8b
```

### Step 3: Run Master Pipeline Execution
Execute the full end-to-end data cleaning, canonical transformation, feature extraction, risk scoring, temporal correlation, graph construction, and advanced insights pipeline:
```bash
python scripts/run_pipeline.py
```

### Step 4: Run Automated Verification Suite (116 Tests)
```bash
python -m pytest tests/
```
*Expected Result*: **116 passed in ~90s (100% GREEN)**

### Step 5: Launch TRACEONE Streamlit Command Center
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501` to access:
1. **Command Center**: Executive SOC dashboard & risk landscape.
2. **Investigation Center**: Deep entity triage, contributor weights, & graph explorer.
3. **Data Trust & Lineage Center**: Quality dimensions, rescue logs, & provenance tree.
4. **AI Investigator**: Local natural language agentic investigation workspace.