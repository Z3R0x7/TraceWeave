# Attack Investigation Application — System Guide & Codebase Walkthrough

This document provides a comprehensive technical guide to the Attack Investigation Application. It is written for all audiences: **end-user analysts**, **engineering teammates**, **evaluators**, and **AI assistants** inspecting the codebase.

---

## 1. Executive Summary & Core Mission

This application implements **Functional Requirements 5, 6, and 7 (FR-5, FR-6, FR-7)** for attack investigation:
- **FR-5 (Investigation Interface & Evidence Navigation):** Incident exploration, interactive timeline with presentation ordering, entity-relationship topology graphs, raw evidence tracing, and data-quality limitation auditing.
- **FR-6 (Next-Target Look-Ahead):** Algorithmic reasoning across a dataset-wide access-history artifact (`access_history.parquet`) to identify reachable candidate targets without claiming speculative probabilities.
- **FR-7 (AI-Assisted Investigation Reports & Fallback):** LLM-powered narrative explanation via Groq or OpenAI with strict semantic support validation, prompt injection defense, and an offline deterministic fallback that produces self-contained Markdown and escaped HTML reports.

### The Core Design Principle: Clear Division of Responsibility
```
┌──────────────────────────────────────┐       ┌──────────────────────────────────────┐
│       Teammate's Engine (Disk)       │       │    Investigation Application (Ours)  │
├──────────────────────────────────────┤       ├──────────────────────────────────────┤
│ • Raw security log ingestion & parsing│──────>│ • Manifest streaming & validation     │
│ • Attack detection & event correlation│ Handoff│ • SQLite state & DuckDB analytics   │
│ • MITRE ATT&CK & kill-chain labeling │ via    │ • Timeline, graph & evidence browser │
│ • Parquet output generation          │ JSON/  │ • FR-6 access-history look-ahead    │
│ • Detection accuracy benchmarks      │ Parquet│ • Groq/OpenAI reports + safe fallback│
└──────────────────────────────────────┘       └──────────────────────────────────────┘
```
The application **does not parse raw logs, run detection heuristics, or alter MITRE labels**. It imports completed, verified engine artifacts, validates contract compliance, and provides high-performance investigative exploration.

---

## 2. High-Level Architecture & Tech Stack

```
                          ┌────────────────────────┐
                          │ Streamlit UI (Port 8501)│
                          │   (ui/app.py + Plotly)  │
                          └───────────┬────────────┘
                                      │ HTTP (Read-Only)
                                      ▼
                          ┌────────────────────────┐
                          │  FastAPI Backend (8000)│
                          │      (api/main.py)     │
                          └─────┬────────────┬─────┘
                                │            │
            ┌───────────────────┘            └────────────────────┐
            ▼                                                     ▼
┌─────────────────────────┐                               ┌─────────────────────────┐
│     Transactional       │                               │       Analytical        │
│    SQLite Database      │                               │   DuckDB (:memory:)     │
│    (data/app/app.sqlite)│                               │  Direct Parquet Queries │
├─────────────────────────┤                               ├─────────────────────────┤
│ • Imports lifecycle     │                               │ • Evidence lookups      │
│ • Run metadata          │                               │ • FR-6 access history   │
│ • Incident summaries    │                               │ • Query profiling       │
│ • Report cache          │                               │ • Bounded RAM (<512 MB) │
└─────────────────────────┘                               └─────────────────────────┘
```

### Technology Selection Rationale
| Component | Technology | Rationale |
|---|---|---|
| **Backend API** | FastAPI + Uvicorn | Async background tasks, strict OpenAPI schema validation, lightweight. |
| **User Interface** | Streamlit + Plotly | Fast data-centric analyst dashboard with interactive graphs and tables. |
| **Application State**| SQLite (`sqlite3`) | Single-writer transactional consistency for import jobs and cached reports. |
| **Evidence Analytics** | DuckDB (`read_parquet`)| Fast vectorized SQL queries on Parquet files without loading datasets into RAM. |
| **Data Contracts** | Pydantic v2 | Authoritative schema enforcement (`extra="forbid"`) and JSON Schema generation. |
| **AI Integration** | Groq & OpenAI APIs | Structured JSON explanation with 2-stage verification and offline fallback. |

---

## 3. Directory Structure & Key Files

```
.
├── api/
│   ├── config.py         # Application settings (roots, approved hosts, AI keys)
│   ├── contracts.py      # Pydantic contract definitions (Manifest, Incident, etc.)
│   ├── imports.py        # Import lifecycle, streaming, validation, index promotion
│   ├── investigation.py  # Analytical queries: ordered timeline, evidence, FR-6 reachability
│   ├── main.py           # FastAPI application, route handlers, background tasks
│   ├── reports.py        # AI explanation, sanitization, semantic verification, report formatting
│   ├── storage.py        # SQLite schema initialization and connection management
│   └── transfer.py       # Bounded file streaming, TLS pinning, SSRF protection
├── contracts/            # Machine-readable JSON Schemas exported for the engine team
├── docs/
│   ├── requirements.md   # Requirements traceability matrix
│   └── verification.md   # Verification log, benchmark results, test evidence
├── scripts/
│   ├── benchmark.py      # Performance profiling (import time, latency, memory, DuckDB scans)
│   ├── demo.py           # Synthetic engine-output generator for local development
│   └── export_contracts.py # Auto-generates contracts/*.schema.json from Pydantic
├── tests/                # 49 automated tests (contracts, transfer, reachability, UI, API)
├── ui/
│   └── app.py            # Streamlit multi-page investigation workstation
├── compose.yaml          # Docker Compose container orchestration
├── Dockerfile            # Container build definition
└── README.md             # Startup instructions and operational guidance
```

---

## 4. Deep-Dive: Module by Module

### 4.1. Contract Layer (`api/contracts.py`)
This file is the single source of truth for all engine-to-application handoffs.
- **`Manifest`**: Defines run metadata, source dataset size, incident count, and artifacts dictionary.
  - Requires checksums (`sha256`) on all files except the incident bundle directory.
  - Distinguishes application `status` (`completed`) from engine-level `engine_status` (`queued | running | completed | failed`) and `engine_phase` (`parsing | detecting | correlating | writing_results`).
- **`Incident`**: Bundles entities, timeline steps, relationships, MITRE techniques, kill-chain phases, engine review, and data quality impacts.
  - Validates that all entity IDs in timeline steps and relationships exist in `incident.entities`.
  - Enforces timezone-aware ISO 8601 timestamps.
  - Forbids duplicate IDs (`step_id`, `relationship_id`, `entity_id`).
- **`Step`**: Individual timeline event. Contains `display_order`, `ordering_basis`, `ordering_confidence`, `interpretation_status` (`observed | derived | hypothesized`), `maliciousness`, and optional `kill_chain_phase`.
- **`Quality`**: Dataset-wide metrics (`total_records_read`, `malformed_records`, `duplicate_records`, etc.).

### 4.2. Ingestion & Security Boundary (`api/transfer.py` & `api/imports.py`)
Engine output may be hosted locally or on remote cloud storage (S3/GCS presigned URLs).
- **Streaming Transfer (`Transfer.fetch`)**:
  - Reads data in 1 MB chunks and writes directly to disk staging (`never holds full files in RAM`).
  - Computes running SHA-256 digests and validates against declared sizes and checksums.
- **Security Boundaries**:
  - **Local Imports**: Confined to `IMPORT_ROOT` via `Transfer.inside()`; resolves paths and blocks symlink/directory traversal attacks.
  - **Remote Imports**: Only allows `https://` URLs from an explicit hostname allowlist (`APPROVED_REMOTE_HOSTS`). Blocks query-parameter logging to keep presigned credentials safe.
  - **SSRF & DNS Rebinding Protection**: `PinnedHTTPS` resolves IP addresses via `socket.getaddrinfo` and rejects non-public / internal IP ranges (e.g. `127.0.0.1`, RFC 1918 private subnets).
- **Atomic Staging & SQLite Indexing**:
  - Unpacks summaries from NDJSON line-by-line (`readline()` up to 8 MB) without parsing the entire file into memory.
  - Stages metadata in an isolated `stage/index.sqlite` database.
  - Verifies that all evidence IDs cited in the incident exist in `evidence.parquet`.
  - Atomically renames the staging folder into `data/app/runs/{run_id}/{import_id}` and attaches the index into the main database.

### 4.3. Analytical Engine & FR-6 Look-Ahead (`api/investigation.py`)
Analytical queries avoid loading full Parquet tables into memory by spinning up transient, read-only in-memory DuckDB sessions configured with a 512 MB memory limit:

#### 1. Evidence Query (`evidence()`)
Uses DuckDB's vectorized `read_parquet()` with SQL filter pushdown (`WHERE incident_id = ? AND evidence_id IN (...)`). It scans only relevant row groups and streams bounded paginated results.

#### 2. Timeline Path (`ordered_path()`)
Preserves identical timestamps and sequence ties. It sorts steps by `(observed_at is None, timestamp, display_order)` while surfacing `ordering_confidence` and `ordering_basis`, ensuring display ordering is never mistaken for causal proof.

#### 3. FR-6 Reachability Look-Ahead (`reachability()`)
Identifies candidate next targets using the dataset-wide `access_history.parquet`:
- **Entity Seeding**: Seeds the search only with accounts and hosts implicated in suspicious/malicious, non-hypothesized steps.
- **Allowed Relationships**: Accepts only verified administrative or network relations (`permission`, `admin_access`, `allowed_network`, `successful_remote_auth`). Pure traffic or shared subnets are rejected.
- **Temporal Validity**:
  - Explicit access (`permission`, `admin_access`) must have validity intervals covering the incident's `analysis_reference_time` (`valid_from <= ref <= valid_to`).
  - Historical remote authentication must have `observed_at < reference_time` to be labeled prior access.
  - IP-to-host mappings must be valid at the observed event time.
- **Ranking**: Ranked by evidence strength (`high` for valid explicit permission, `medium` for historical remote logons) and recency (30-day penalty), never by arbitrary compromise probabilities.
- **Exclusion**: Targets already present in the incident are excluded.
- **Empty Output**: If no evidence supports a candidate, returns: *"No evidence-supported next target can be determined from the supplied access history."*

### 4.4. AI-Assisted Explanations & Reporting (`api/reports.py`)
- **Sanitized Package**: Extracts up to 30 facts and evidence excerpts. Strips passwords, bearer tokens, API keys, and long string values before sending to any LLM.
- **Prompt Defense**: Treats all log-derived strings as untrusted data, forbidding models from executing embedded instructions.
- **Two-Stage Model Verification**:
  1. **Schema & Identifier Matching**: Checks that returned explanations use only known `fact_id`, exact cited `evidence_ids`, identical `entity_ids`, and unaltered `interpretation_status`.
  2. **Semantic Entailment Review**: A second prompt asks the model to confirm that every claim is strictly entailed by the cited evidence, rejecting invented steps or escalated maliciousness claims.
- **Safe Fallback**: If the configured provider fails, times out, is rate-limited, or fails verification, the engine immediately reverts to the deterministic report without altering downstream formats.
- **Report Caching**: Cache key is a SHA-256 hash of `(provider, model, prompt_version, engine_review, evidence_package_sha256)`.
- **HTML Export**: Escapes all text via `html.escape()` to prevent script injection via malicious log strings.

### 4.5. Investigation Interface (`ui/app.py`)
The Streamlit interface provides five structured workspaces:
1. **Import:** Select local manifest or enter HTTPS URL; view real-time download byte count, validation phase, and errors.
2. **Runs:** Review imported datasets, source tier (Core/Advanced/Extreme), engine completion status, incident count, and dataset-wide quality metrics.
3. **Incidents:** Dedicated incident triage view with severity, minimum risk, host, account, and technique filters, paginated table, and quick selection.
4. **Investigation:** In-depth examination divided into 7 tabs:
   - **Overview:** Severity, risk score, MITRE techniques, kill-chain phases, and engine review.
   - **Timeline:** Expandable event cards with maliciousness tags, ordering confidence, and evidence citations.
   - **Graph:** Plotly entity-relationship graph (hosts, accounts, processes) with dashed lines for derived/hypothesized links and edge inspection.
   - **Evidence:** Paginated tabular evidence records with source file identifiers and record locators.
   - **Next targets:** FR-6 look-ahead candidates with evidence strength, score, assumptions, and supporting IDs.
   - **Data quality:** Dataset-wide quality counters side-by-side with incident-specific impact notes.
   - **Report:** Provider health check, on-demand AI/deterministic report generation, and one-click Markdown/HTML downloads.
5. **Empty Result:** When a dataset has zero detected incidents, explicitly displays: *"Processing completed successfully with zero detected incidents."*

---

## 5. API Reference Summary

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check returning service status and AI configuration. |
| `POST` | `/api/v1/ai/health` | Probes configured Groq/OpenAI provider with a minimal test prompt. |
| `POST` | `/api/v1/imports/local` | Initiates asynchronous background import from a local manifest path. |
| `POST` | `/api/v1/imports/remote`| Initiates asynchronous background import from an approved HTTPS URL. |
| `GET` | `/api/v1/imports/{import_id}` | Polls status (`queued`, `running`, `completed`, `failed`), phase, and byte counts. |
| `GET` | `/api/v1/runs` | Lists imported runs and source dataset metadata. |
| `GET` | `/api/v1/runs/{run_id}/quality` | Returns dataset-wide parsing and data-quality metrics. |
| `GET` | `/api/v1/runs/{run_id}/incidents` | Lists and filters incidents with pagination, severity, risk, host, and technique. |
| `GET` | `/api/v1/runs/{run_id}/incidents/{incident_id}` | Returns complete incident bundle JSON. |
| `GET` | `/api/v1/runs/{run_id}/incidents/{incident_id}/path` | Returns presentation-ordered timeline and relationships. |
| `GET` | `/api/v1/runs/{run_id}/incidents/{incident_id}/evidence` | Returns paginated evidence rows filtered from `evidence.parquet`. |
| `GET` | `/api/v1/runs/{run_id}/incidents/{incident_id}/reachability`| Returns FR-6 next-target candidates from `access_history.parquet`. |
| `POST`/`GET` | `/api/v1/runs/{run_id}/incidents/{incident_id}/report` | Generates or retrieves cached structured investigation report. |
| `GET` | `/api/v1/runs/{run_id}/incidents/{incident_id}/report.md` | Returns plain-text Markdown report. |
| `GET` | `/api/v1/runs/{run_id}/incidents/{incident_id}/report.html`| Returns self-contained, escaped HTML report. |

---

## 6. How to Run, Test, and Benchmark

### 6.1. Local Python Startup
```sh
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Generate synthetic demonstration fixtures
python scripts/demo.py

# 3. Start FastAPI backend
uvicorn api.main:app --host 127.0.0.1 --port 8000

# 4. In a separate terminal, start Streamlit UI
source .venv/bin/activate
streamlit run ui/app.py --server.port=8501 --browser.gatherUsageStats=false
```
Open **http://localhost:8501** in your browser. Under Import, enter `data/input/demo/manifest.json`.

### 6.2. Docker Compose
```sh
docker compose up --build
```
- UI available at `http://localhost:8501`.
- Backend docs available at `http://localhost:8000/docs`.

### 6.3. Running the Test Suite
```sh
# Full test suite with coverage report
pytest --cov=api --cov-report=term-missing

# Static typing & linting
pyright
ruff check api ui scripts tests
```

### 6.4. Running the Benchmark
```sh
# Synthetic 250,000-row benchmark
python -m scripts.benchmark --rows 250000

# Actual teammate engine manifest benchmark
python -m scripts.benchmark --manifest /path/to/manifest.json
```
**Measured Synthetic Performance on 16 GB Laptop (250k rows):**
- Import duration: ~45 ms
- Cold path latency: 1.3 ms (target: < 2000 ms)
- Warm path latency: 1.25 ms (target: < 500 ms)
- Peak process RSS: ~180 MB (target: < 8 GB)
- Direct DuckDB Parquet row-group scanning without RAM bloat.

---

## 7. Key Operational & Security Rules

1. **API Keys**: Keep `OPENAI_API_KEY` and `GROQ_API_KEY` in environment variables. They are never logged, returned in API responses, or exposed to Streamlit.
2. **Presigned URLs**: Query parameters are filtered before logging or exposing to frontend consumers.
3. **No Dynamic Model Switching**: If Groq or OpenAI fails, the system falls back to deterministic mode rather than switching providers silently, avoiding unexpected data governance or cost shifts.
4. **Offline Capability**: Setting `AI_PROVIDER=disabled` requires zero external network connections and produces 100% deterministic reports.
5. **Memory Cap**: Never call `.read()` or `.to_pandas()` on entire large Parquet files. Use DuckDB bounded queries with pagination.
