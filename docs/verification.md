# Verification record — 31 October 2026

Implemented using Ponytail full mode and the ECC verification-loop workflow. The authoritative
requirement mapping is in `docs/requirements.md`; engine-facing JSON Schemas are in `contracts/`.

| Gate | Result | Evidence |
|---|---|---|
| Build | PASS locally | `python -m compileall -q api ui scripts`; both Docker image builds also completed |
| Types | PASS | `pyright`: zero errors/warnings |
| Lint | PASS | `ruff check api ui scripts tests` |
| Tests | PASS | 49 API, contract, transfer, FR-6, report and Streamlit tests; backend coverage 93%; includes a 300-incident streamed import/pagination test and a report request during a stalled bundle download |
| Dependencies | PASS | `pip check`: no broken requirements |
| Security checks | PASS for executed checks | No key-pattern matches in source/config; confinement, private DNS, redirects, unknown citations, sanitization and HTML escaping tested |
| Change review | Manual review | Workspace has no Git repository; inspected new application/config/tests and marked the previous plan superseded |
| Compose configuration | PASS | `docker compose config --quiet` |
| Local runtime | VERIFIED | API health, actual background import, path/reachability, report generation, Streamlit health, and persisted demo after API restart |
| Container runtime | VERIFIED | Docker 29.8.0, Python 3.13.18 image: latest API/UI started; health endpoints passed; demo import, path, evidence and report worked; evidence persisted after API restart; UI container has neither provider key |
| Live AI | NOT PERFORMED | No configured provider/model/key; provider HTTP contracts and failure cases tested with mocks |
| Full 15/50 GB tier | NOT PERFORMED | Real completed engine handoff has not been supplied |

The test framework reports one upstream Starlette/httpx deprecation warning. Tests still pass.
This is separate from application correctness failures.

## Representative synthetic benchmark

Executed `python -m scripts.benchmark --rows 250000` on the local Python 3.13.1 macOS arm64
environment. This is 250,000 synthetic evidence records and one incident, not a source-tier run.

- Import: approximately 45 ms.
- Cold incident path: approximately 1.4 ms.
- Maximum of ten warm path requests: approximately 1.4 ms.
- Peak process RSS: approximately 270 MB.
- Query profile: approximately 9.7 MB read, one Parquet file, 24 row groups, and 92,160 rows
  scanned for 100 returned rows in the recorded run. DuckDB dynamic filtering can vary the
  scan count between executions.

These measurements establish the small representative case only. Repeat the benchmark with
`--manifest` for actual teammate artifacts before claiming 15 GB or 50 GB acceptance.

## Remaining acceptance inputs

1. Teammate's completed manifest and all referenced output artifacts.
2. A locally configured Groq or OpenAI model/key for the explicit provider health check.
3. Real 15 GB fallback and 50 GB stretch handoffs for tier measurements.

Docker initially delayed new container startup, then recovered without restarting the daemon
or changing unrelated containers. Final Compose startup succeeded with both latest images.
The running interface is at http://127.0.0.1:8501; API documentation is at
http://127.0.0.1:8000/docs. Duplicate local development servers were stopped.

The application itself remains usable in local Python mode with deterministic reports.
