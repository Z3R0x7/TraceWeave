# Implementation traceability

The user's Revised Integration Plan is the implementation scope. This checklist records
where each requirement is implemented and which verification applies. It does not certify
unprovided full-tier datasets or live provider credentials.

| Requirement | Implementation | Verification |
|---|---|---|
| Local and HTTPS manifest input | `api/transfer.py`, `api/imports.py` | local integration and mocked remote equivalence |
| Streaming, checksums, sizes and confinement | transfer chunk loop, pinned TLS host, root resolver | transfer size/checksum, symlink, DNS, URL and redirect tests |
| Zero incidents | importer count validation | zero-result integration test |
| NDJSON summaries and individual bundles | bounded readline, per-bundle JSON limit | importer tests; synthetic benchmark |
| Lifecycle/phase separation | SQLite imports and manifest engine fields | job status API, restart handling |
| Stable run-scoped IDs and revisions | `(run_id,incident_id)` key and revision gate | revision reimport tests |
| Source file and record locator | required Parquet fields | import validation |
| Entity/evidence references | Pydantic validators and evidence lookup | contract and missing-evidence tests |
| Timestamp ties and uncertainty | ordered path plus explicit ordering metadata | tied timestamp test and UI captions |
| Observation versus maliciousness | independent contract fields | schema and UI |
| Dataset-wide quality | Quality contract and separate endpoint/tab | integration test |
| Engine-supplied incident quality | incident bundle and dedicated display | integration fixture and report export |
| SQLite state, DuckDB analytical reads | backend-only Store and in-memory query sessions | restart integration and query benchmark |
| Every public endpoint | FastAPI OpenAPI routes | API integration tests and `/docs` |
| Timeline/graph/evidence navigation | Streamlit tabs and relationship inspector | Streamlit AppTest |
| Full-dataset FR-6 handoff | separate access-history Parquet | candidate exists outside incident evidence |
| Evidence-supported look-ahead | allowed relation types, time/validity checks, top ten | access-condition tests |
| Groq/OpenAI/disabled adapter | backend Provider | provider HTTP-shape tests and no-key fallback |
| Explicit provider health check | `POST /api/v1/ai/health` and UI button | endpoint/mocked provider tests; live credentials pending |
| Reuse engine review | inline and separate review merge | review-artifact integration test |
| Sanitized bounded report package | sanitizer and fact/evidence caps | sanitization and report tests |
| Schema, IDs and semantic support | Narrative model, exact identifier sets, second support review | invalid narrative and semantic-rejection tests |
| Provider/model/prompt/review/fingerprint cache | reports cache key | fingerprint and cache reuse tests |
| Escaped self-contained HTML | HTML escape before export | script-injection test |
| Persistent storage and startup | local README, Dockerfile, Compose volumes | local API/UI smoke; Compose config |
| Performance observability | benchmark script and DuckDB profile | synthetic representative artifacts, not 50 GB proof |
| No engine responsibility overlap | application imports completed artifacts only | no raw-log parsing/detection/correlation implementation |

## External acceptance still required

- Import real teammate output and reconcile its fields against the exported schemas.
- Execute the explicit provider health check using an available model and an authorized key.
- Run a full 15 GB engine-output handoff and retain it as fallback.
- Benchmark the 50 GB engine-output handoff on the judging laptop; source-size metadata alone
  is not evidence of a successful full-tier run.
- Docker runtime acceptance completed for the synthetic fixture; repeat it with real artifacts.
