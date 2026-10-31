# Engine handoff v1

Engine command (non-interactive):

```text
python engine.py analyze --input <dataset-file-or-directory> --output <new-run-directory> --job-id <job-id> --quiet
```

Exit status: 0 baseline completed, 1 error, 130 interrupted. Existing output directories are rejected. Start subprocess with an argument list, not a shell string. AI is optional enrichment and can be run separately. A completed baseline can have unavailable/failed AI review.

Read `progress.v1.json` while running. It is atomically replaced. `status` is running/completed/failed; `phase` is starting/parsing/normalizing/detecting/correlating/writing_results/completed. `processed_bytes/total_bytes` measures ingestion, NOT the entire analysis. Counters are input records; malformed records are excluded; missing-critical-fields counts can overlap other categories. `out_of_order_records` is within-file timestamp reversals, not a live-stream watermark metric. Parsed duplicates are counted after disk-backed deduplication.

Read `manifest.v1.json` only when published. It names:

- `incidents.v1.jsonl`: streamed summaries, one per line (valid empty file for zero findings).
- `incidents/<id>.json`: bounded per-incident details.
- `evidence/incident_evidence.parquet`: full supporting evidence membership with `incident_id`.
- `findings.parquet`: all detections and their incident memberships, including steps omitted from previews.
- `normalized/events.parquet`: all successfully normalized, deduplicated records.
- `access_history/authentication.parquet`: all successful authentication observations, including hosts outside existing incidents.
- `access_history/host_observations.parquet`: time-qualified host/address evidence.

Do not open or write the engine's temporary analytical DuckDB. That file is deleted after successful export. Use your own read connection to exported Parquet.

## Incident semantics

`incident_kind` is `single_finding` or `related_activity`. Neither proves an attack. Automatic multi-detection grouping requires the same host-scoped process entity ID. Missing IDs do not get replaced by host/account/time guesses. An authentication failure/success sequence is its own supported finding. Full cross-host/session chain inference is not implemented in v0.1.

Every step includes rule ID/version, primary evidence ID, evidence list/count, detection basis, proposed technique, tactic, uncertainty, and source entities. `kill_chain_stage` is null until the expected taxonomy is confirmed. ATT&CK tactic is not silently substituted for a different framework's stage.

The `T1486` mapping for reported mass renames is explicitly hypothetical; no claim of proven encryption. A configured destination indicator has no automatic C2 technique assignment; a connection does not prove beaconing. Demo indicators are opt-in and marked in configuration/manifest.

`step_index` orders the preview by timestamp and deterministic IDs; tied timestamps do not establish causal order. Previews cap steps at `max_incident_steps`; `steps_truncated` and full counts are explicit. Query `findings.parquet` and supporting Parquet for complete details. Graph edges have either entity endpoints (`source_id`, `target_id`) or step endpoints (`source_step_id`, `target_step_id`). The frontend must support both or render them in separate views.

## Evidence

Evidence ID is a SHA-256 of stripped original record bytes. Exact byte-equivalent duplicates collapse; JSON objects with different serialization remain distinct. Conflicting original event IDs are preserved and counted. Source locator includes absolute source path, source file identity, record number, byte offset, and length. Keep the input snapshot available and verify source metadata before fetching original bytes. These IDs and metadata are references, not authenticated provenance or full-file integrity certificates.

Sanitized bounded evidence excerpts are previews and may not be valid JSON after truncation. Raw inputs and analytical command-line fields can contain sensitive information: keep the workspace private. Sanitization is best-effort, not DLP certification.

## Access-history limitations

No current ACL, admin rights, network permission, or complete topology is inferred. Authentication observations are historical and are not necessarily RemoteInteractive; v0.1 does not export logon type. The application must call them successful authentication observations, not verified remote/admin reachability. Join address observations with time context; a bare IP match is insufficient.

## AI

Groq and OpenAI share a provider adapter. Keys are read only from environment or hidden interactive entry, never artifacts. AI suggestions stay under `ai_review`, separate from baseline steps/edges. Each review records model/provider, prompt version, packet fingerprint and limitations. A missing key does not make baseline analysis fail. Request excerpts are sanitized and bounded; external use requires permission for the actual dataset.

The caller can use `python engine.py validate --run <run>` before import. The built-in validator checks artifact presence, record accounting, graph endpoints and evidence references. It is not proof of analytical accuracy.

Machine-readable structural contracts are in `contracts/incident-v1.schema.json` and `contracts/progress-v1.schema.json`. Unknown additional fields are permitted for compatibility; endpoint and evidence checks remain necessary.
