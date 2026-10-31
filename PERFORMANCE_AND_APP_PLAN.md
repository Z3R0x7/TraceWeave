# Performance first, runnable application second

Status: implementation plan. This document does not implement automation, deployment or a new application workflow.

## Scope and acceptance targets

The PRD defines Core = 15 GB, Advanced = 30 GB, Extreme = 50 GB. Interpret the requested scope below Advanced as Core, with the newly supplied file as the first real acceptance case. Do not substitute larger-tier tests until this scope works reliably.

Initial supplied test:

`/Users/mac/Documents/firex_logs/firex-10G.log`

Inspected size: **6,543,120,032 bytes (6.543 GB decimal)**. It is readable and starts with a FortiGate record. The filename says 10G; performance reports must use the actual byte count. Preserve the original file. Never use the invalid 10k EDR dataset or synthetic fixture as detection/performance acceptance evidence.

| Measure | Acceptance | Stretch target |
|---|---|---|
| Complete supplied-file processing | Under 2 hours | Under 1 hour |
| Full Core qualification, when valid 15 GB data is available | Under 2 hours | Under 1 hour |
| Combined application-process memory | Under 8 GB target; never accept a run exceeding 10 GB | Under 8 GB throughout |
| Open a selected incident | Under 2 seconds after indexing | Under 500 ms with a warm cache |
| Result integrity | Complete source accounting, valid evidence references and explicit rejected-byte coverage | Same |

Timing starts when analysis begins on an already-local source and stops when detection, correlation, configured AI work, required exports and the investigation index are ready. Measure browser upload duration separately; disclose it rather than hiding it in analysis throughput. Report both ingestion time and total time. A pipeline with AI skipped is a profiling probe, not acceptance of the configured AI-enabled app.

The earlier 527.7 MB probe took 336 seconds with approximately 875 MB combined lifetime RSS upper bound; external AI was excluded. It does not prove any full-tier target. Changes since that probe require new measurement. The performance goal was cleared in the chat; this plan does not silently recreate an autonomous goal.

## Phase 1 — establish one authoritative codebase and baseline

1. Reconcile the latest GitHub checkout (`d45d44e` at review time) with local work in a separate branch. Retain GitHub's raw-log job workflow and the local disk-backed result importer. Review local engine optimizations individually; do not overwrite either version wholesale.
2. Remove obsolete result-size/row-count rejection limits from the integrated viewer while retaining schema validation and bounded individual requests/records. Ensure large inputs never require browser-wide JSON loading.
3. Record the source checksum/size, code revision, Python/Node versions, CPU/RAM, free disk and analysis settings for a reproducible baseline. Do not record secrets.
4. Add stage timing, CPU time, records/bytes per second, database/export sizes and whole-process-tree memory sampling. Include Python, Node and any future workers, including transient overlapping processes. Lifetime RSS maxima can provide a conservative bound when the process set is known; do not report the parent's memory alone.
5. Profile bounded portions of this supplied file before scheduling the full-file run. Retain only compact performance artifacts and useful completed outputs; remove task-owned temporary benchmark copies when finished.

Exit: an attributable baseline and a ranked list of measured bottlenecks. No speed or accuracy claim from the dummy data.

## Phase 2 — optimize the engine without losing evidence

Prioritize the current dominant cost: ingestion/parsing/metadata/storage, rather than graph styling.

- Verify the guarded firewall metadata path, native JSON encoder and early deduplication against the reference behavior. Keep the generic endpoint/access path for richer records. Exact-byte deduplication must retain every occurrence and original locator; malformed records cannot be promoted to valid duplicates.
- Tune bounded batches, SQLite cache/checkpoint behavior and worker messages using measured CPU, I/O and memory. Reject changes that merely move cost into export or increase memory without a throughput benefit. Recent single-insert and alternate-tokenizer experiments did not demonstrate a benefit and were not retained.
- If one Python process remains CPU-bound, introduce a small bounded worker pipeline, starting at two workers and measuring before increasing. Preserve global deduplication, authentication sequences, PID lifetimes and incident correlation across worker/chunk boundaries. Bound in-flight work so a slow storage stage cannot accumulate the dataset in RAM.
- Add only indexes justified by actual queries. Review global correlation and export query plans on the larger run; avoid per-incident rescans of the full dataset.
- Reserve storage from measured amplification, including indexes, WAL, exports, uploads and gzip decoding. The existing twice-input estimate is inadequate: a supplied 4.29 GB run produced roughly a 20 GB database alone. Check free space during execution as well as admission.
- Keep AI evidence packets and request budgets bounded. Track useful accepted/rejected results, provider latency and quota failures separately from local engine time. A rejected or unavailable model response must not be misreported as successful review.

Memory budget proposal: up to 1 GB for the coordinator, up to 4 GB combined for processing workers, up to 1 GB for API/index activity and 2 GB headroom. These are planning allocations, not established measurements. Tune to stay below 8 GB combined RSS; reaching 10 GB requires graceful failure/cancellation, not a passing result.

Exit: a demonstrable improvement on the same source sections, with equivalent evidence accounting and detection/correlation behavior. Do not improve apparent speed by disabling required stages, dropping records, truncating analysis or fabricating incident links.

## Phase 3 — full supplied-file acceptance

Run the entire inspected 6.543 GB source with the selected provider/model and explicit data-sharing authorization. Keys remain in backend `.env` until the app credential flow exists. A local-only performance run may precede it, but must be labelled as excluding live AI.

Retain:

- Actual source bytes/checksum and complete parsed/rejected/duplicate occurrence accounting.
- Stage and total timings; peak simultaneous process-tree memory and conservative upper bound if used.
- Findings, incident memberships, mappings, evidence locator integrity and output-index integrity.
- Provider/model, request/token budgets, review outcomes and any incomplete coverage, without the key.
- Sampled source-record cross-checks and before/after regression comparisons. Investigate the existing timestamp disagreement; optimization must not silently alter the source clock interpretation.

Do not invent ground truth or claim detection accuracy from matching counts. With supplied planted-attack labels, evaluate the PRD's gates: detection over 70%, correct labels over 60%, at least half the planted paths reconstructed, and false incidents under 30%. Without those labels, report accuracy as unverified.

Repeat acceptance after material engine/storage changes. After the supplied file passes, validate the full 15 GB Core tier before claiming Core readiness. The 6.543 GB file alone cannot establish 10 GB or 15 GB completion.

## Phase 4 — automate the local app (plan only; build after performance gate)

Backend work:

1. One durable job record per run: queued, running, completed, failed, cancelling, cancelled and needs-credentials. Persist job identity/configuration and safe errors in SQLite. Reconcile interrupted jobs at restart and prevent duplicate launches.
2. Connect raw-log selection, upload or allowlisted server-local input, engine execution and output activation. Use resumable chunk transfers for browser inputs, checksum verification and immutable source IDs. Do not re-upload files already on the server.
3. Track and cancel the whole Python/Node process group. Keep completed artifacts when analysis or viewing fails; distinguish an engine failure from a viewer-index failure.
4. Keep runtime provider credentials on the backend. Validate provider/model/key before expensive processing, scope credentials to the session and require reconnection after expiry/restart. Never expose keys through UI state, command arguments, logs or artifacts.
5. Create a persistent investigation index once, keyed by source/run fingerprint and engine/schema revision. Reopen it on subsequent visits instead of importing hundreds of MB of JSONL every time. Invalidate changed or partial artifacts safely.
6. Serve indexed, paginated incident summaries and on-demand graph neighborhoods/evidence. A graph request should retrieve one incident or neighborhood, not rescan the full output. Precompute/cache risk rankings and preserve their explanation.

Frontend work:

1. One flow: choose input → check connection/provider → analyze → progress/cancel → open investigation.
2. Show upload, ingestion, detection, correlation, AI, export and indexing as separate measured phases. Reconnect to a running job after page reload.
3. Synchronize graph, timeline, selection and evidence. Add expand/filter controls and bounded result pages; repeated observations may be grouped into an edge with a count and evidence lookup.
4. Preserve observed/inferred/predicted styling, incomplete coverage, unknown permissions, timestamp conflicts and AI hypotheses. Never carry synthetic access facts into a real run.
5. Keep three investigation tabs. FR6 requires verified inventory/permission/policy context; absent context remains unknown. Reports cite evidence, show risk and raw-record counts, and label model drafts for analyst review.
6. Provide clear empty, failed, partial, cancelled and expired-key states, accessible keyboard controls and downloadable reports.

Exit: one supplied-file run completes through the UI without manual copying or terminal intervention, survives page refresh, and opens its real incident paths within the latency target. Live AI and cancellation/restart failure paths must be checked, not just mocked.

## Phase 5 — package and release (plan only)

- Supply one documented startup command and, if useful, a minimal container deployment with a persistent data directory. Choose an existing Docker/system service workflow rather than adding multiple deployment systems.
- Fix the root README: its Stage 1 `uvicorn api:app` and missing test-path instructions do not match the reviewed checkout.
- Validate Python/Node versions, writable storage, free space and provider configuration at startup. Keep originals and outputs outside the code checkout.
- Add authentication and per-user data ownership before any remote deployment. Keep loopback-only behavior for the initial local app.
- Define retention, deliberate run deletion, backup/restore, bounded logs and safe upgrades/rollback. Record third-party provenance and resolve the LateralX redistribution issue in NOTICE.md before distributing a release.
- Run a clean-install acceptance: start the app, select the supplied source, execute, inspect graph/timeline/evidence/reach/report, restart and reopen completed results. Measure speed and memory again on this packaged path.

## Execution order

Baseline and reconciliation → measured engine improvements → full supplied-file performance/quality checks → full Core qualification → local job automation and persistent investigation index → packaging/deployment acceptance.

Current deliverable is this plan. No automation, app integration or deployment is built by this document. No performance target or real-data accuracy gate is claimed as achieved.
