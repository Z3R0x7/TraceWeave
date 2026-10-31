# TraceWeave

Local security-log analysis and evidence-linked investigation. Python 3.12+ and Node 24+ are required. Uses selected LateralX classification and Jevline identity/relationship code; see [NOTICE.md](NOTICE.md).

## Start

From this folder:

```sh
./start.command
```

The launcher creates the Python environment and installs pinned dependencies on first use. Open **http://127.0.0.1:18505/** and keep the terminal open. On macOS, `start.command` can also be launched from Finder. Use `PORT=18506 ./start.command` if that port is occupied.

This is a local single-user submission candidate. It is not a remotely authenticated multi-user deployment.

## Analyze

1. Check the readiness panel. Connect Groq/OpenAI using the masked session key form, or configure `.env` from `.env.example`. The session key is held only in backend memory and shared by analysis and report generation. Connecting makes one small provider health request. Keys never appear in reports or job records.
2. Select raw logs, or enter their absolute server-local paths to avoid copying large files. Supported: FortiGate, JSONL/NDJSON, CSV and gzip. The supplied performance case is `/Users/mac/Documents/firex_logs/firex-10G.log` (6,543,120,032 actual bytes).
3. Confirm bounded AI evidence sharing, then select **Analyze and investigate**. The whole source is processed locally; AI reviews selected packets, not every record. Packets may retain account names and IPs after sanitization. The default budget is ten packets, bounded by the engine's request limit.
4. Follow measured phase/byte/record progress. The browser may be refreshed while analysis continues. Cancel analysis to terminate its Python/Node process group. Original inputs and partial results are retained.
5. The completed output opens automatically. The engine and viewer retain separate failure states: an indexing failure does not erase a successful engine run. Reopen completed results from Run history.

Raw browser uploads use bounded chunks and save offsets. After interruption, reselect the original files in the same order to resume; name, size and modification time must match. Uploaded copies live under `runs/website/`. A local source path is read directly. Jobs require estimated disk headroom of six times source size plus 3 GiB; real expansion can exceed that, especially for gzip. No arbitrary total source-size limit is imposed.

## Investigate

- **Attack path:** risk-ranked candidates, a synchronized timeline, entity graph and evidence inspector. Solid cyan = recorded observation; dashed amber = inferred association; dotted purple = conditional predicted exposure. Risk is a transparent triage heuristic, not compromise probability. Raw-record counts deduplicate repeated citations and exclude AI text; truncated previews show lower bounds.
- **Possible next reach:** permission, session and network-policy evidence intersected at their stated validity time. Missing context stays unknown. `investigation-context.json` in the demo is invented; real investigations never inherit those permissions.
- **Report:** downloadable cited evidence report. Optional AI drafting requires another explicit action, citation validation and a second support review. AI drafts remain unconfirmed and require analyst review.

Open an existing result folder through **Existing engine output**. Required: `summary.json`, `evidence.jsonl`, and `incidents.jsonl` or `findings.jsonl`. Raw logs, `.env` and the large engine database are not uploaded by this picker. Result transfers are chunked; incident/evidence indexes are disk-backed and persist in `runs/viewer-cache/`. Completed indexes and risk rankings are reused on reopening the same artifacts. Source changes or viewer version changes invalidate the cache. Lists show up to 250 results per query; search is performed against the indexed candidates. Interrupted exports without incident rows are labelled uncorrelated previews.

## Engine CLI

The CLI still uses `.env`; it does not receive browser-session credentials.

```sh
cp .env.example .env  # only if you do not already have one
chmod 600 .env
.venv/bin/python engine.py --input /absolute/path/your.log --output runs/my-analysis
```

Select a new output directory per run. Outputs include summary/progress, findings/incidents/evidence JSONL, AI reviews, source identities, rejected spans and `analysis.sqlite`. Retain source logs to verify exact byte/record locators. Invalid spans are counted and excluded; `--strict` stops instead. No missing bytes are reconstructed.

## Persistence and recovery

Job records and logs are stored beneath `runs/website/`; no API key is persisted. Runtime credentials must be reconnected after restart. `.env` remains private and gitignored. The most recent valid investigation index is reopened on startup. An abruptly detached process is shown as detached and blocks duplicate analysis; the app does not kill an unverified historical PID. Stop/recover such a process through the original terminal before starting another. Normal terminal shutdown cancels app-owned analysis.

Keep the `runs/` folder between restarts. Back up completed source/output folders; do not delete active jobs or caches currently in use. There is no automatic destructive retention. Logs and artifacts can contain sensitive investigation data and should stay private.

## Submission status

Implemented: local analysis-to-investigation workflow, runtime AI configuration, chunked transfers, persisted job records, cancellation, cached result/risk indexes, three investigation tabs, cited reports, heuristic ranking and distinct raw-record counts.

**Acceptance testing is on hold at the user's request.** Recent changes have syntax checks only; no new engine benchmark or live-provider call was run for this release candidate. Detection/label/path accuracy, full-file performance, recovery behavior, packaging and all user flows still require acceptance before claiming a production-ready or competition-qualified release. No 10/10 rating is claimed.

The existing 10k EDR sample is invalid and must not be used for validation. Dummy data is clearly marked synthetic. Full Core qualification requires a valid 15 GB dataset; the named 10G file's actual 6.543 GB size cannot establish that qualification.

See [PERFORMANCE_AND_APP_PLAN.md](PERFORMANCE_AND_APP_PLAN.md) for acceptance gates and [JURY_READINESS_REVIEW.md](JURY_READINESS_REVIEW.md) for the evidence gaps. The dedicated-server design remains in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).
