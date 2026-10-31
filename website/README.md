# Local investigation prototype

Three tabs consuming `../dummy-100mb-engine-output`. Start from `backend-fusion`:

```sh
.venv/bin/python website/server.py
```

Open http://127.0.0.1:18502. Uses Python's standard-library HTTP server and vanilla JavaScript/SVG; no npm packages or CSS framework. Bind is loopback only. This is a local single-user fixture viewer, not the dedicated-server deployment in `../IMPLEMENTATION_PLAN.md`.

## Data and feature flow

1. At startup, read summary.json, incidents.jsonl and evidence.jsonl. Preserve rule findings, null labels, source locators, simulated AI flags and uncertainty. A separate investigation-context.json contains **invented** inventory/access facts; the real firewall logs did not provide them.
2. Rank incidents by a transparent heuristic: 20 alert points; 40 for a recorded success in the authentication candidate; 10 for a mapped technique; 10 for multiple rule findings; up to 10 for supporting raw records. This score is triage priority, not compromise probability. Existing AI hypotheses cannot raise it. Scores and components are returned by the API.
3. Tab 1 (FR5): the same selected candidate drives its graph, timeline and evidence inspector. Solid cyan links represent recorded synthetic facts, dashed amber links represent uncertain associations, and dotted purple links represent conditional future exposure. Clicking graph links/nodes or timeline steps opens cited evidence. Timestamp ties/conflicts never establish causality. Source/destination observations are not successful attack edges.
4. Tab 2 (FR6): intersect a recorded account/session with time-valid account permissions and matching network policy. The result is conditional on attacker control, which is **not** established. An allowed port alone is insufficient; missing permissions remain unknown, and expired rights are excluded. The authentication example yields read access to one file server, not admin rights. No live network probing occurs. Other fixture incidents lack sufficient context and correctly produce no candidate.
5. Tab 3 (B2): generate a downloadable plain-English evidence report containing observations, proposed labels, conditional reach, citations and limits. The default is a deterministic template with no external request.
6. B3: count distinct supporting source-record IDs across rule steps, excluding AI text and repeated citations. The authentication example shows **11 raw records → 2 rule findings → 1 candidate incident**. The metric counts supporting raw records, including the success record, rather than claiming all 11 were separately raised security alerts. Truncated real incidents would require an engine-supplied full membership count; this viewer only uses the complete small fixture.

The fixture has 71 miniature log records, 62 rule findings, two simulated AI hypotheses and 61 candidate incidents. The authentication scenario and access context were deliberately added for UI development. No full 100 MB file was run. All data remains explicitly synthetic. The website does not change detections or persist generated reports; download a report to save it.

## AI investigation model

Use AI for constrained explanation and report drafting after deterministic evidence selection and reach calculations. The model has no tools, shell access or ability to add permissions, change scores, promote hypotheses to facts, or rewrite baseline findings. The fixture's existing two AI review records remain labelled simulated.

Optional live report flow:

1. Configure the existing backend `.env` provider/model/key. No browser key field is needed, and no key is returned to JavaScript.
2. Select a candidate, open the report tab, inspect the sharing description, tick the consent box and click **Generate AI draft**. Nothing calls the provider merely by opening a page or selecting a candidate.
3. Send only that synthetic candidate's bounded facts, up to 12 previews of 800 characters, and the relevant invented permission/policy facts. Use the engine's fixed provider endpoints. All supplied content is untrusted evidence.
4. First model call returns structured sections/claims with evidence IDs. Reject invalid structure, excessive content, missing IDs and fabricated IDs.
5. Second model call checks semantic support against the original packet. Reject the draft if it reports any unsupported claim. Passing this check means model-reviewed, not independently verified truth; the displayed draft still requires analyst review.
6. A missing key, provider error, invalid response or failed check produces a safe error and preserves the template option. Maximum two provider calls, including retries, per requested report. Only one AI report request may execute at a time. No live provider check was performed during implementation.

Raw context is synthetic and contains no secret fields; evidence previews are capped. For later real-log integration, use the engine sanitizer, enforce source/output ownership, and add production authentication/storage limits before exposing this service. The demo's mutation route requires an exact local Host, same-origin request and a per-process request token. Static files are allowlisted, `.env` cannot be served, there is no cross-origin API, and all log/model content is rendered as text.

## API (FR7)

- `GET /api/bootstrap` — fixture summary, local request token and sharing policy.
- `GET /api/incidents` — candidates sorted by descending risk, with record/finding counts.
- `GET /api/incidents/{id}/path` — incident, timeline, graph, risk and conditional reach graph.
- `GET /api/evidence/{id}` — source locator and synthetic preview, including supplemental context evidence.
- `POST /api/report` — `{"incident_id":"dummy_auth_001","mode":"template"}` or `"ai"`; JSON, same-origin and `X-Demo-Token` required.

## Checks and remaining work

Checked the fixture's byte locators/checksums, citation/graph references, sorted risk, all three uncertainty classes, positive permission/policy intersection, missing/expired permissions, merged record count, and real browser navigation/evidence/report generation. No persistent test suite or extra benchmark data was added. Live AI and production deployment remain unverified.

For real output, replace the fixture adapter with completed engine artifacts and a verified inventory/access-history contract. Preserve the distinction between observed evidence, inferred associations and predicted exposure. Do not copy the invented permissions into real investigations. The core engine and its FR1–FR4 behavior are unchanged by this prototype.

## Choose an engine-output folder

Use **Engine output folder** at the top of the page. Enter the absolute folder path on the computer running this server and click **Load folder**, or use the browser directory chooser. This selects engine outputs, not a raw log to analyze. Opening a folder never calls AI or changes its source files.

Required: `summary.json`, `evidence.jsonl`, and `incidents.jsonl` or `findings.jsonl`. Optional: `investigation-context.json`. The import reads only these five allowed names; `.env`, databases and raw logs are excluded. A browser import transfers at most 32 MiB of those artifacts; use the local/server path for larger exports (256 MiB/file, 512 MiB total and 100,000 JSONL rows/file are the prototype limits). All files must be directly inside the chosen folder.

The viewer validates the new input before switching. Invalid imports retain the previous dataset. It updates synthetic/partial labels, summary counts, timestamp warnings, reports and graphs from the selected folder. Imported results never inherit the dummy folder's invented permissions. If the export has no incident rows but does have findings, show up to 250 **uncorrelated finding previews**, without claiming completed correlation. Completed datasets display the 250 highest-scored candidates; filtering applies to that displayed set. Source identities and observation edges are derived from supplied evidence rather than hardcoded demo host names.

Truncated incident step previews show the supporting raw-record count as a lower bound. Full rule counts use the incident's `total_rule_findings`. Unknown timestamps stay unknown, and AI-only candidates are supported. Reports identify the selected input as synthetic or imported. An optional live AI request now applies to the selected input; the report consent box must be checked again after switching data. No imported real data was sent to a provider during this change.

This section supersedes the initial fixture-only loading behavior described above. The example fixture remains the startup default.

## Large result imports (current behavior)

The fixed 32 MiB browser, 256 MiB/file, 512 MiB/folder and 100,000-row rejection limits have been removed. Browser folder imports upload each artifact in 4 MiB chunks; server-path imports read JSONL incrementally. Incident/evidence/reference indexes use temporary disk-backed SQLite storage with bounded caches. Only the top 250 candidates are sent to the browser at once; this is a display bound, not a file-size restriction. The 4 MiB individual JSONL-record validation guard remains. Capacity depends on disk space, available memory for individual records and metadata, and import time; unlimited physical capacity is not claimed. Existing source artifacts are read-only. This supersedes the earlier size-limit descriptions.

## Integrated local submission candidate (current)

Start with `../start.command`; default port is now 18505. The root README is the authoritative startup guide. `jobs.py` adds persisted per-run records, chunk offsets/resume, direct server-local input, subprocess-group cancellation, history and safe recovery states. Browser-session AI credentials are verified on explicit connect, remain memory-only, and are shared by analysis/report requests. `.env` is the fallback.

The viewer now persists incident/evidence indexes, risk rankings and the last selected dataset under `runs/viewer-cache/`. Reopening unchanged versioned results reuses the index. Search queries run against the stored candidate ranking rather than only filtering the first displayed page. An engine completion and viewer activation failure are distinct. Source `coverage: partial` is reflected in the dataset banner.

Opening the report tab generates the deterministic evidence report automatically, without a model call. Live drafts still require explicit provider-sharing consent. Existing raw analysis uses the engine's bounded discovery/label review policy and requires consent in the analysis form.

Testing is on hold. Only syntax checks were run for these integrated changes; do not interpret this implementation note as a passing end-to-end or performance result. Earlier measured checks in this document describe older code versions. See `../SUBMISSION.md` for the current feature/gate distinction.
