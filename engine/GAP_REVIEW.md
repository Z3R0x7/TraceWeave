# Engine gap review and application handoff

The input list is design advice, not a specification to implement blindly. No maximum file-size check is imposed. Memory is bounded by partition queues, row/byte batch limits and disk-backed SQL. Finite disk, RAM, CPU and runtime remain practical limits. 30/50 GB acceptance is **not yet verified**.

| Gap | Current engine status |
|---|---|
| G1 | Newline-aligned process workers, bounded in-flight jobs. Exact byte offsets, no worker IPC of rows. |
| G2 | `--corrupt-policy skip` continues after rejected records and writes offset, length and reason. Strict mode remains the default. Oversized records are drained with bounded reads. |
| G3 | UTC normalization, missing/ambiguous timestamps rejected, original firewall clock representations retained. Epoch/local clock drift is flagged, not automatically corrected. |
| G4 | Exact-record dedup runs in disk-backed SQL, not a Python global set. Windowed fuzzy dedup is deliberately absent: it could remove real repeated attacks. |
| G5 | Operator-provided static host/IP aliases resolved by SQL joins. Ambiguous aliases rejected. Automatic DHCP history and case-folding of all accounts are not implemented: both can merge different entities incorrectly. |
| G6 | Asset criticality contributes to triage priority. Permissions/reachability must still come from evidence; asset importance does not grant access. |
| G7 | Validated allowlist reduces priority without removing evidence or detections. False-positive improvement is unmeasured. |
| G8–G9 | Workers parse only; global SQL detects windows after all partitions land. Additive counters aggregate exactly. One/two worker tests compare counts, IDs and steps across a split authentication attack. |
| G10 | Typed configuration and snapshot linting, nine code-defined starter rules. Generic YAML/Sigma rule execution remains unimplemented. |
| G11 | Deferred live mode. Stable snapshot required. |
| G12 | Incident IDs derive from recorded identity/session or exact evidence, not run directory. Repeat-alert group IDs also include rule, signature, observer, endpoints and fixed time bucket. Group boundaries can split a sequence. |
| G13 | Preflight disk estimate, free-space reserve checks and capped DuckDB spill. Estimate configurable; not a guaranteed output-size bound. |
| G14 | CPU/RAM-based parser count, database memory cap, bounded batches and sampled process-tree RSS governor. RSS may be unavailable on this host. Use Docker memory limits for hard isolation. |
| G15 | Per-run output, atomic progress/manifest, run lock and clean summary. |
| G16 | Resume completed **parse partitions** with `--resume`; changed source/parse settings rejected. SQL phases rebuild. Not transaction-level SQL checkpointing. |
| G17 | `cancel` flag, timeout checks, DuckDB interrupt, partial-status file and retained completed partitions. Failed directories never get a completed manifest. |
| G18 | Phase times, actual bytes, skipped records/bytes, parent OS peak and sampled process-tree peak. Null memory measurement means unknown. |
| G19 | Application owner: authenticated job-start/status API integration still needed. Existing API imports completed artifacts; it does not launch ingestion. |
| G20 | Engine `raw` reads registered immutable source IDs only, enforces line boundaries and 64 KiB/100-line limits. An HTTP route is an application task. |
| G21 | Engine `metrics` command and metrics JSON ready; scoreboard HTTP route remains application work. |
| G22 | Deferred SSE. Progress JSON already supports polling. |
| G23 | Schema export includes optional enrichment/playbook metadata; adapter maps engine output to the app contract. Two contracts remain explicit, not interchangeable. |
| G24 | AI defaults off. CLI launches enabled AI in a separate process after core completion; bounded/cached validated reviews cannot change baseline facts. `review` can also run manually. |
| G25 | CLI covers analyze/resume/cancel/summary/metrics/evaluate/raw/validate/incidents/show/review. API/UI are separate processes; no redundant `serve` wrapper. |
| G26 | Existing Docker packaging, read-only input mounts, local data excluded from build context. Docker daemon unavailable here; do not claim a new Docker scale test. |
| G27 | Deterministic rule fixtures plus serial/parallel equivalence, corruption, cancellation/resume and offline enrichment tests. Full official ground truth not supplied. |
| G28 | Validated config covers limits, aliases, assets, known-benign entries and optional snapshots. Rule-directory plugin support deferred. |

## Additional suggestions from the list

Repeated matching firewall alerts can share an alert group without erasing their findings. Evidence pointers are retained, step previews are capped, full Parquet remains queryable. There is no arbitrary incident-count cap or automatic deletion of low-severity singletons. A fixed “hundreds of incidents” target would conceal data.

Parsing currently uses a strict source-specific Python parser in process workers, with a direct FortiGate mapping fast path. It is not a native DuckDB bulk key/value parser. Normalized records and bounded excerpts are retained on disk; candidate-only two-pass retention is not implemented. These are remaining storage/performance opportunities.

`evaluate --truth` scores independent evidence-ID truth against completed findings: detection recall, technique correctness, ordered complete paths, optional false-incident share, runtime, measured memory and sampled local bundle-open latency. It never feeds truth back into detection. Null/unknown measurements are not a pass. Organizer scoring may use different matching rules.

## Three proposed SOC features

1. **Triage: partly shipped.** Application priority queue receives a deterministic score from severity, linked-finding count, asset criticality and allowlist context. It is not a probability. Narrow repeated-alert grouping shipped. Case statuses, assignees, notes and shift-handoff workflow remain application work; no database migration for them is claimed.
2. **Offline enrichment: shipped as optional snapshots.** IP/domain feed matches retain evidence IDs, source and date. MITRE STIX can be converted offline into mitigation cards, with source/date/evidence attached. No real feeds or MITRE bundle are fabricated or automatically downloaded. GeoIP/ASN, hash matches and OTX are not implemented. Demo indicators remain an explicitly secondary regression option.
3. **Anomaly ML: deferred.** No Isolation Forest is trained. No anomaly accuracy claim until scale and independent baseline evaluation succeed.

Static snapshots may be stale and matching an indicator does not establish compromise. Mitigation cards are analyst guidance; no response action is executed.

MITRE conversion follows its public [STIX relationship model](https://mitre-attack.github.io/attack-data-model/schemas/relationship-types/): a `course-of-action` mitigates an `attack-pattern`.

Example optional config entries (use real inventory, never these fixture addresses):

```json
{
  "asset_map": [{"host": "DC-01", "aliases": ["dc-01.corp"], "ips": ["10.0.0.10"], "criticality": 90}],
  "allowlist": [{"field": "source_ip", "value": "192.0.2.10", "reason": "Approved test scanner"}],
  "indicator_snapshot": "/feeds/indicators.json",
  "playbook_snapshot": "/feeds/playbooks.json"
}
```

Ground-truth evaluation file format:

```json
{"complete": false, "incidents": [{"id": "independent-attack-1", "steps": [{"evidence_id": "ev_<sha256-of-record>", "technique_id": "T1110"}]}]}
```

IDs must come from independent annotation; copying the engine's findings into this file does not measure accuracy. Run `python3 engine.py evaluate --run runs/large --truth /evaluation/truth.json`.
