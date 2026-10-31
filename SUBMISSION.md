# Submission candidate: TraceWeave

## Purpose

Turn security logs into evidence-linked candidate incidents and support analyst investigation through a timeline, entity graph, conditional access view and cited report. Preserve the difference between recorded facts, inferred associations and predicted exposure.

## Start and demonstrate

1. Install Python 3.12+ and Node 24+, then run `./start.command` from this folder. Open http://127.0.0.1:18505.
2. Show the readiness panel. Connect an AI provider with a masked session key, or configure the private backend `.env`.
3. For a quick UI demonstration, use the startup fixture with its visible SYNTHETIC label. It demonstrates 11 raw authentication records merged into two findings and one candidate. Its access permissions are invented and must be identified as such.
4. For a real investigation, open a completed engine-output folder. Do not launch a long analysis while acceptance testing is on hold. For a later live run, choose raw logs or their local paths, authorize bounded provider sharing, and select Analyze and investigate.
5. Select a high-priority candidate. Explain the heuristic risk breakdown, raw-record count, proposed labels, timestamp uncertainty and evidence locators. Open a graph link and the matching timeline evidence.
6. Show possible next reach only when supplied session/permission/policy facts support it. A real firewall-only export can correctly say unknown. Never present the fixture's permissions as real-network evidence.
7. Open Report. The app automatically prepares an evidence template for the selected candidate. Download it, or explicitly request a live model draft with citation/support checks.
8. Show run history and reopen an existing result. The persistent viewer index avoids rebuilding unchanged results on each visit.

## Requirement mapping

| Requirement | Implementation | Acceptance status |
|---|---|---|
| FR1 streamed processing | engine.py framing, deduplication and SQLite persistence | Full-source speed/memory acceptance pending |
| FR2 suspicious activity | signature, endpoint-pattern and global authentication sequence rules | Ground-truth detection accuracy pending |
| FR3 ATT&CK / stage labels | curated mappings and separately constrained AI hypotheses; null when unsupported | Label coverage and correctness incomplete |
| FR4 incident grouping | recorded process/session/account relationships, global reconciliation and time windows | Planted-path accuracy pending |
| FR5 timeline and graph | website path tab and synchronized evidence | Updated integration needs acceptance |
| FR6 conditional next reach | validity-aware session + permission + network-policy intersection | Real supplied access context required |
| FR7 usable page/API and guide | local server, API routes, launcher, README | Clean-install acceptance pending |
| B1 priority ranking | explained heuristic score, highest first | Not a calibrated compromise probability |
| B2 readable report | automatic on report-tab open; optional constrained AI draft; download | Live-provider acceptance pending |
| B3 raw records merged | distinct cited raw IDs, with lower-bound flag for truncated step previews | Full membership counts require complete engine output |

## Honest limitations

The real supplied file called firex-10G.log contains 6,543,120,032 bytes. Do not describe it as a completed 10 GB or 15 GB benchmark. The earlier performance goal has not been proven. Testing is now explicitly on hold; the app-owned benchmark was stopped, while any separately started user run was left alone.

No ground-truth labels were provided for computing the PRD's detection, labelling, path or false-incident metrics. High candidate counts are not proof of attack detection. Timestamp conflicts remain visible. Successful model support checks are not independently verified truth.

This is a local single-user release candidate. Multi-user authentication, remote deployment and the LateralX redistribution permission noted in NOTICE.md remain separate release gates. Code and syntax checks do not replace the paused acceptance work. Do not claim a 10/10 rating, production readiness or competition qualification before those gates pass.

## Include / exclude

Include engine.py, bridge.ts, rules.json, pinned requirements, selected vendor source/notices, website/, start.command, .env.example and the documentation. The synthetic fixture may be included as a visibly labelled demonstration asset.

Exclude .env, runtime keys, virtual environments, real logs, runs/, viewer caches and private outputs. Keep user sources and completed evidence artifacts private. The current changes have not been published to GitHub by this task.
