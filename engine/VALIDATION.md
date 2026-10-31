# Validation status — 31 October 2026

## Automated checks

94 engine/application tests passed during this update. Cases include newline-aligned ranges, an oversized unterminated line, one/two-worker equivalence, authentication windows split between workers, corrupt-line skip accounting, cancellation/resume, changed-source rejection, immutable raw-evidence reads, offline source attribution and STIX conversion. Tests do not establish real-world detection accuracy.

## Official dataset prefix

Input: first 200,000 record-aligned lines from the supplied `firex` file, 105,591,026 bytes. This is a prefix, not a full official tier.

| Check | Result |
|---|---:|
| Records parsed | 200,000 |
| Rejected records | 0 |
| Scanned bytes | 105,591,026 |
| Candidate findings | 9,137 |
| Candidate investigations | 9,137 |
| Timestamp conflicts retained | 200,000 |
| Serial/parallel differences in finding IDs, incident IDs, rule, evidence, time and count | 0 |
| Latest four-worker end-to-end run | 45.729 seconds |

The same prefix initially took 150.105 seconds on the earlier serial implementation. Direct source mapping, parallel parsing and streamed baseline briefs reduced overhead. Runs included code/output changes and some background overlap, so these timings are diagnostic rather than a controlled worker-scaling result. Do not extrapolate them into a guaranteed 50 GB runtime.

The parent-process OS peak for the latest four-worker run was approximately 1.07 GiB. **Combined-worker/process-tree RSS could not be measured on this host**, so the PRD memory target is not established. Enforce and measure container memory on the intended judging machine.

The run artifacts remain private/gitignored. [scale-validation.json](scale-validation.json) contains aggregate measurements only.

## Still unverified

- Complete 15/30/50 GB runs and the PRD runtime/memory gates.
- Accuracy against independent organizer ground truth, including full attack-path reconstruction.
- Live Groq/OpenAI interpretation quality.
- Updated Docker execution: local Docker daemon unavailable.
- Binary tail semantics and systematic 19,800-second source clock discrepancy.

Skip mode can continue beyond rejected lines and reports exclusions. It does not interpret binary bytes or turn incomplete telemetry into full source coverage.
