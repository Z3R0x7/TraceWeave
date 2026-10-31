# Primary dataset and validation policy

Updated 31 October 2026.

## Authoritative source

The user confirmed that `firex-10G.log` is the hackathon-supplied low-tier dataset and that future tiers, including 50 GB tests, use this dataset family. It is now the primary format and performance reference. The random EDR generator is a secondary regression fixture only.

Local source at the time of confirmation:

```text
/Users/mac/Documents/ChatGPT/mitigata_hackathon/outputs/killchain-engine/firex-10G.log
```

Observed size: 6,543,120,032 bytes. The name and size do not independently establish an official 15 GB acceptance run.

Raw logs, extracted samples and all reference manifests stay outside Git. Do not use incident IDs, offsets, labels or scenario descriptions in a ground-truth sidecar as detector inputs. The input directory scanner excludes `*.manifest.json` files.

## Source adapter

The primary supported source is FortiGate-style `key=value` records, with quoted strings and strict token validation. The per-record `auto` setting also retains ECS-like JSON line support. `--input-format fortigate` or `--input-format jsonl` can force a parser.

Preserve source/destination IPs separately from the firewall device's observer identity. Firewall session IDs are retained as observations; they are not treated as globally unique process IDs or automatic causal links.

The epoch `eventtime` is used when supplied, otherwise timezone-qualified date/time is used. Both raw representations and their difference are retained. The initial official prefix has a systematic 19,800-second difference; this choice is provisional pending clarification. Do not claim verified event chronology while source timestamps disagree.

A full streaming UTF-8 scan located the first invalid byte at offset 4,815,675,394, inside a record. The source changes from valid firewall text to unsupported binary bytes. The current default stops on binary records and records the offset/error. It never labels a partially parsed file a complete full-tier analysis. Verify whether the remaining section is encoded/compressed, intentional, or incomplete/corrupted before a full benchmark.

The available `firex-30G.log.manifest.json` names another tier and references a separate Windows stream. It is not assumed to match this source. Companion telemetry should be inspected and mapped before use; no Windows format is inferred from its filename alone.

## Detection scope

Added firewall-specific upstream IPS and antivirus detection findings, plus raw repeated-login-failure threshold detection. These complement the existing raw failures-then-success rule. An upstream IPS signature or antivirus block is not proof of exploitation, endpoint execution or compromise, and currently has no speculative ATT&CK technique assigned.

Endpoint process and registry rules remain available only when those fields are supplied by compatible endpoint telemetry. They are not expected to fire on firewall-only records. Broad cross-host reconstruction and signature-specific mappings still need implementation and labeled evaluation.

## Testing requirements from now on

1. Use record-aligned excerpts of the official dataset for parser/detection development, with actual source span documented.
2. Preserve synthetic unit fixtures for specific cases such as binary handling, repeated logins and missing fields.
3. Compare candidate detections to reference truth only during evaluation, never while selecting events.
4. Test cross-file/batch relationships and rejected-record accounting.
5. Resolve binary and timestamp ambiguity before claiming complete source coverage or attack ordering.
6. Benchmark the entire supported source tier and pipeline after small tests pass. Small prefixes do not establish whole-file correctness or 50 GB timing.

## First real-data validation

- Extracted first 10,000 record-aligned lines into gitignored `engine/data/input/official-sample/firex-prefix-10000.log`.
- Input bytes: 5,280,417.
- Parsed: 10,000; malformed: 0.
- Timestamp conflicts flagged: 10,000.
- Candidate findings: 473; no claim that these are 473 confirmed attacks.
- Saved run: `engine/runs/official-prefix-10000`.
- Full 6.543 GB run and 50 GB run: not performed.

## Current engine/application checks

- 94 combined automated tests passed after the evidence review, session grouping and adapter updates.
- The official 10,000-record prefix imports as 473 candidate investigations; path, evidence, reachability and report endpoints returned successfully.
- A fresh engine run writes clean briefs under the current run’s `briefs.v1.jsonl`.
- Automatic session association requires observer, session identifier and network tuple in a five-minute bucket. It is not a causal attack claim; boundaries can split a real session.
- Optional AI review receives bounded primary and neighboring detected evidence, validates references, caches responses and preserves baseline findings. Live model quality is unmeasured.
- The adapter preserves step edges, typed empty access tables, actual source size and complete AI review metadata. It does not manufacture access rights or permission validity windows.

Latest scale/correctness checks are documented in [VALIDATION.md](VALIDATION.md). Full 30/50 GB runs remain unverified.
