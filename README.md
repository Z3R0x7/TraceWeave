# Log analysis engine

Standalone backend only. No UI, API server or app linking is required.
Uses selected LateralX detection code and Jevline normalization/relationship code.

The proposed server/API integration is documented in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).
It is a plan; the integration is not implemented in this repository.

## Run

Python 3.12+ and Node 24+ are required. From the repository directory, prepare a fresh checkout:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

Skip copying `.env.example` if you already have a configured `.env`.

1. Edit `.env` and paste your matching provider key. The file is private and gitignored.

```dotenv
AI_PROVIDER=groq
AI_MODEL=openai/gpt-oss-120b
GROQ_API_KEY=your_key_here
AI_MAX_PACKETS=10
```

For OpenAI, use `AI_PROVIDER=openai`, a supported Responses model ID in `AI_MODEL`,
and `OPENAI_API_KEY`. No key is copied from the previous app.

2. Run your supplied file:

```sh
.venv/bin/python engine.py \
  --input "/absolute/path/to/your.log" \
  --output runs/firex-50g
```

Choose a new output directory for each run. Repeat `--input` for multiple supplied files.
AI is required and enabled by default: a missing key or failed provider health check
stops the command before expensive ingestion. API keys are not printed or added to reports.

Supported inputs: FortiGate key/value logs, Windows/ECS-style JSONL/NDJSON, CSV, and gzip.
The engine streams the file into disk-backed storage. Invalid spans are counted and
excluded; use `--strict` to stop instead. Original files are unchanged; no missing data
is reconstructed. Gzip is decoded into an output snapshot for exact decoded-byte locators.

## Output

| File | Contents |
|---|---|
| `summary.json` | Final counts, coverage, incidents, AI scope, token usage, timing and limits |
| `progress.json` | Current phase and ingestion counters |
| `findings.jsonl` | Rule findings and separately marked AI hypotheses, techniques and phases |
| `incidents.jsonl` | Correlated candidate timelines, entities, supported links and AI proposals |
| `evidence.jsonl` | Supporting source paths, checksums, record/byte locators and previews |
| `ai_reviews.jsonl` | AI decisions, rejected-response reasons and packet fingerprints |
| `rejected.jsonl` | Invalid source spans and reasons |
| `analysis.sqlite` | Complete evidence, normalized metadata, findings and relationship membership |
| `sources.json` | Input identities and checksums |

Incident previews are bounded; full membership remains in SQLite and the findings export.
Keep the input snapshots and output private: logs can contain sensitive information.

## Detection and AI

Rules identify endpoint patterns, upstream security signatures and global authentication
bursts/failures-followed-by-success. Correlation uses recorded process identity, sessions
and supported relationships across files. ATT&CK tactics and proposed Lockheed Martin
phases are separate. Blocked observations do not prove successful exploitation.

AI reviews selected high-priority candidates **and unflagged discovery windows**. Each
packet contains at most six sanitized previews of 800 characters plus bounded facts and
a technique catalog. IDs and quotes are checked; a second model pass reviews support.
Accepted AI results remain hypotheses and cannot overwrite the rule findings.

The complete file is parsed, but AI coverage is bounded by `AI_MAX_PACKETS` (default 10).
The request budget is one health call plus twice that value, including retry attempts.
Increasing the budget increases provider usage/cost; this is not exhaustive LLM inspection
of every record. No 85–90% accuracy claim is made without matching held-out evaluation.

No additional test cases are generated. Superseded helpers, debug logs and synthetic
benchmarks were removed. Useful previous results are preserved separately under
`../outputs/backend-fusion-previous-results`. Keep `bridge.ts`, `rules.json`, `vendor/`
and the upstream notices alongside `engine.py`.
