# TraceWeave — Run Guide

## Validation status

The engine supports bounded-memory, disk-backed processing and configurable resources for larger files. Complete 30 GB and 50 GB runs have **not been validated**. Current real-data validation covers the first 10,000 official records; automated tests cover parsing, detection, correlation and application handoff. The supplied source contains unsupported binary data, so a full analysis requires a valid replacement or an explicitly partial recovery run.

## Requirements

- Python 3.12 on Linux or macOS.
- Internet access to install dependencies; optional internet/API credentials for AI review.
- Writable disk space for inputs, normalized data, results, and temporary query files.
- Alternatively, Docker with its engine running.

## Run with Python

```bash
git clone https://github.com/Z3R0x7/TraceWeave.git
cd TraceWeave/engine
python3 -m pip install --target .deps -r requirements.lock.txt
python3 engine.py
```

No virtual environment is required. The script finds dependencies in `.deps` automatically. The interactive menu can check resources, inspect input, configure and analyze logs, list results, or display one incident. Hidden keys entered in the menu are held only for that process and are never saved.

## Primary official dataset

The primary dataset is the hackathon-provided FortiGate-style `firex` log family. Copy or mount your official file privately; raw logs are not included in this repository.

From `TraceWeave/engine`:

```bash
python3 engine.py audit --input /path/to/firex-10G.log
python3 engine.py inspect --input /path/to/firex-10G.log
python3 engine.py analyze --input /path/to/verified-firex.log --input-format fortigate --output runs/official
```

Use a new output directory per run. Default `auto` detects FortiGate records or ECS JSON per line. Unsupported binary input stops analysis explicitly rather than silently excluding an unknown section. Resolve the supplied file's binary sections and timestamp discrepancy before claiming a complete-tier run. See `engine/DATASET_POLICY.md` for validation status.

## Generate secondary regression logs

Run from `TraceWeave/engine`:

```bash
python3 tools/edr_log_generator.py --count 10000 --output file --file data/input/sample.jsonl --rate 0 --seed 42
```

The generator appends to an existing output file. Use a new filename for an independent run. Its random events test ingestion and detections; use the connected fixture below to exercise a linked timeline.

## Analyze and inspect results

```bash
python3 engine.py doctor
python3 engine.py inspect --input data/input/sample.jsonl
python3 engine.py analyze --input data/input/sample.jsonl --output runs/sample --demo-indicators
python3 engine.py incidents --run runs/sample --sort severity
python3 engine.py show --run runs/sample --incident <incident-id-from-list>
python3 engine.py validate --run runs/sample
```

Replace `<incident-id-from-list>` with an actual ID. Each analysis requires a new output directory. Input is uncompressed FortiGate key=value records or ECS-like JSON lines. Other text formats, CEF, JSON arrays and compressed/binary input are not accepted.

`--demo-indicators` enables only the supplied generator's synthetic test destinations. Omit it for other datasets; configure real indicators explicitly.

## Run the connected fixture

```bash
python3 tools/make_scenario.py --output data/input/connected
python3 engine.py analyze --input data/input/connected --output runs/connected --demo-indicators
python3 engine.py incidents --run runs/connected
python3 engine.py validate --run runs/connected
```

This fixture is team-authored, not organizer ground truth.

## Change processing settings

Automatic resource selection is the default. Override settings when needed:

```bash
python3 engine.py analyze --input data/input/sample.jsonl --output runs/manual --demo-indicators --profile conservative --memory-gb 2 --threads 2 --batch-records 5000 --spill-gb 20
```

The memory option controls the database budget, not total application memory. Inspect all options with `python3 engine.py analyze --help`. Use `python3 engine.py configure` to save non-secret settings, then pass `--config <settings-file>` to later commands. No API key is saved in that file.

## Optional AI review

The engine works without AI keys. For external AI review, use only data you are permitted to send to the selected provider. Supply credentials in the same terminal session, using hidden entry:

```bash
python3 engine.py
```

Choose **3. Configure and analyze**, select `groq` or `openai`, enter a model available to your account, and provide the hidden key.

For automated review, set `GROQ_API_KEY` or `OPENAI_API_KEY` privately in the process environment, then run:

```bash
python3 engine.py review --run runs/sample --ai-provider groq --ai-model openai/gpt-oss-120b --ai-max-reviews 5
python3 engine.py review --run runs/sample --ai-provider openai --ai-model <available-model-id> --ai-max-reviews 5
```

Use the command for your configured provider. Missing keys or failed requests leave baseline findings usable. `.env.example` lists variable names; the script does not automatically load `.env` files. Do not commit credentials.

Reviews examine up to 20 primary evidence records and 10 related candidate records within a five-minute window, subject to the configured input limit. Candidate retrieval uses shared hosts, accounts or source/destination pairs. It does not establish causality. Each suggested mapping and connection is checked against the evidence packet and the supplied technique reference. Responses are cached by packet/model; reviews never replace the baseline graph.

Use `show` to read the explanation. Clean machine-readable summaries are saved in `runs/<run>/briefs/<incident-id>.json`; detailed records remain in `incidents/`. The brief separates observations, engine connections, AI suggestions, missing evidence and input coverage. Re-run the adapter into a **new handoff directory** after AI review to expose updated results in the UI. AI reviews automatically increase changed bundle revisions for re-import.

For an explicitly partial analysis of a damaged file, add `--recover-valid-prefix` to `analyze`. This excludes everything from the damaged record onward and reports excluded bytes. It is not a complete-tier benchmark.

## Run with Docker

From `TraceWeave/engine`:

```bash
docker build -t traceweave-engine .
mkdir -p runs
docker run --rm --user "$(id -u):$(id -g)" --memory=8g --cpus=4 -v "$PWD/data/input:/data/input:ro" -v "$PWD/runs:/data/output" traceweave-engine analyze --input /data/input/sample.jsonl --output /data/output/sample --demo-indicators
```

Generate the sample first. Ensure the selected user can write the output mount. For interactive mode, use `docker run -it` with appropriate mounts and the `menu` command. Docker packaging requires independent verification on your machine.

## Application integration

Launch the engine as a background subprocess with an argument list:

```text
python3 engine.py analyze --input <dataset> --output <new-run-directory> --job-id <job-id> --quiet
```

Read `progress.v1.json` during processing and `manifest.v1.json` after completion. The manifest points to incident summaries, individual incident bundles, evidence, and access-history outputs. See [engine/CONTRACT.md](engine/CONTRACT.md) and the JSON Schemas under `engine/contracts/` for exact inputs and outputs. Use the adapter below to translate these artifacts into the included application contract.

## Investigation Application (UI, FR-6 & Reporting)

The investigation application provides the analyst workstation for exploring incidents, navigating timeline events, inspecting entity graphs, running FR-6 look-ahead reachability, and generating AI or deterministic reports.

> See [EXPLANATION.md](EXPLANATION.md) for the complete architecture guide and codebase walkthrough.

### Run with Docker Compose

```bash
docker compose up --build
```

- Web UI: http://localhost:8501
- API Documentation: http://localhost:8000/docs

### Run Locally with Python

```bash
python3 -m pip install --target .app-deps -e '.[dev]'
export PYTHONPATH="$PWD/.app-deps:$PWD/engine/.deps:$PWD"

# Terminal 1: FastAPI Backend
python3 -m uvicorn api.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Streamlit Frontend
python3 -m streamlit run ui/app.py --server.port=8501 --browser.gatherUsageStats=false
```

### Ingesting Engine Outputs

To adapt an engine run into the application:

```bash
python scripts/adapt_engine.py engine/runs/sample data/input/sample
```

Then on the web UI Import page, enter `sample/manifest.json`.

### Run Application Tests

```bash
pytest --cov=api --cov-report=term-missing
pyright
ruff check api ui scripts tests
```

## Run Engine Tests

From `TraceWeave/engine`:

```bash
python3 -m unittest discover -s tests -v
```
