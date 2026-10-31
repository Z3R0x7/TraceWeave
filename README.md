# TraceWeave — Run Guide

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

## Generate test logs

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

Replace `<incident-id-from-list>` with an actual ID. Each analysis requires a new output directory. Input is uncompressed, one ECS-like JSON object per line; arbitrary text logs, CEF, JSON arrays, and compressed files are not accepted.

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

Read `progress.v1.json` during processing and `manifest.v1.json` after completion. The manifest points to incident summaries, individual incident bundles, evidence, and access-history outputs. See [engine/CONTRACT.md](engine/CONTRACT.md) and the JSON Schemas under `engine/contracts/` for exact inputs and outputs. The application can be added alongside the `engine/` directory.

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
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

# Terminal 1: FastAPI Backend
uvicorn api.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Streamlit Frontend
streamlit run ui/app.py --server.port=8501 --browser.gatherUsageStats=false
```

### Ingesting Engine Outputs

To adapt an engine run into the application:

```bash
python scripts/adapt_dumbo.py engine/runs/sample data/input/sample
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
