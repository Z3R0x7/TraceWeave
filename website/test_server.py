import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from website import server


class AnalysisBridgeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runs = mock.patch.object(server, "RUNS", Path(self.temp.name))
        self.runs.start()
        with server.JOB_LOCK:
            server.ANALYSIS.clear()
            server.ANALYSIS["status"] = "idle"

    def tearDown(self):
        self.runs.stop()
        self.temp.cleanup()

    def test_uploaded_log_runs_existing_engine_and_loads_its_output(self):
        payload = b'date=2026-01-01 time=00:00:00 srcip=10.0.0.1\n'
        job = server.create_analysis([{"name": "../../firewall.log", "size": len(payload)}])
        server.receive_analysis_file(job["id"], 0, io.BytesIO(payload), len(payload))
        with server.JOB_LOCK:
            uploaded = server.ANALYSIS["files"][0]["_path"]
            output = server.ANALYSIS["_output"]
            server.ANALYSIS["status"] = "queued"

        def complete(command, **kwargs):
            output.mkdir()
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.object(server.subprocess, "run", side_effect=complete) as run, mock.patch.object(
            server, "load_dataset", return_value={"id": "loaded-output"}
        ) as load:
            server.run_analysis(job["id"])

        self.assertEqual(uploaded.name, "00_firewall.log")
        self.assertEqual(uploaded.read_bytes(), payload)
        self.assertEqual(server.analysis_status()["status"], "completed")
        self.assertEqual(server.analysis_status()["output"], str(output))
        self.assertIn(str(uploaded), run.call_args.args[0])
        load.assert_called_once_with(output)

    def test_active_upload_cannot_be_replaced_or_cancelled_mid_write(self):
        job = server.create_analysis([{"name": "firewall.log", "size": 10}])
        with self.assertRaises(RuntimeError):
            server.create_analysis([{"name": "other.log", "size": 10}])

        with server.JOB_LOCK:
            server.ANALYSIS["files"][0]["receiving"] = True
        with self.assertRaises(RuntimeError):
            server.cancel_analysis(job["id"])
        with server.JOB_LOCK:
            server.ANALYSIS["files"][0].pop("receiving")

        self.assertEqual(server.cancel_analysis(job["id"])["status"], "cancelled")
        replacement = server.create_analysis([{"name": "other.log", "size": 10}])
        self.assertNotEqual(replacement["id"], job["id"])

    def test_output_activation_failure_is_recorded_in_engine_log(self):
        payload = b"{}\n"
        job = server.create_analysis([{"name": "events.jsonl", "size": len(payload)}])
        server.receive_analysis_file(job["id"], 0, io.BytesIO(payload), len(payload))
        with server.JOB_LOCK:
            output = server.ANALYSIS["_output"]
            log = server.ANALYSIS["_log"]
            server.ANALYSIS["status"] = "queued"

        def complete(command, **kwargs):
            output.mkdir()
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.object(server.subprocess, "run", side_effect=complete), mock.patch.object(
            server, "load_dataset", side_effect=ValueError("invalid generated artifact")
        ):
            server.run_analysis(job["id"])

        self.assertEqual(server.analysis_status()["status"], "failed")
        self.assertIn("Viewer activation failed: invalid generated artifact", log.read_text())


if __name__ == "__main__":
    unittest.main()
