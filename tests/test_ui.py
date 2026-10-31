from pathlib import Path

from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from api.config import Settings
from api.main import create_app
from scripts.demo import create_demo


def test_ui_import_and_investigate(monkeypatch, tmp_path):
    manifest = create_demo(tmp_path / "input")
    settings = Settings(import_root=manifest.parent, data_root=tmp_path / "app")
    with TestClient(create_app(settings)) as client:
        def request(method, url, **kwargs):
            kwargs.pop("timeout", None)
            return client.request(method, url.replace("http://127.0.0.1:8000", ""), **kwargs)
        monkeypatch.setattr("httpx.request", request)
        at = AppTest.from_file(Path("ui/app.py").resolve(), default_timeout=20).run()
        assert not at.exception
        at.text_input[0].set_value(str(manifest)).run()
        at.button[0].click().run()
        assert not at.exception
        at.sidebar.radio[0].set_value("Runs").run()
        assert not at.exception
        at.sidebar.radio[0].set_value("Incidents").run()
        assert not at.exception
        assert any("matching incidents" in str(c.value) for c in at.caption)
        at.sidebar.radio[0].set_value("Investigation").run()
        assert not at.exception
        assert any("Suspicious scripting" in s.value for s in at.subheader)
        for view in ["Timeline", "Graph", "Evidence", "Next targets", "Data quality", "Report"]:
            next(r for r in at.radio if r.label == "Investigation view").set_value(view).run()
            assert not at.exception


def test_ui_empty_result(monkeypatch, tmp_path):
    manifest = create_demo(tmp_path / "input", count=0)
    settings = Settings(import_root=manifest.parent, data_root=tmp_path / "app")
    with TestClient(create_app(settings)) as client:
        def request(method, url, **kwargs):
            kwargs.pop("timeout", None)
            return client.request(method, url.replace("http://127.0.0.1:8000", ""), **kwargs)
        monkeypatch.setattr("httpx.request", request)
        at = AppTest.from_file(Path("ui/app.py").resolve(), default_timeout=20).run()
        assert not at.exception
        at.text_input[0].set_value(str(manifest)).run()
        at.button[0].click().run()
        at.sidebar.radio[0].set_value("Incidents").run()
        assert any("zero detected incidents" in str(info.value) for info in at.info)
        at.sidebar.radio[0].set_value("Investigation").run()
        assert any("zero detected incidents" in str(info.value) for info in at.info)
