import hashlib
import io
import socket
from urllib.parse import urlsplit

import pytest

from api.config import Settings
from api.contracts import Artifact
from api.transfer import ImportFailure, Transfer


def test_streaming_size_and_checksum(tmp_path):
    data = b"a" * (3 * 1024 * 1024)
    (tmp_path / "file").write_bytes(data)
    transfer = Transfer(Settings(import_root=tmp_path), "manifest.json", False)
    artifact = Artifact(location="file", sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
    transfer.fetch("file", tmp_path / "copy", artifact)
    assert (tmp_path / "copy").stat().st_size == len(data)
    with pytest.raises(ImportFailure, match="size limit"):
        transfer.fetch("file", tmp_path / "copy2", limit=10)


def test_symlink_escape(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside").write_text("secret")
    (root / "link").symlink_to(tmp_path / "outside")
    transfer = Transfer(Settings(import_root=root), "manifest.json", False)
    with pytest.raises(ImportFailure):
        transfer.fetch("link", root / "copy")


@pytest.mark.parametrize("url", ["http://engine.example/file", "https://other.example/file",
                                      "https://user:password@engine.example/file",
                                      "https://engine.example:8080/file"])
def test_remote_url_policy(tmp_path, url):
    transfer = Transfer(Settings(approved_hosts=("engine.example",)),
                        "https://engine.example/manifest.json", True)
    with pytest.raises(ImportFailure):
        transfer.fetch(url, tmp_path / "copy")


def test_private_dns_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    ])
    transfer = Transfer(Settings(approved_hosts=("engine.example",)),
                        "https://engine.example/manifest.json", True)
    with pytest.raises(ImportFailure, match="non-public"):
        transfer.fetch("file", tmp_path / "copy")


def remote_fixture(monkeypatch, directory, status=200):
    class Response(io.BytesIO):
        status: int

    class Connection:
        def __init__(self, host, address):
            assert address == "8.8.8.8"

        def request(self, method, path):
            self.path = urlsplit(path).path.removeprefix("/output/")

        def getresponse(self):
            response = Response((directory / self.path).read_bytes())
            response.status = status
            return response

        def close(self):
            pass

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
    ])
    monkeypatch.setattr("api.transfer.PinnedHTTPS", Connection)


def test_remote_equivalent_to_local(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from api.main import create_app
    from scripts.demo import create_demo
    directory = tmp_path / "source"
    create_demo(directory)
    remote_fixture(monkeypatch, directory)
    settings = Settings(data_root=tmp_path / "app", approved_hosts=("engine.example",))
    with TestClient(create_app(settings)) as client:
        job = client.post("/api/v1/imports/remote", json={
            "manifest_url": "https://engine.example/output/manifest.json?signature=hidden"
        }).json()
        assert client.get("/api/v1/imports/" + job["import_id"]).json()["status"] == "completed"
        assert client.get("/api/v1/runs/demo_run/incidents").json()["total"] == 1


def test_redirect_rejected(monkeypatch, tmp_path):
    (tmp_path / "manifest.json").write_text("{}")
    remote_fixture(monkeypatch, tmp_path, status=302)
    transfer = Transfer(Settings(approved_hosts=("engine.example",)),
                        "https://engine.example/output/manifest.json", True)
    with pytest.raises(ImportFailure, match="redirects"):
        transfer.fetch(transfer.source, tmp_path / "out")
