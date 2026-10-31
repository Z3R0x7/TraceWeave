"""Bounded file transfer with an explicit HTTPS trust boundary."""

import hashlib
import http.client
import ipaddress
import socket
import ssl
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from api.config import Settings
from api.contracts import Artifact


class ImportFailure(ValueError):
    pass


def inside(root: Path, name: str) -> Path:
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ImportFailure("Path escapes configured import root")
    return path


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str):
        self.tls_context = ssl.create_default_context()
        super().__init__(host, timeout=30, context=self.tls_context)
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, 443), timeout=self.timeout)
        try:
            self.sock = self.tls_context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


class Transfer:
    def __init__(self, settings: Settings, source: str, remote: bool, progress=None):
        self.settings, self.source, self.remote = settings, source, remote
        self.original_source = source
        self.progress = progress
        self.host = urlsplit(source).hostname if remote else None
        if not remote:
            self.source = str(inside(settings.import_root, source))

    def resolve_url(self, location: str) -> str:
        url = urljoin(self.source, location)
        parsed = urlsplit(url)
        if ".." in unquote(urlsplit(location).path).split("/"):
            raise ImportFailure("Remote path traversal is not allowed")
        if (parsed.scheme != "https" or parsed.hostname != self.host
                or parsed.hostname not in self.settings.approved_hosts
                or parsed.username or parsed.password or parsed.port not in (None, 443)
                or parsed.fragment):
            raise ImportFailure("Remote URL must use HTTPS on the same approved host")
        return url

    def fetch(self, location: str, destination: Path, artifact: Artifact | None = None,
              limit: int | None = None):
        limit = limit or self.settings.max_artifact_bytes
        digest, count = hashlib.sha256(), 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        connection = None
        if self.remote:
            url = self.resolve_url(location)
            parsed = urlsplit(url)
            addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
                raise ImportFailure("Remote host resolves to a non-public address")
            connection = PinnedHTTPS(str(parsed.hostname), str(addresses[0][4][0]))
            request_path = parsed.path or "/"
            if parsed.query:
                request_path += "?" + parsed.query
            connection.request("GET", request_path)
            source = connection.getresponse()
            if source.status != 200:
                connection.close()
                raise ImportFailure("Remote download failed; redirects are not followed")
        else:
            name = self.source if location == self.original_source else str(
                Path(self.source).parent / location
            )
            source_path = inside(self.settings.import_root, name)
            source = source_path.open("rb")
        try:
            with source, destination.open("wb") as output:
                while chunk := source.read(1024 * 1024):
                    count += len(chunk)
                    if count > limit:
                        raise ImportFailure("Artifact exceeds configured size limit")
                    output.write(chunk)
                    digest.update(chunk)
                    if self.progress:
                        self.progress(len(chunk))
            if artifact:
                if artifact.size_bytes is not None and artifact.size_bytes != count:
                    raise ImportFailure("Artifact size mismatch")
                if artifact.sha256 and digest.hexdigest() != artifact.sha256.lower():
                    raise ImportFailure("Artifact checksum mismatch")
        finally:
            if connection:
                connection.close()
