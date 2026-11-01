from __future__ import annotations

from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socket import create_connection
from select import select
from threading import RLock, Thread
from time import time
from urllib.parse import urlsplit


MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_HISTORY = 500
_HOP_HEADERS = {
    "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
}
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}


@dataclass(frozen=True, slots=True)
class ProxyEntry:
    timestamp: float
    method: str
    url: str
    status: int | None
    request_headers: tuple[str, ...]
    request_bytes: int
    response_bytes: int
    note: str = ""


class ProxyError(RuntimeError):
    pass


class _ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, owner: HTTPProxy):
        self.owner = owner
        super().__init__(address, _ProxyHandler)


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NetViewProxy/0.1"

    @property
    def owner(self) -> HTTPProxy:
        return self.server.owner

    def log_message(self, _format, *_args):
        return

    def _respond_error(self, status: int, message: str) -> None:
        body = (message + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _forward(self) -> None:
        if self.headers.get("Transfer-Encoding"):
            self._respond_error(501, "Chunked request bodies are not supported yet")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._respond_error(400, "Invalid Content-Length")
            return
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._respond_error(413, "Request body exceeds the 1 MiB limit")
            return

        target = urlsplit(self.path)
        if target.scheme.lower() != "http" or not target.hostname:
            self._respond_error(400, "Use an absolute http:// URL through the proxy")
            return
        if target.username is not None or target.password is not None:
            self._respond_error(400, "Credentials in proxy URLs are not supported")
            return
        try:
            port = target.port or 80
        except ValueError:
            self._respond_error(400, "Invalid target port")
            return

        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        headers = {}
        for name, value in self.headers.items():
            lower = name.lower()
            if lower not in _HOP_HEADERS and lower not in _SENSITIVE_HEADERS and lower != "host":
                headers[name] = value
        headers["Host"] = target.netloc
        headers["Connection"] = "close"

        try:
            body = self.rfile.read(length) if length else None
            connection = HTTPConnection(target.hostname, port, timeout=8)
            try:
                connection.request(self.command, path, body=body, headers=headers)
                response = connection.getresponse()
                response_body = response.read(MAX_RESPONSE_BYTES + 1)
                truncated = len(response_body) > MAX_RESPONSE_BYTES
                response_body = response_body[:MAX_RESPONSE_BYTES]
                self.send_response(response.status, response.reason)
                for name, value in response.getheaders():
                    lower = name.lower()
                    if lower not in _HOP_HEADERS and lower not in _SENSITIVE_HEADERS and lower != "content-length":
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD" and response_body:
                    self.wfile.write(response_body)
                self.close_connection = True
                self.owner._record(ProxyEntry(
                    timestamp=time(),
                    method=self.command,
                    url=self.path,
                    status=response.status,
                    request_headers=tuple(sorted(
                        name for name in self.headers
                        if name.lower() not in _SENSITIVE_HEADERS
                    )),
                    request_bytes=length,
                    response_bytes=len(response_body),
                    note="Response truncated at 4 MiB" if truncated else "",
                ))
            finally:
                connection.close()
        except (OSError, HTTPException, ValueError) as exc:
            self.owner._record(ProxyEntry(
                timestamp=time(), method=self.command, url=self.path,
                status=None, request_headers=tuple(sorted(self.headers.keys())),
                request_bytes=length, response_bytes=0, note=str(exc)[:240],
            ))
            if not self.wfile.closed:
                try:
                    self._respond_error(502, "Upstream request failed")
                except OSError:
                    pass

    def do_CONNECT(self) -> None:
        host, separator, port_text = self.path.rpartition(":")
        if not separator or not host:
            self._respond_error(400, "Invalid CONNECT target")
            return
        try:
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise ValueError
            upstream = create_connection((host.strip("[]"), port), timeout=8)
        except (OSError, ValueError):
            self._respond_error(502, "Could not establish the CONNECT tunnel")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        self.owner._record(ProxyEntry(
            timestamp=time(), method="CONNECT", url=self.path, status=200,
            request_headers=(), request_bytes=0, response_bytes=0,
            note="Encrypted tunnel; HTTPS contents are not inspected",
        ))
        self.connection.setblocking(False)
        upstream.setblocking(False)
        try:
            sockets = (self.connection, upstream)
            while True:
                readable, _, exceptional = select(sockets, [], sockets, 30)
                if exceptional or not readable:
                    break
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = upstream if source is self.connection else self.connection
                    destination.sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            upstream.close()
            self.close_connection = True

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_PATCH = _forward
    do_DELETE = _forward
    do_HEAD = _forward
    do_OPTIONS = _forward


class HTTPProxy:
    """Local HTTP proxy with bounded metadata history and opaque HTTPS tunnels."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("NetView proxy must bind to loopback only")
        if not 0 <= port <= 65535:
            raise ValueError("Port must be between 0 and 65535")
        self.host = "127.0.0.1" if host == "localhost" else host
        self.port = port
        self._server: _ProxyServer | None = None
        self._thread: Thread | None = None
        self._history: list[ProxyEntry] = []
        self._lock = RLock()

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            return self.host, self.port
        return self.host, self._server.server_address[1]

    @property
    def history(self) -> tuple[ProxyEntry, ...]:
        with self._lock:
            return tuple(self._history)

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()

    def _record(self, entry: ProxyEntry) -> None:
        with self._lock:
            self._history.append(entry)
            del self._history[:-MAX_HISTORY]

    def start(self) -> tuple[str, int]:
        if self._server is not None:
            return self.address
        try:
            server = _ProxyServer((self.host, self.port), self)
        except OSError as exc:
            raise ProxyError(f"Could not start proxy: {exc}") from exc
        self._server = server
        self.port = server.server_address[1]
        self._thread = Thread(target=server.serve_forever, name="NetViewProxy", daemon=True)
        self._thread.start()
        return self.address

    def stop(self) -> None:
        server, thread = self._server, self._thread
        if server is None:
            return
        self._server = None
        self._thread = None
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=3)
