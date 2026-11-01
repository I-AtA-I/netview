from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from socket import create_connection

import pytest

from netview.core.proxy import HTTPProxy


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"origin response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        response = b"echo:" + body
        self.send_response(201)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        return


@pytest.fixture
def origin():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_proxy_forwards_http_and_records_metadata(origin):
    proxy = HTTPProxy(port=0)
    host, port = proxy.start()
    try:
        with create_connection((host, port), timeout=3) as client:
            client.sendall(
                f"GET http://127.0.0.1:{origin}/check HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin}\r\nConnection: close\r\n\r\n".encode()
            )
            response = bytearray()
            while chunk := client.recv(4096):
                response.extend(chunk)
        assert b"200 OK" in response
        assert response.endswith(b"origin response")
        entries = proxy.history
        assert len(entries) == 1
        assert entries[0].method == "GET"
        assert entries[0].status == 200
        assert entries[0].url.endswith("/check")
        assert entries[0].response_bytes == len(b"origin response")
        assert b"GET http://127.0.0.1" in entries[0].request_message
        assert b"origin response" in entries[0].response_message
    finally:
        proxy.stop()


def test_proxy_only_binds_loopback():
    with pytest.raises(ValueError, match="loopback"):
        HTTPProxy(host="0.0.0.0")


def test_proxy_history_is_bounded():
    proxy = HTTPProxy()
    for index in range(510):
        from netview.core.proxy import ProxyEntry
        proxy._record(ProxyEntry(index, "GET", "/", 200, (), 0, 0))
    assert len(proxy.history) == 100



def test_proxy_captures_request_and_response_bodies(origin):
    proxy = HTTPProxy(port=0)
    host, port = proxy.start()
    body = b'{"hello":"netview"}'
    try:
        with create_connection((host, port), timeout=3) as client:
            client.sendall(
                f"POST http://127.0.0.1:{origin}/echo HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{origin}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n".encode() + body
            )
            response = bytearray()
            while chunk := client.recv(4096):
                response.extend(chunk)
        assert b"201 Created" in response
        entry = proxy.history[-1]
        assert body in entry.request_message
        assert b"echo:" + body in entry.response_message
        assert "Content-Type" in entry.request_headers
    finally:
        proxy.stop()


def test_proxy_history_clear_releases_captured_messages():
    from netview.core.proxy import ProxyEntry

    proxy = HTTPProxy()
    proxy._record(ProxyEntry(1, "GET", "/", 200, (), 0, 0, request_message=b"request"))
    proxy.clear_history()
    assert proxy.history == ()
    assert proxy._history_bytes == 0
