from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.request import ProxyHandler, build_opener

import pytest

from netview.core.proxy import HTTPProxy


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"origin response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        opener = build_opener(ProxyHandler({"http": f"http://{host}:{port}"}))
        response = opener.open(f"http://127.0.0.1:{origin}/check", timeout=3)
        assert response.read() == b"origin response"
        entries = proxy.history
        assert len(entries) == 1
        assert entries[0].method == "GET"
        assert entries[0].status == 200
        assert entries[0].url.endswith("/check")
        assert entries[0].response_bytes == len(b"origin response")
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
    assert len(proxy.history) == 500
