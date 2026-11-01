import pytest

from netview.core.request_replay import RequestReplayError, send_loopback_request


def test_rejects_non_loopback_target():
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    with pytest.raises(RequestReplayError, match="loopback"):
        send_loopback_request("192.0.2.1", 80, request)


def test_rejects_hostname_other_than_localhost():
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    with pytest.raises(RequestReplayError, match="localhost"):
        send_loopback_request("example.com", 80, request)


def test_rejects_http_response():
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    with pytest.raises(RequestReplayError, match="Only HTTP requests"):
        send_loopback_request("127.0.0.1", 80, response)


def test_rejects_oversized_request():
    request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" + b"x" * 70000
    with pytest.raises(RequestReplayError, match="64 KiB"):
        send_loopback_request("127.0.0.1", 80, request)
