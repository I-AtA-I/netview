from netview.core import parse_http_message, looks_like_http


def test_parse_http_request_metadata():
    payload = (
        b"GET /index.html?q=netview HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: NetViewTest/1.0\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 12\r\n"
        b"Cookie: session=secret\r\n"
        b"Authorization: Bearer secret-token\r\n"
        b"\r\nhello world!"
    )

    assert looks_like_http(payload)
    message = parse_http_message(payload)

    assert message.is_request is True
    assert message.method == "GET"
    assert message.target == "/index.html?q=netview"
    assert message.version == "HTTP/1.1"
    assert message.host == "example.com"
    assert message.content_type == "text/plain"
    assert message.content_length == 12
    assert message.headers_complete is True
    assert message.header_count == 6
    assert not hasattr(message, "cookie")
    assert not hasattr(message, "authorization")


def test_parse_http_response():
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: example-server\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: 42\r\n"
        b"\r\n<html></html>"
    )

    message = parse_http_message(payload)

    assert message.is_request is False
    assert message.status_code == 200
    assert message.reason == "OK"
    assert message.server == "example-server"
    assert message.content_type == "text/html; charset=utf-8"
    assert message.content_length == 42
    assert message.headers_complete is True


def test_parse_partial_http_headers():
    payload = b"GET /partial HTTP/1.0\r\nHost: example.test\r\n"

    message = parse_http_message(payload)

    assert message.is_request is True
    assert message.target == "/partial"
    assert message.host == "example.test"
    assert message.headers_complete is False


def test_non_http_payload_is_not_detected():
    assert looks_like_http(b"\x16\x03\x01\x00\x10") is False
