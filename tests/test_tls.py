import pytest

from netview.core import TLSParseError, parse_tls_record, looks_like_tls


def extension(extension_type, value):
    return extension_type.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def make_client_hello():
    host = b"example.com"
    server_name_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_value = len(server_name_entry).to_bytes(2, "big") + server_name_entry

    alpn_list = b"\x02h2" + b"\x08http/1.1"
    alpn_value = len(alpn_list).to_bytes(2, "big") + alpn_list

    versions_list = b"\x03\x04\x03\x03"
    supported_versions_value = bytes([len(versions_list)]) + versions_list

    extensions = (
        extension(0, sni_value)
        + extension(16, alpn_value)
        + extension(43, supported_versions_value)
    )

    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"  # empty session ID
        + b"\x00\x04\x13\x01\x13\x03"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    return record


def make_server_hello():
    extensions = extension(43, b"\x03\x04") + extension(16, b"\x00\x03\x02h2")
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def test_parse_client_hello_metadata():
    record_bytes = make_client_hello()

    assert looks_like_tls(record_bytes) is True
    record = parse_tls_record(record_bytes)

    assert record.content_type_name == "Handshake"
    assert record.version_name == "TLS 1.0"
    assert record.is_truncated is False
    assert record.handshake_name == "Client Hello"
    assert record.client_hello.server_name == "example.com"
    assert record.client_hello.alpn_protocols == ("h2", "http/1.1")
    assert record.client_hello.supported_versions == (0x0304, 0x0303)
    assert record.client_hello.cipher_suites == (0x1301, 0x1303)


def test_parse_server_hello_metadata():
    record = parse_tls_record(make_server_hello())

    assert record.handshake_name == "Server Hello"
    assert record.server_hello.negotiated_version == 0x0304
    assert record.server_hello.alpn_protocol == "h2"
    assert record.server_hello.cipher_suite == 0x1301


def test_tls_application_data_record():
    record = parse_tls_record(b"\x17\x03\x03\x00\x03abc")

    assert record.content_type_name == "Application Data"
    assert record.is_truncated is False
    assert record.handshake_type is None


def test_tls_truncated_record_is_reported():
    record = parse_tls_record(b"\x17\x03\x03\x00\x10abc")

    assert record.is_truncated is True
    assert record.captured_length == 3


def test_tls_non_record_rejected():
    with pytest.raises(TLSParseError):
        parse_tls_record(b"hello")


def test_tls_incomplete_client_hello_is_reported_without_guessing():
    # The record is complete, but the handshake message spans more bytes
    # than this TCP segment captured.
    payload = b"\x01\x00\x00\x40\x03\x03" + b"\x00" * 5
    record_bytes = b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload
    record = parse_tls_record(record_bytes)

    assert record.handshake_name == "Client Hello"
    assert record.handshake_is_truncated is True
    assert record.client_hello is None
