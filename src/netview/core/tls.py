from dataclasses import dataclass


class TLSParseError(ValueError):
    pass


CONTENT_TYPES = {
    20: "Change Cipher Spec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
    24: "Heartbeat",
}

HANDSHAKE_TYPES = {
    0: "Hello Request",
    1: "Client Hello",
    2: "Server Hello",
    4: "New Session Ticket",
    8: "Encrypted Extensions",
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished",
    24: "Key Update",
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

CIPHER_NAMES = {
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
}


def tls_version_name(value: int) -> str:
    return TLS_VERSIONS.get(value, f"Unknown (0x{value:04x})")


def cipher_suite_name(value: int) -> str:
    return CIPHER_NAMES.get(value, f"Unknown (0x{value:04x})")


@dataclass(frozen=True, slots=True)
class TLSClientHello:
    legacy_version: int
    session_id_length: int
    cipher_suites: tuple[int, ...]
    compression_methods: tuple[int, ...]
    server_name: str | None
    alpn_protocols: tuple[str, ...]
    supported_versions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class TLSServerHello:
    legacy_version: int
    session_id_length: int
    cipher_suite: int
    compression_method: int
    negotiated_version: int | None
    alpn_protocol: str | None


@dataclass(frozen=True, slots=True)
class TLSRecord:
    content_type: int
    legacy_version: int
    record_length: int
    captured_length: int
    is_truncated: bool
    handshake_type: int | None = None
    handshake_length: int | None = None
    handshake_is_truncated: bool = False
    client_hello: TLSClientHello | None = None
    server_hello: TLSServerHello | None = None

    @property
    def content_type_name(self) -> str:
        return CONTENT_TYPES.get(self.content_type, f"Unknown ({self.content_type})")

    @property
    def version_name(self) -> str:
        return tls_version_name(self.legacy_version)

    @property
    def handshake_name(self) -> str | None:
        if self.handshake_type is None:
            return None
        return HANDSHAKE_TYPES.get(self.handshake_type, f"Handshake {self.handshake_type}")


def looks_like_tls(data: bytes) -> bool:
    if len(data) < 5:
        return False
    content_type = data[0]
    major = data[1]
    minor = data[2]
    record_length = int.from_bytes(data[3:5], "big")
    return (
        content_type in CONTENT_TYPES
        and major == 3
        and minor <= 4
        and record_length <= 18432
    )


def _take(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    end = offset + length
    if length < 0 or end > len(data):
        raise TLSParseError(f"Truncated TLS {label}")
    return data[offset:end], end


def _parse_extensions(data: bytes, offset: int) -> tuple[dict[int, bytes], int]:
    if offset == len(data):
        return {}, offset
    raw_length, cursor = _take(data, offset, 2, "extensions length")
    total_length = int.from_bytes(raw_length, "big")
    end = cursor + total_length
    if end > len(data):
        raise TLSParseError("Truncated TLS extensions")

    extensions: dict[int, bytes] = {}
    while cursor < end:
        header, cursor = _take(data, cursor, 4, "extension header")
        ext_type = int.from_bytes(header[:2], "big")
        ext_length = int.from_bytes(header[2:4], "big")
        value, cursor = _take(data, cursor, ext_length, "extension data")
        if cursor > end:
            raise TLSParseError("TLS extension exceeds its declared block")
        extensions[ext_type] = value

    if cursor != end:
        raise TLSParseError("Malformed TLS extensions block")
    return extensions, end


def _parse_sni(data: bytes) -> str | None:
    if len(data) < 2:
        raise TLSParseError("Truncated TLS server-name extension")
    list_length = int.from_bytes(data[:2], "big")
    if list_length != len(data) - 2:
        raise TLSParseError("Invalid TLS server-name list length")
    cursor = 2
    while cursor < len(data):
        header, cursor = _take(data, cursor, 3, "server-name entry")
        name_type = header[0]
        name_length = int.from_bytes(header[1:3], "big")
        name, cursor = _take(data, cursor, name_length, "server name")
        if name_type == 0:
            return name.decode("ascii", errors="replace").rstrip(".")
    return None


def _parse_alpn(data: bytes) -> tuple[str, ...]:
    if len(data) < 2:
        raise TLSParseError("Truncated TLS ALPN extension")
    list_length = int.from_bytes(data[:2], "big")
    if list_length != len(data) - 2:
        raise TLSParseError("Invalid TLS ALPN list length")
    cursor = 2
    protocols: list[str] = []
    while cursor < len(data):
        length = data[cursor]
        cursor += 1
        if length == 0:
            raise TLSParseError("Empty TLS ALPN protocol identifier")
        raw, cursor = _take(data, cursor, length, "ALPN protocol")
        protocols.append(raw.decode("ascii", errors="replace"))
    return tuple(protocols)


def _parse_supported_versions_client(data: bytes) -> tuple[int, ...]:
    if not data:
        raise TLSParseError("Truncated supported_versions extension")
    length = data[0]
    if length != len(data) - 1 or length % 2:
        raise TLSParseError("Invalid supported_versions list")
    return tuple(
        int.from_bytes(data[index:index + 2], "big")
        for index in range(1, len(data), 2)
    )


def _parse_client_hello(body: bytes) -> TLSClientHello:
    cursor = 0
    raw, cursor = _take(body, cursor, 2, "ClientHello version")
    legacy_version = int.from_bytes(raw, "big")
    _, cursor = _take(body, cursor, 32, "ClientHello random")
    raw, cursor = _take(body, cursor, 1, "ClientHello session ID length")
    session_length = raw[0]
    if session_length > 32:
        raise TLSParseError("Invalid TLS session ID length")
    _, cursor = _take(body, cursor, session_length, "ClientHello session ID")

    raw, cursor = _take(body, cursor, 2, "cipher-suite vector length")
    cipher_length = int.from_bytes(raw, "big")
    if cipher_length == 0 or cipher_length % 2:
        raise TLSParseError("Invalid TLS cipher-suite vector length")
    raw, cursor = _take(body, cursor, cipher_length, "cipher-suite vector")
    cipher_suites = tuple(
        int.from_bytes(raw[index:index + 2], "big")
        for index in range(0, len(raw), 2)
    )

    raw, cursor = _take(body, cursor, 1, "compression-method vector length")
    compression_length = raw[0]
    if compression_length == 0:
        raise TLSParseError("Empty TLS compression-method vector")
    raw, cursor = _take(body, cursor, compression_length, "compression-method vector")
    compression_methods = tuple(raw)

    extensions, cursor = _parse_extensions(body, cursor)
    if cursor != len(body):
        raise TLSParseError("Unexpected trailing bytes in TLS ClientHello")

    server_name = _parse_sni(extensions[0]) if 0 in extensions else None
    alpn = _parse_alpn(extensions[16]) if 16 in extensions else ()
    versions = _parse_supported_versions_client(extensions[43]) if 43 in extensions else ()

    return TLSClientHello(
        legacy_version=legacy_version,
        session_id_length=session_length,
        cipher_suites=cipher_suites,
        compression_methods=compression_methods,
        server_name=server_name,
        alpn_protocols=alpn,
        supported_versions=versions,
    )


def _parse_server_hello(body: bytes) -> TLSServerHello:
    cursor = 0
    raw, cursor = _take(body, cursor, 2, "ServerHello version")
    legacy_version = int.from_bytes(raw, "big")
    _, cursor = _take(body, cursor, 32, "ServerHello random")
    raw, cursor = _take(body, cursor, 1, "ServerHello session ID length")
    session_length = raw[0]
    if session_length > 32:
        raise TLSParseError("Invalid TLS session ID length")
    _, cursor = _take(body, cursor, session_length, "ServerHello session ID")
    raw, cursor = _take(body, cursor, 3, "ServerHello cipher and compression")
    cipher_suite = int.from_bytes(raw[:2], "big")
    compression_method = raw[2]
    extensions, cursor = _parse_extensions(body, cursor)
    if cursor != len(body):
        raise TLSParseError("Unexpected trailing bytes in TLS ServerHello")

    negotiated_version = None
    if 43 in extensions:
        if len(extensions[43]) != 2:
            raise TLSParseError("Invalid ServerHello supported_versions extension")
        negotiated_version = int.from_bytes(extensions[43], "big")

    alpn_protocol = None
    if 16 in extensions:
        protocols = _parse_alpn(extensions[16])
        alpn_protocol = protocols[0] if protocols else None

    return TLSServerHello(
        legacy_version=legacy_version,
        session_id_length=session_length,
        cipher_suite=cipher_suite,
        compression_method=compression_method,
        negotiated_version=negotiated_version,
        alpn_protocol=alpn_protocol,
    )


def parse_tls_record(data: bytes) -> TLSRecord:
    if len(data) < 5:
        raise TLSParseError("TLS record header is shorter than 5 bytes")
    if not looks_like_tls(data):
        raise TLSParseError("Payload does not look like a TLS record")

    content_type = data[0]
    legacy_version = int.from_bytes(data[1:3], "big")
    record_length = int.from_bytes(data[3:5], "big")
    captured_length = min(record_length, len(data) - 5)
    is_truncated = captured_length < record_length
    record_payload = data[5:5 + captured_length]

    handshake_type = None
    handshake_length = None
    handshake_is_truncated = False
    client_hello = None
    server_hello = None

    if content_type == 22 and len(record_payload) >= 4:
        handshake_type = record_payload[0]
        handshake_length = int.from_bytes(record_payload[1:4], "big")
        if handshake_length <= len(record_payload) - 4:
            handshake_body = record_payload[4:4 + handshake_length]
            if handshake_type == 1:
                client_hello = _parse_client_hello(handshake_body)
            elif handshake_type == 2:
                server_hello = _parse_server_hello(handshake_body)
        else:
            handshake_is_truncated = True

    return TLSRecord(
        content_type=content_type,
        legacy_version=legacy_version,
        record_length=record_length,
        captured_length=captured_length,
        is_truncated=is_truncated,
        handshake_type=handshake_type,
        handshake_length=handshake_length,
        handshake_is_truncated=handshake_is_truncated,
        client_hello=client_hello,
        server_hello=server_hello,
    )
