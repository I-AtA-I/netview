from netview.core import PacketRecord, dissect_ethernet_frame, process_packet
from netview.filters import compile_filter

from tests.test_dns import encode_name, make_query, make_response
from tests.test_tls import make_client_hello


DST = bytes.fromhex("aabbccddeeff")
SRC = bytes.fromhex("112233445566")


def make_udp_segment(source_port, destination_port, payload):
    length = 8 + len(payload)
    return (
        source_port.to_bytes(2, "big")
        + destination_port.to_bytes(2, "big")
        + length.to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )


def make_tcp_segment(source_port, destination_port, payload, flags=0x18):
    header = bytearray(20)
    header[0:2] = source_port.to_bytes(2, "big")
    header[2:4] = destination_port.to_bytes(2, "big")
    header[4:8] = (1000).to_bytes(4, "big")
    header[8:12] = (0).to_bytes(4, "big")
    header[12] = 0x50
    header[13] = flags
    header[14:16] = (4096).to_bytes(2, "big")
    return bytes(header) + payload


def make_ipv4_frame(transport, protocol):
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = (20 + len(transport)).to_bytes(2, "big")
    ip[8] = 64
    ip[9] = protocol
    ip[12:16] = bytes([192, 0, 2, 10])
    ip[16:20] = bytes([198, 51, 100, 20])
    return DST + SRC + b"\x08\x00" + bytes(ip) + transport


def dissect(frame):
    return dissect_ethernet_frame(frame)


def processed(frame):
    record = PacketRecord(
        number=1,
        timestamp=1234.5,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    )
    return process_packet(record)


def test_udp_dns_query_dissection_and_filter():
    frame = make_ipv4_frame(make_udp_segment(53000, 53, make_query()), 17)
    result = dissect(frame)

    assert result.protocol == "DNS"
    assert result.protocol_stack == ("Ethernet II", "IPv4", "UDP", "DNS")
    assert result.dns.query_name == "example.com"

    packet = processed(frame)
    assert packet.info == "query example.com A"
    assert compile_filter("dns").matches(packet)
    assert compile_filter("dns.qry.name == EXAMPLE.COM").matches(packet)
    assert compile_filter("dns.qry.type == 1").matches(packet)
    assert compile_filter("dns.flags.response == false").matches(packet)


def test_udp_dns_response_has_answer_summary():
    frame = make_ipv4_frame(make_udp_segment(53, 53000, make_response()), 17)
    packet = processed(frame)

    assert packet.protocol == "DNS"
    assert packet.dissection.dns.is_response is True
    assert packet.info == "response example.com A → 93.184.216.34"
    assert compile_filter("dns.rcode == 0").matches(packet)
    assert compile_filter("dns.flags.response == true").matches(packet)


def test_mdns_is_identified_separately():
    frame = make_ipv4_frame(make_udp_segment(5353, 5353, make_query("printer.local")), 17)
    packet = processed(frame)

    assert packet.protocol == "mDNS"
    assert packet.dissection.dns.query_name == "printer.local"
    assert compile_filter("dns").matches(packet)
    assert compile_filter("mdns").matches(packet)
    assert not compile_filter("llmnr").matches(packet)


def test_dns_over_tcp_is_dissected():
    message = make_query("tcp-dns.example")
    payload = len(message).to_bytes(2, "big") + message
    frame = make_ipv4_frame(make_tcp_segment(53000, 53, payload), 6)
    packet = processed(frame)

    assert packet.protocol == "DNS"
    assert packet.dissection.dns.tcp_framed is True
    assert packet.dissection.dns.query_name == "tcp-dns.example"
    assert packet.info == "query tcp-dns.example A"


def test_http_request_dissection_and_filter():
    http = (
        b"GET /status HTTP/1.1\r\n"
        b"Host: status.example.test\r\n"
        b"Accept: */*\r\n\r\n"
    )
    frame = make_ipv4_frame(make_tcp_segment(51000, 80, http), 6)
    packet = processed(frame)

    assert packet.protocol == "HTTP"
    assert packet.dissection.http.method == "GET"
    assert packet.dissection.http.host == "status.example.test"
    assert packet.info == "GET /status Host=status.example.test"
    assert compile_filter("http").matches(packet)
    assert compile_filter("http.host == STATUS.EXAMPLE.TEST").matches(packet)
    assert compile_filter("http.request.method == get").matches(packet)
    assert compile_filter("http.request.uri == /status").matches(packet)


def test_http_response_dissection_and_filter():
    http = b"HTTP/1.1 204 No Content\r\nServer: netview-test\r\n\r\n"
    frame = make_ipv4_frame(make_tcp_segment(80, 51000, http), 6)
    packet = processed(frame)

    assert packet.protocol == "HTTP"
    assert packet.dissection.http.status_code == 204
    assert packet.info == "HTTP/1.1 204 No Content"
    assert compile_filter("http.response.code == 204").matches(packet)


def test_tls_client_hello_sni_alpn_and_filter():
    frame = make_ipv4_frame(make_tcp_segment(51000, 443, make_client_hello()), 6)
    packet = processed(frame)

    assert packet.protocol == "TLS"
    assert packet.dissection.tls.client_hello.server_name == "example.com"
    assert packet.dissection.tls.client_hello.alpn_protocols == ("h2", "http/1.1")
    assert packet.info.startswith("Client Hello SNI=example.com ALPN=h2,http/1.1")
    assert compile_filter("tls").matches(packet)
    assert compile_filter("tls.sni == example.com").matches(packet)
    assert compile_filter("tls.handshake.type == 1").matches(packet)
    assert compile_filter("tls.record.content_type == 22").matches(packet)


def test_tls_application_data_is_recognized_without_decryption():
    record = b"\x17\x03\x03\x00\x04data"
    frame = make_ipv4_frame(make_tcp_segment(443, 51000, record), 6)
    packet = processed(frame)

    assert packet.protocol == "TLS"
    assert packet.dissection.tls.content_type_name == "Application Data"
    assert packet.dissection.tls.client_hello is None
    assert "Application Data" in packet.info


def test_non_application_tcp_payload_remains_tcp():
    frame = make_ipv4_frame(make_tcp_segment(50000, 50001, b"plain bytes"), 6)
    packet = processed(frame)

    assert packet.protocol == "TCP"
    assert packet.dissection.dns is None
    assert packet.dissection.http is None
    assert packet.dissection.tls is None
    assert not compile_filter("http or tls or dns").matches(packet)


def test_http_uri_filter_supports_quoted_query_string():
    from netview.filters import compile_filter

    http = b"GET /search?q=netview%20analyzer HTTP/1.1\r\nHost: example.test\r\n\r\n"
    packet = processed(make_ipv4_frame(make_tcp_segment(51000, 80, http), 6))
    assert compile_filter('http.request.uri == "/search?q=netview%20analyzer"').matches(packet)
