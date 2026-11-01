import pytest

from netview.core import DNSParseError, parse_dns_message


def encode_name(name):
    if name == ".":
        return b"\x00"
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\x00"


def make_query(name="example.com", qtype=1):
    return (
        b"\x12\x34"  # transaction ID
        + b"\x01\x00"  # standard query, recursion desired
        + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        + encode_name(name)
        + qtype.to_bytes(2, "big")
        + b"\x00\x01"
    )


def make_response():
    question = encode_name("example.com") + b"\x00\x01\x00\x01"
    answer = (
        b"\xc0\x0c"  # compression pointer to question name
        + b"\x00\x01\x00\x01"
        + b"\x00\x00\x00\x3c"
        + b"\x00\x04"
        + bytes([93, 184, 216, 34])
    )
    return (
        b"\x12\x34"
        + b"\x81\x80"
        + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        + question
        + answer
    )


def test_parse_dns_query():
    dns = parse_dns_message(make_query())

    assert dns.transaction_id == 0x1234
    assert dns.is_response is False
    assert dns.recursion_desired is True
    assert dns.query_name == "example.com"
    assert dns.questions[0].type_name == "A"
    assert dns.questions[0].qclass == 1
    assert dns.answers == ()


def test_parse_dns_response_with_compressed_answer():
    dns = parse_dns_message(make_response())

    assert dns.is_response is True
    assert dns.rcode == 0
    assert dns.rcode_name == "NoError"
    assert dns.query_name == "example.com"
    assert len(dns.answers) == 1
    assert dns.answers[0].name == "example.com"
    assert dns.answers[0].type_name == "A"
    assert dns.answers[0].data == "93.184.216.34"
    assert dns.answers[0].ttl == 60


def test_parse_dns_over_tcp_length_prefix():
    message = make_query("netview.local")
    framed = len(message).to_bytes(2, "big") + message

    dns = parse_dns_message(framed, tcp_framed=True)

    assert dns.tcp_framed is True
    assert dns.query_name == "netview.local"
    assert dns.message_length == len(message)


def test_dns_tcp_truncated_frame():
    message = make_query()
    framed = (len(message) + 10).to_bytes(2, "big") + message

    with pytest.raises(DNSParseError, match="Truncated"):
        parse_dns_message(framed, tcp_framed=True)


def test_dns_name_pointer_loop_is_rejected():
    message = bytearray(b"\x00" * 12)
    message[4:6] = b"\x00\x01"
    message.extend(b"\xc0\x0c\x00\x01\x00\x01")

    with pytest.raises(DNSParseError, match="loop"):
        parse_dns_message(bytes(message))


def test_dns_short_header_is_rejected():
    with pytest.raises(DNSParseError):
        parse_dns_message(b"\x00" * 11)


def test_dns_malformed_txt_record_is_rejected():
    question = encode_name("example.com") + b"\x00\x10\x00\x01"
    answer = b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x01\x00\x02\x05x"
    message = b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + answer

    with pytest.raises(DNSParseError, match="TXT"):
        parse_dns_message(message)
