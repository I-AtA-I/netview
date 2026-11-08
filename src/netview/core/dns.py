from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address


class DNSParseError(ValueError):
    pass


DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}

DNS_RCODE_NAMES = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
    6: "YXDomain",
    7: "YXRRSet",
    8: "NXRRSet",
    9: "NotAuth",
    10: "NotZone",
}


@dataclass(frozen=True, slots=True)
class DNSQuestion:
    name: str
    qtype: int
    qclass: int

    @property
    def type_name(self) -> str:
        return DNS_TYPE_NAMES.get(self.qtype, f"TYPE{self.qtype}")


@dataclass(frozen=True, slots=True)
class DNSResourceRecord:
    name: str
    record_type: int
    record_class: int
    ttl: int
    data_length: int
    data: str

    @property
    def type_name(self) -> str:
        return DNS_TYPE_NAMES.get(self.record_type, f"TYPE{self.record_type}")


@dataclass(frozen=True, slots=True)
class DNSMessage:
    transaction_id: int
    flags: int
    questions: tuple[DNSQuestion, ...]
    answers: tuple[DNSResourceRecord, ...]
    authorities: tuple[DNSResourceRecord, ...]
    additionals: tuple[DNSResourceRecord, ...]
    message_length: int
    tcp_framed: bool = False

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0x0F

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & 0x0400)

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def recursion_desired(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def recursion_available(self) -> bool:
        return bool(self.flags & 0x0080)

    @property
    def authenticated_data(self) -> bool:
        return bool(self.flags & 0x0020)

    @property
    def checking_disabled(self) -> bool:
        return bool(self.flags & 0x0010)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def rcode_name(self) -> str:
        return DNS_RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")

    @property
    def query_name(self) -> str | None:
        return self.questions[0].name if self.questions else None


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    return_offset: int | None = None
    wire_length = 0
    visited: set[int] = set()
    jumps = 0

    while True:
        if cursor >= len(data):
            raise DNSParseError("Truncated DNS name")

        length = data[cursor]

        if length == 0:
            if wire_length + 1 > 255:
                raise DNSParseError("DNS name is longer than 255 bytes")
            if return_offset is None:
                return_offset = cursor + 1
            break

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise DNSParseError("Truncated DNS compression pointer")

            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer >= len(data):
                raise DNSParseError("DNS compression pointer is out of bounds")
            if pointer in visited:
                raise DNSParseError("DNS compression pointer loop")

            visited.add(pointer)
            jumps += 1
            if jumps > 32:
                raise DNSParseError("Too many DNS compression pointer jumps")

            if return_offset is None:
                return_offset = cursor + 2
            cursor = pointer
            continue

        if length & 0xC0:
            raise DNSParseError("Reserved DNS label encoding")
        if length > 63:
            raise DNSParseError("DNS label is longer than 63 bytes")
        if cursor + 1 + length > len(data):
            raise DNSParseError("Truncated DNS label")

        raw_label = data[cursor + 1:cursor + 1 + length]
        labels.append(raw_label.decode("ascii", errors="backslashreplace"))
        wire_length += 1 + len(raw_label)
        cursor += 1 + length

        # DNS limits the encoded name length, not the decoded string length.
        if wire_length + 1 > 255:
            raise DNSParseError("DNS name is longer than 255 bytes")

    return (".".join(labels) if labels else "."), return_offset


def _parse_rdata(data: bytes, offset: int, record_type: int, length: int) -> str:
    raw = data[offset:offset + length]

    if record_type == 1 and length == 4:
        return str(IPv4Address(raw))
    if record_type == 28 and length == 16:
        return str(IPv6Address(raw))
    if record_type in {2, 5, 12}:
        name, next_offset = _decode_name(data, offset)
        if next_offset > offset + length:
            raise DNSParseError("DNS name RDATA exceeds its declared length")
        return name
    if record_type == 15 and length >= 3:
        preference = int.from_bytes(raw[:2], "big")
        exchange, next_offset = _decode_name(data, offset + 2)
        if next_offset > offset + length:
            raise DNSParseError("MX exchange name exceeds its declared RDATA length")
        return f"{preference} {exchange}"
    if record_type == 16:
        chunks: list[str] = []
        cursor = 0
        while cursor < len(raw):
            chunk_length = raw[cursor]
            cursor += 1
            if cursor + chunk_length > len(raw):
                raise DNSParseError("Malformed DNS TXT record")
            chunks.append(raw[cursor:cursor + chunk_length].decode("utf-8", errors="replace"))
            cursor += chunk_length
        return " | ".join(chunks)

    return raw.hex(" ")


def _parse_question(data: bytes, offset: int) -> tuple[DNSQuestion, int]:
    name, cursor = _decode_name(data, offset)
    if cursor + 4 > len(data):
        raise DNSParseError("Truncated DNS question")

    question = DNSQuestion(
        name=name,
        qtype=int.from_bytes(data[cursor:cursor + 2], "big"),
        qclass=int.from_bytes(data[cursor + 2:cursor + 4], "big"),
    )
    return question, cursor + 4


def _parse_record(data: bytes, offset: int) -> tuple[DNSResourceRecord, int]:
    name, cursor = _decode_name(data, offset)
    if cursor + 10 > len(data):
        raise DNSParseError("Truncated DNS resource record header")

    record_type = int.from_bytes(data[cursor:cursor + 2], "big")
    record_class = int.from_bytes(data[cursor + 2:cursor + 4], "big")
    ttl = int.from_bytes(data[cursor + 4:cursor + 8], "big")
    data_length = int.from_bytes(data[cursor + 8:cursor + 10], "big")
    rdata_offset = cursor + 10
    end = rdata_offset + data_length

    if end > len(data):
        raise DNSParseError("Truncated DNS resource record data")

    rdata_text = _parse_rdata(data, rdata_offset, record_type, data_length)
    record = DNSResourceRecord(
        name=name,
        record_type=record_type,
        record_class=record_class,
        ttl=ttl,
        data_length=data_length,
        data=rdata_text,
    )
    return record, end


def parse_dns_message(data: bytes, *, tcp_framed: bool = False) -> DNSMessage:
    """Parse one DNS message. For TCP, data includes the 2-byte length prefix."""
    if tcp_framed:
        if len(data) < 2:
            raise DNSParseError("Truncated DNS-over-TCP length prefix")
        declared_length = int.from_bytes(data[:2], "big")
        if declared_length < 12:
            raise DNSParseError("DNS-over-TCP message is shorter than its header")
        if len(data) < declared_length + 2:
            raise DNSParseError("Truncated DNS-over-TCP message")
        data = data[2:2 + declared_length]

    if len(data) < 12:
        raise DNSParseError("DNS message is shorter than 12 bytes")

    transaction_id = int.from_bytes(data[0:2], "big")
    flags = int.from_bytes(data[2:4], "big")
    question_count = int.from_bytes(data[4:6], "big")
    answer_count = int.from_bytes(data[6:8], "big")
    authority_count = int.from_bytes(data[8:10], "big")
    additional_count = int.from_bytes(data[10:12], "big")

    # Cap the counts so malformed headers can't trigger work beyond the packet.
    total_records = question_count + answer_count + authority_count + additional_count
    if total_records > len(data):
        raise DNSParseError("DNS section counts exceed the available message size")

    cursor = 12
    questions: list[DNSQuestion] = []
    answers: list[DNSResourceRecord] = []
    authorities: list[DNSResourceRecord] = []
    additionals: list[DNSResourceRecord] = []

    for _ in range(question_count):
        question, cursor = _parse_question(data, cursor)
        questions.append(question)

    for records, count in (
        (answers, answer_count),
        (authorities, authority_count),
        (additionals, additional_count),
    ):
        for _ in range(count):
            record, cursor = _parse_record(data, cursor)
            records.append(record)

    return DNSMessage(
        transaction_id=transaction_id,
        flags=flags,
        questions=tuple(questions),
        answers=tuple(answers),
        authorities=tuple(authorities),
        additionals=tuple(additionals),
        message_length=len(data),
        tcp_framed=tcp_framed,
    )
