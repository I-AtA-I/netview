from dataclasses import dataclass
from ipaddress import IPv4Address


class IPv4ParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IPv4Header:
    header_length: int
    total_length: int
    dscp: int
    ecn: int
    identification: int
    reserved_flag: bool
    dont_fragment: bool
    more_fragments: bool
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source: bytes
    destination: bytes
    options: bytes
    captured_length: int

    @property
    def source_ip(self) -> str:
        return str(IPv4Address(self.source))

    @property
    def destination_ip(self) -> str:
        return str(IPv4Address(self.destination))

    @property
    def payload_offset(self) -> int:
        return self.header_length

    @property
    def payload_length(self) -> int:
        return self.total_length - self.header_length

    @property
    def captured_payload_length(self) -> int:
        return max(0, self.captured_length - self.header_length)

    @property
    def is_fragment(self) -> bool:
        return self.more_fragments or self.fragment_offset > 0

    @property
    def is_truncated(self) -> bool:
        return self.captured_length < self.total_length


def parse_ipv4_packet(data: bytes) -> IPv4Header:
    if len(data) < 20:
        raise IPv4ParseError("IPv4 packet is shorter than 20 bytes")

    version = data[0] >> 4
    ihl = data[0] & 0x0F

    if version != 4:
        raise IPv4ParseError("Invalid IP version")

    if ihl < 5:
        raise IPv4ParseError("Invalid IPv4 header length")

    header_length = ihl * 4

    if len(data) < header_length:
        raise IPv4ParseError("Truncated IPv4 header")

    total_length = int.from_bytes(data[2:4], "big")

    if total_length < header_length:
        raise IPv4ParseError("Total length is smaller than header length")

    flags_fragment = int.from_bytes(data[6:8], "big")

    return IPv4Header(
        header_length=header_length,
        total_length=total_length,
        dscp=(data[1] >> 2) & 0x3F,
        ecn=data[1] & 0x03,
        identification=int.from_bytes(data[4:6], "big"),
        reserved_flag=bool(flags_fragment & 0x8000),
        dont_fragment=bool(flags_fragment & 0x4000),
        more_fragments=bool(flags_fragment & 0x2000),
        # Keep IPv4 and IPv6 fragment offsets in the same units (bytes).
        fragment_offset=(flags_fragment & 0x1FFF) * 8,
        ttl=data[8],
        protocol=data[9],
        header_checksum=int.from_bytes(data[10:12], "big"),
        source=data[12:16],
        destination=data[16:20],
        options=data[20:header_length],
        captured_length=min(len(data), total_length),
    )
