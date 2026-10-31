from dataclasses import dataclass


class UDPParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class UDPHeader:
    source_port: int
    destination_port: int
    length: int
    checksum: int
    captured_length: int

    @property
    def payload_offset(self) -> int:
        return 8

    @property
    def payload_length(self) -> int:
        return self.length - 8

    @property
    def captured_payload_length(self) -> int:
        return max(0, self.captured_length - 8)

    @property
    def is_truncated(self) -> bool:
        return self.captured_length < self.length


def parse_udp_datagram(data: bytes) -> UDPHeader:
    if len(data) < 8:
        raise UDPParseError("UDP datagram is shorter than 8 bytes")

    length = int.from_bytes(data[4:6], "big")

    if length < 8:
        raise UDPParseError("Invalid UDP length")

    return UDPHeader(
        source_port=int.from_bytes(data[0:2], "big"),
        destination_port=int.from_bytes(data[2:4], "big"),
        length=length,
        checksum=int.from_bytes(data[6:8], "big"),
        captured_length=min(len(data), length),
    )
