from dataclasses import dataclass


class TCPParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TCPHeader:
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    header_length: int
    reserved: int
    ns: bool
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int
    options: bytes

    @property
    def payload_offset(self) -> int:
        return self.header_length

    @property
    def is_cwr(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def is_ece(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def is_urg(self) -> bool:
        return bool(self.flags & 0x20)

    @property
    def is_ack(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def is_psh(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def is_rst(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def active_flags(self) -> tuple[str, ...]:
        names = (
            ("CWR", self.is_cwr),
            ("ECE", self.is_ece),
            ("URG", self.is_urg),
            ("ACK", self.is_ack),
            ("PSH", self.is_psh),
            ("RST", self.is_rst),
            ("SYN", self.is_syn),
            ("FIN", self.is_fin),
        )

        return tuple(name for name, active in names if active)


def parse_tcp_segment(data: bytes) -> TCPHeader:
    if len(data) < 20:
        raise TCPParseError("TCP segment is shorter than 20 bytes")

    offset_words = data[12] >> 4

    if offset_words < 5:
        raise TCPParseError("Invalid TCP data offset")

    header_length = offset_words * 4

    if len(data) < header_length:
        raise TCPParseError("Truncated TCP header")

    return TCPHeader(
        source_port=int.from_bytes(data[0:2], "big"),
        destination_port=int.from_bytes(data[2:4], "big"),
        sequence_number=int.from_bytes(data[4:8], "big"),
        acknowledgment_number=int.from_bytes(data[8:12], "big"),
        header_length=header_length,
        reserved=(data[12] >> 1) & 0x07,
        ns=bool(data[12] & 0x01),
        flags=data[13],
        window_size=int.from_bytes(data[14:16], "big"),
        checksum=int.from_bytes(data[16:18], "big"),
        urgent_pointer=int.from_bytes(data[18:20], "big"),
        options=data[20:header_length],
    )
