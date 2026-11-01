from dataclasses import dataclass


class ICMPParseError(ValueError):
    pass


ICMP4_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
}

ICMP6_TYPES = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect",
    143: "MLDv2 Listener Report",
}


@dataclass(frozen=True, slots=True)
class ICMPHeader:
    version: int
    type: int
    code: int
    checksum: int
    rest_of_header: bytes
    header_length: int
    type_name: str

    @property
    def identifier(self) -> int | None:
        if self.type in ({0, 8} if self.version == 4 else {128, 129}) and len(self.rest_of_header) >= 2:
            return int.from_bytes(self.rest_of_header[:2], "big")
        return None

    @property
    def sequence_number(self) -> int | None:
        if self.type in ({0, 8} if self.version == 4 else {128, 129}) and len(self.rest_of_header) >= 4:
            return int.from_bytes(self.rest_of_header[2:4], "big")
        return None


def parse_icmp_message(data: bytes, version: int = 4) -> ICMPHeader:
    if version not in (4, 6):
        raise ValueError("ICMP version must be 4 or 6")
    if len(data) < 4:
        raise ICMPParseError("ICMP message is shorter than 4 bytes")

    message_type = data[0]
    echo_types = {0, 8} if version == 4 else {128, 129}
    if message_type in echo_types and len(data) < 8:
        raise ICMPParseError("Truncated ICMP echo header")

    header_length = min(len(data), 8)
    type_names = ICMP4_TYPES if version == 4 else ICMP6_TYPES

    return ICMPHeader(
        version=version,
        type=message_type,
        code=data[1],
        checksum=int.from_bytes(data[2:4], "big"),
        rest_of_header=data[4:header_length],
        header_length=header_length,
        type_name=type_names.get(message_type, f"Unknown type ({message_type})"),
    )
