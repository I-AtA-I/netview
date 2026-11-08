from dataclasses import dataclass
from ipaddress import IPv6Address


class IPv6ParseError(ValueError):
    pass


EXTENSION_NAMES = {
    0: "Hop-by-Hop Options",
    43: "Routing",
    44: "Fragment",
    50: "Encapsulating Security Payload",
    51: "Authentication Header",
    60: "Destination Options",
    135: "Mobility",
    139: "Host Identity Protocol",
    140: "Shim6 Protocol",
}

# Extension headers whose length is encoded in 8-byte units.
_OPTIONS_HEADERS = {0, 43, 60, 135, 139, 140}


@dataclass(frozen=True, slots=True)
class IPv6ExtensionHeader:
    header_type: int
    name: str
    next_header: int
    offset: int
    length: int
    fragment_offset: int | None = None
    more_fragments: bool = False
    fragment_identification: int | None = None


@dataclass(frozen=True, slots=True)
class IPv6Header:
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    source: bytes
    destination: bytes
    captured_length: int
    extension_headers: tuple[IPv6ExtensionHeader, ...]
    upper_layer_protocol: int
    upper_layer_offset: int
    fragment_offset: int = 0
    more_fragments: bool = False
    fragment_identification: int | None = None

    @property
    def source_ip(self) -> str:
        return str(IPv6Address(self.source))

    @property
    def destination_ip(self) -> str:
        return str(IPv6Address(self.destination))

    @property
    def total_length(self) -> int:
        return 40 + self.payload_length

    @property
    def is_truncated(self) -> bool:
        return self.captured_length < self.total_length

    @property
    def is_fragment(self) -> bool:
        return (
            self.fragment_offset > 0
            or self.more_fragments
            or any(header.header_type == 44 for header in self.extension_headers)
        )


def parse_ipv6_packet(data: bytes) -> IPv6Header:
    if len(data) < 40:
        raise IPv6ParseError("IPv6 packet is shorter than 40 bytes")

    version = data[0] >> 4
    if version != 6:
        raise IPv6ParseError("Invalid IP version")

    traffic_class = ((data[0] & 0x0F) << 4) | (data[1] >> 4)
    flow_label = ((data[1] & 0x0F) << 16) | int.from_bytes(data[2:4], "big")
    payload_length = int.from_bytes(data[4:6], "big")
    initial_next_header = data[6]
    hop_limit = data[7]
    source = data[8:24]
    destination = data[24:40]

    # IPv6 jumbograms use a Hop-by-Hop Jumbo Payload option and are not
    # interpreted by this first implementation.
    if payload_length == 0:
        captured_length = min(len(data), 40)
        bounded_length = 40
    else:
        bounded_length = 40 + payload_length
        captured_length = min(len(data), bounded_length)

    offset = 40
    next_header = initial_next_header
    extensions: list[IPv6ExtensionHeader] = []
    fragment_offset = 0
    more_fragments = False
    fragment_identification = None

    # Protect the parser from malformed cyclic/overlong extension chains.
    while next_header in (_OPTIONS_HEADERS | {44, 51}):
        if len(extensions) >= 16:
            raise IPv6ParseError("Too many IPv6 extension headers")

        if offset + 2 > captured_length:
            raise IPv6ParseError("Truncated IPv6 extension header")

        header_type = next_header
        following_header = data[offset]

        if header_type in _OPTIONS_HEADERS:
            length = (data[offset + 1] + 1) * 8
        elif header_type == 44:  # Fragment header
            length = 8
        else:  # Authentication Header
            length = (data[offset + 1] + 2) * 4

        if length < 8 or offset + length > captured_length:
            raise IPv6ParseError("Invalid or truncated IPv6 extension header")

        extension_fragment_offset = None
        extension_more_fragments = False
        extension_fragment_identification = None

        if header_type == 44:
            fragment_field = int.from_bytes(data[offset + 2:offset + 4], "big")
            extension_fragment_offset = ((fragment_field & 0xFFF8) >> 3) * 8
            extension_more_fragments = bool(fragment_field & 0x0001)
            extension_fragment_identification = int.from_bytes(
                data[offset + 4:offset + 8], "big"
            )
            fragment_offset = extension_fragment_offset
            more_fragments = extension_more_fragments
            fragment_identification = extension_fragment_identification

        extensions.append(
            IPv6ExtensionHeader(
                header_type=header_type,
                name=EXTENSION_NAMES.get(header_type, f"Unknown extension ({header_type})"),
                next_header=following_header,
                offset=offset,
                length=length,
                fragment_offset=extension_fragment_offset,
                more_fragments=extension_more_fragments,
                fragment_identification=extension_fragment_identification,
            )
        )

        offset += length
        next_header = following_header

        # Non-initial fragments do not begin with the upper-layer header.
        if header_type == 44 and fragment_offset > 0:
            break

    return IPv6Header(
        traffic_class=traffic_class,
        flow_label=flow_label,
        payload_length=payload_length,
        next_header=initial_next_header,
        hop_limit=hop_limit,
        source=source,
        destination=destination,
        captured_length=captured_length,
        extension_headers=tuple(extensions),
        upper_layer_protocol=next_header,
        upper_layer_offset=offset,
        fragment_offset=fragment_offset,
        more_fragments=more_fragments,
        fragment_identification=fragment_identification,
    )
