from dataclasses import dataclass


VLAN_TPIDS = {0x8100, 0x88A8}


class EthernetParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VlanTag:
    tpid: int
    priority: int
    drop_eligible: bool
    vlan_id: int


@dataclass(frozen=True, slots=True)
class EthernetHeader:
    destination: bytes
    source: bytes
    type_or_length: int
    payload_offset: int
    vlan_tags: tuple[VlanTag, ...]

    @property
    def destination_mac(self) -> str:
        return ":".join(f"{byte:02x}" for byte in self.destination)

    @property
    def source_mac(self) -> str:
        return ":".join(f"{byte:02x}" for byte in self.source)

    @property
    def ether_type(self) -> int | None:
        if self.type_or_length >= 0x0600:
            return self.type_or_length
        return None


def parse_ethernet_frame(data: bytes) -> EthernetHeader:
    if len(data) < 14:
        raise EthernetParseError("Ethernet frame is shorter than 14 bytes")

    destination = data[0:6]
    source = data[6:12]

    type_or_length = int.from_bytes(data[12:14], "big")
    offset = 14

    vlan_tags = []

    while type_or_length in VLAN_TPIDS:
        if len(data) < offset + 4:
            raise EthernetParseError("Truncated VLAN tag")

        tci = int.from_bytes(data[offset:offset + 2], "big")

        vlan_tags.append(
            VlanTag(
                tpid=type_or_length,
                priority=(tci >> 13) & 0b111,
                drop_eligible=bool((tci >> 12) & 1),
                vlan_id=tci & 0x0FFF,
            )
        )

        type_or_length = int.from_bytes(
            data[offset + 2:offset + 4], "big"
        )

        offset += 4

    return EthernetHeader(
        destination=destination,
        source=source,
        type_or_length=type_or_length,
        payload_offset=offset,
        vlan_tags=tuple(vlan_tags),
    )
