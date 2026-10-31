from dataclasses import dataclass

from .ethernet import EthernetHeader, EthernetParseError, parse_ethernet_frame
from .ipv4 import IPv4Header, IPv4ParseError, parse_ipv4_packet
from .models import PacketRecord
from .tcp import TCPHeader, TCPParseError, parse_tcp_segment
from .udp import UDPHeader, UDPParseError, parse_udp_datagram


LINKTYPE_ETHERNET = 1


@dataclass(frozen=True, slots=True)
class DissectionResult:
    ethernet: EthernetHeader | None = None
    ipv4: IPv4Header | None = None
    tcp: TCPHeader | None = None
    udp: UDPHeader | None = None

    payload: bytes = b""
    protocol: str = "Unknown"
    errors: tuple[str, ...] = ()

    @property
    def protocol_stack(self) -> tuple[str, ...]:
        layers = []

        if self.ethernet is not None:
            layers.append("Ethernet II")

        if self.ipv4 is not None:
            layers.append("IPv4")

        if self.tcp is not None:
            layers.append("TCP")
        elif self.udp is not None:
            layers.append("UDP")

        return tuple(layers)


def dissect_ethernet_frame(data: bytes) -> DissectionResult:
    try:
        ethernet = parse_ethernet_frame(data)
    except EthernetParseError as exc:
        return DissectionResult(errors=(f"Ethernet: {exc}",))

    network_data = data[ethernet.payload_offset:]

    if ethernet.ether_type != 0x0800:
        if ethernet.ether_type is None:
            protocol = "IEEE 802.3"
        else:
            protocol = f"EtherType 0x{ethernet.ether_type:04x}"

        return DissectionResult(
            ethernet=ethernet,
            payload=network_data,
            protocol=protocol,
        )

    try:
        ipv4 = parse_ipv4_packet(network_data)
    except IPv4ParseError as exc:
        return DissectionResult(
            ethernet=ethernet,
            payload=network_data,
            protocol="IPv4",
            errors=(f"IPv4: {exc}",),
        )

    ip_data = network_data[:ipv4.captured_length]
    transport_data = ip_data[ipv4.header_length:]

    if ipv4.fragment_offset > 0:
        return DissectionResult(
            ethernet=ethernet,
            ipv4=ipv4,
            payload=transport_data,
            protocol="IPv4 fragment",
        )

    if ipv4.protocol == 6:
        try:
            tcp = parse_tcp_segment(transport_data)
        except TCPParseError as exc:
            return DissectionResult(
                ethernet=ethernet,
                ipv4=ipv4,
                payload=transport_data,
                protocol="TCP",
                errors=(f"TCP: {exc}",),
            )

        return DissectionResult(
            ethernet=ethernet,
            ipv4=ipv4,
            tcp=tcp,
            payload=transport_data[tcp.header_length:],
            protocol="TCP",
        )

    if ipv4.protocol == 17:
        try:
            udp = parse_udp_datagram(transport_data)
        except UDPParseError as exc:
            return DissectionResult(
                ethernet=ethernet,
                ipv4=ipv4,
                payload=transport_data,
                protocol="UDP",
                errors=(f"UDP: {exc}",),
            )

        udp_data = transport_data[:udp.captured_length]

        return DissectionResult(
            ethernet=ethernet,
            ipv4=ipv4,
            udp=udp,
            payload=udp_data[udp.payload_offset:],
            protocol="UDP",
        )

    if ipv4.protocol == 1:
        protocol = "ICMP (not decoded)"
    else:
        protocol = f"IP protocol {ipv4.protocol}"

    return DissectionResult(
        ethernet=ethernet,
        ipv4=ipv4,
        payload=transport_data,
        protocol=protocol,
    )


def dissect_packet(packet: PacketRecord) -> DissectionResult:
    if packet.link_type != LINKTYPE_ETHERNET:
        return DissectionResult(
            payload=packet.data,
            protocol=f"Unsupported link type {packet.link_type}",
            errors=(f"Unsupported link type: {packet.link_type}",),
        )

    return dissect_ethernet_frame(packet.data)
