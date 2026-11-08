from dataclasses import dataclass

from .arp import ARPHeader, ARPParseError, parse_arp_packet
from .dns import DNSMessage, DNSParseError, parse_dns_message
from .ethernet import EthernetHeader, EthernetParseError, parse_ethernet_frame
from .http import HTTPMessage, parse_http_message, looks_like_http
from .icmp import ICMPHeader, ICMPParseError, parse_icmp_message
from .ipv4 import IPv4Header, IPv4ParseError, parse_ipv4_packet
from .ipv6 import IPv6Header, IPv6ParseError, parse_ipv6_packet
from .models import PacketRecord
from .tcp import TCPHeader, TCPParseError, parse_tcp_segment
from .tls import TLSParseError, TLSRecord, looks_like_tls, parse_tls_record
from .udp import UDPHeader, UDPParseError, parse_udp_datagram


LINKTYPE_ETHERNET = 1

ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "802.1Q VLAN",
    0x86DD: "IPv6",
    0x8847: "MPLS",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery",
    0x8864: "PPPoE Session",
    0x888E: "EAPOL",
    0x88CC: "LLDP",
    0x88A8: "802.1ad Provider Bridging",
}

IP_PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    4: "IPv4 encapsulation",
    6: "TCP",
    17: "UDP",
    41: "IPv6 encapsulation",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "No Next Header",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
    136: "UDP-Lite",
    137: "MPLS-in-IP",
}


@dataclass(frozen=True, slots=True)
class DissectionResult:
    ethernet: EthernetHeader | None = None
    arp: ARPHeader | None = None
    ipv4: IPv4Header | None = None
    ipv6: IPv6Header | None = None
    tcp: TCPHeader | None = None
    udp: UDPHeader | None = None
    icmp: ICMPHeader | None = None
    dns: DNSMessage | None = None
    http: HTTPMessage | None = None
    tls: TLSRecord | None = None

    payload: bytes = b""
    protocol: str = "Unknown"
    errors: tuple[str, ...] = ()

    @property
    def protocol_stack(self) -> tuple[str, ...]:
        layers = []

        if self.ethernet is not None:
            layers.append("Ethernet II")
            if self.ethernet.vlan_tags:
                layers.extend("802.1Q VLAN" for _ in self.ethernet.vlan_tags)

        if self.arp is not None:
            layers.append("ARP")

        if self.ipv4 is not None:
            layers.append("IPv4")

        if self.ipv6 is not None:
            layers.append("IPv6")
            layers.extend(header.name for header in self.ipv6.extension_headers)

        if self.tcp is not None:
            layers.append("TCP")
        elif self.udp is not None:
            layers.append("UDP")
        elif self.icmp is not None:
            layers.append("ICMP" if self.icmp.version == 4 else "ICMPv6")

        if self.dns is not None:
            layers.append(self.protocol if self.protocol in {"mDNS", "LLMNR"} else "DNS")
        elif self.http is not None:
            layers.append("HTTP")
        elif self.tls is not None:
            layers.append("TLS")

        return tuple(layers)


def _ether_type_protocol(ether_type: int | None) -> str:
    if ether_type is None:
        return "IEEE 802.3"
    return ETHERTYPE_NAMES.get(ether_type, f"EtherType 0x{ether_type:04x}")


def _decode_application_payload(
    payload: bytes,
    *,
    transport: str,
    source_port: int,
    destination_port: int,
) -> tuple[str | None, DNSMessage | None, HTTPMessage | None, TLSRecord | None, tuple[str, ...]]:
    if not payload:
        return None, None, None, None, ()

    errors: list[str] = []
    dns_port = source_port in {53, 5353, 5355} or destination_port in {53, 5353, 5355}
    dns_candidate = dns_port and (
        (transport == "udp" and (source_port in {53, 5353, 5355} or destination_port in {53, 5353, 5355}))
        or (transport == "tcp" and (source_port == 53 or destination_port == 53))
    )
    # Don't treat every packet on a DNS port as DNS; check for a full header.
    if dns_candidate and len(payload) >= (14 if transport == "tcp" else 12):
        tcp_framed = transport == "tcp"
        try:
            dns = parse_dns_message(payload, tcp_framed=tcp_framed)
            if 5353 in {source_port, destination_port}:
                app_name = "mDNS"
            elif 5355 in {source_port, destination_port}:
                app_name = "LLMNR"
            else:
                app_name = "DNS"
            return app_name, dns, None, None, ()
        except DNSParseError as exc:
            errors.append(f"DNS: {exc}")

    if looks_like_tls(payload):
        try:
            tls = parse_tls_record(payload)
            return "TLS", None, None, tls, tuple(errors)
        except TLSParseError as exc:
            errors.append(f"TLS: {exc}")

    if looks_like_http(payload):
        try:
            http = parse_http_message(payload)
            return "HTTP", None, http, None, tuple(errors)
        except ValueError as exc:
            errors.append(f"HTTP: {exc}")

    return None, None, None, None, tuple(errors)


def _dissect_transport(
    transport_data: bytes,
    protocol_number: int,
    *,
    version: int,
    ethernet: EthernetHeader,
    ipv4: IPv4Header | None = None,
    ipv6: IPv6Header | None = None,
) -> DissectionResult:
    protocol_name = IP_PROTOCOL_NAMES.get(protocol_number, f"IP protocol {protocol_number}")

    if protocol_number == 6:
        try:
            tcp = parse_tcp_segment(transport_data)
        except TCPParseError as exc:
            return DissectionResult(
                ethernet=ethernet,
                ipv4=ipv4,
                ipv6=ipv6,
                payload=transport_data,
                protocol="TCP",
                errors=(f"TCP: {exc}",),
            )

        payload = transport_data[tcp.header_length:]
        app_name, dns, http, tls, app_errors = _decode_application_payload(
            payload,
            transport="tcp",
            source_port=tcp.source_port,
            destination_port=tcp.destination_port,
        )
        return DissectionResult(
            ethernet=ethernet,
            ipv4=ipv4,
            ipv6=ipv6,
            tcp=tcp,
            dns=dns,
            http=http,
            tls=tls,
            payload=payload,
            protocol=app_name or "TCP",
            errors=app_errors,
        )

    if protocol_number == 17:
        try:
            udp = parse_udp_datagram(transport_data)
        except UDPParseError as exc:
            return DissectionResult(
                ethernet=ethernet,
                ipv4=ipv4,
                ipv6=ipv6,
                payload=transport_data,
                protocol="UDP",
                errors=(f"UDP: {exc}",),
            )

        udp_data = transport_data[:udp.captured_length]
        payload = udp_data[udp.payload_offset:]
        app_name, dns, http, tls, app_errors = _decode_application_payload(
            payload,
            transport="udp",
            source_port=udp.source_port,
            destination_port=udp.destination_port,
        )
        return DissectionResult(
            ethernet=ethernet,
            ipv4=ipv4,
            ipv6=ipv6,
            udp=udp,
            dns=dns,
            http=http,
            tls=tls,
            payload=payload,
            protocol=app_name or "UDP",
            errors=app_errors,
        )

    icmp_version = 4 if (version == 4 and protocol_number == 1) else 6 if (version == 6 and protocol_number == 58) else None
    if icmp_version is not None:
        try:
            icmp = parse_icmp_message(transport_data, icmp_version)
        except ICMPParseError as exc:
            return DissectionResult(
                ethernet=ethernet,
                ipv4=ipv4,
                ipv6=ipv6,
                payload=transport_data,
                protocol="ICMP" if icmp_version == 4 else "ICMPv6",
                errors=(f"ICMP: {exc}",),
            )

        protocol = "ICMP" if icmp_version == 4 else "ICMPv6"
        return DissectionResult(
            ethernet=ethernet,
            ipv4=ipv4,
            ipv6=ipv6,
            icmp=icmp,
            payload=transport_data[icmp.header_length:],
            protocol=protocol,
        )

    return DissectionResult(
        ethernet=ethernet,
        ipv4=ipv4,
        ipv6=ipv6,
        payload=transport_data,
        protocol=protocol_name,
    )

def dissect_ethernet_frame(data: bytes) -> DissectionResult:
    try:
        ethernet = parse_ethernet_frame(data)
    except EthernetParseError as exc:
        return DissectionResult(errors=(f"Ethernet: {exc}",))

    network_data = data[ethernet.payload_offset:]
    ether_type = ethernet.ether_type

    if ether_type == 0x0806:
        try:
            arp = parse_arp_packet(network_data)
        except ARPParseError as exc:
            return DissectionResult(
                ethernet=ethernet,
                payload=network_data,
                protocol="ARP",
                errors=(f"ARP: {exc}",),
            )
        return DissectionResult(
            ethernet=ethernet,
            arp=arp,
            payload=network_data[8 + 2 * arp.hardware_length + 2 * arp.protocol_length:],
            protocol="ARP",
        )

    if ether_type == 0x0800:
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

        return _dissect_transport(
            transport_data,
            ipv4.protocol,
            version=4,
            ethernet=ethernet,
            ipv4=ipv4,
        )

    if ether_type == 0x86DD:
        try:
            ipv6 = parse_ipv6_packet(network_data)
        except IPv6ParseError as exc:
            return DissectionResult(
                ethernet=ethernet,
                payload=network_data,
                protocol="IPv6",
                errors=(f"IPv6: {exc}",),
            )

        ipv6_data = network_data[:ipv6.captured_length]
        transport_data = ipv6_data[ipv6.upper_layer_offset:]

        if ipv6.fragment_offset > 0:
            return DissectionResult(
                ethernet=ethernet,
                ipv6=ipv6,
                payload=transport_data,
                protocol="IPv6 fragment",
            )

        return _dissect_transport(
            transport_data,
            ipv6.upper_layer_protocol,
            version=6,
            ethernet=ethernet,
            ipv6=ipv6,
        )

    return DissectionResult(
        ethernet=ethernet,
        payload=network_data,
        protocol=_ether_type_protocol(ether_type),
    )


def dissect_packet(packet: PacketRecord) -> DissectionResult:
    if packet.link_type != LINKTYPE_ETHERNET:
        return DissectionResult(
            payload=packet.data,
            protocol=f"Unsupported link type {packet.link_type}",
            errors=(f"Unsupported link type: {packet.link_type}",),
        )

    return dissect_ethernet_frame(packet.data)
