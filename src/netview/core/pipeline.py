from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from .dissector import DissectionResult, dissect_packet
from .models import PacketRecord
from .tls import cipher_suite_name, tls_version_name


@dataclass(frozen=True, slots=True)
class ProcessedPacket:
    record: PacketRecord
    dissection: DissectionResult

    @property
    def number(self) -> int:
        return self.record.number

    @property
    def timestamp(self) -> float | None:
        return self.record.timestamp

    @property
    def length(self) -> int:
        return self.record.original_length

    @property
    def captured_length(self) -> int:
        return self.record.captured_length

    @property
    def protocol(self) -> str:
        return self.dissection.protocol

    @property
    def source(self) -> str:
        if self.dissection.ipv4 is not None:
            return self.dissection.ipv4.source_ip

        if self.dissection.ipv6 is not None:
            return self.dissection.ipv6.source_ip

        if self.dissection.arp is not None:
            arp = self.dissection.arp
            return arp.sender_protocol_address or arp.sender_hardware_address

        if self.dissection.ethernet is not None:
            return self.dissection.ethernet.source_mac

        return "—"

    @property
    def destination(self) -> str:
        if self.dissection.ipv4 is not None:
            return self.dissection.ipv4.destination_ip

        if self.dissection.ipv6 is not None:
            return self.dissection.ipv6.destination_ip

        if self.dissection.arp is not None:
            arp = self.dissection.arp
            return arp.target_protocol_address or arp.target_hardware_address

        if self.dissection.ethernet is not None:
            return self.dissection.ethernet.destination_mac

        return "—"

    @property
    def source_port(self) -> int | None:
        if self.dissection.tcp is not None:
            return self.dissection.tcp.source_port

        if self.dissection.udp is not None:
            return self.dissection.udp.source_port

        return None

    @property
    def destination_port(self) -> int | None:
        if self.dissection.tcp is not None:
            return self.dissection.tcp.destination_port

        if self.dissection.udp is not None:
            return self.dissection.udp.destination_port

        return None

    @property
    def info(self) -> str:
        dissection = self.dissection

        if dissection.errors:
            return " | ".join(dissection.errors)

        if dissection.arp is not None:
            arp = dissection.arp
            if arp.opcode == 1:
                return f"Who has {arp.target_protocol_address}? Tell {arp.sender_protocol_address}"
            if arp.opcode == 2:
                return f"{arp.sender_protocol_address} is at {arp.sender_hardware_address}"
            return f"{arp.operation} {arp.sender_protocol_address} → {arp.target_protocol_address}"

        if dissection.icmp is not None:
            icmp = dissection.icmp
            return f"{icmp.type_name} (type={icmp.type}, code={icmp.code})"

        if dissection.dns is not None:
            dns = dissection.dns
            if dns.questions:
                question = dns.questions[0]
                action = "response" if dns.is_response else "query"
                summary = f"{action} {question.name} {question.type_name}"
            else:
                summary = "response" if dns.is_response else "message"
            if dns.is_response and dns.answers:
                answer = dns.answers[0]
                summary += f" → {answer.data}"
            if dns.is_response and dns.rcode:
                summary += f" ({dns.rcode_name})"
            return summary

        if dissection.http is not None:
            http = dissection.http
            if http.is_request:
                host = f" Host={http.host}" if http.host else ""
                return f"{http.method} {http.target}{host}"
            reason = f" {http.reason}" if http.reason else ""
            return f"{http.version} {http.status_code}{reason}"

        if dissection.tls is not None:
            tls = dissection.tls
            if tls.client_hello is not None:
                hello = tls.client_hello
                sni = f" SNI={hello.server_name}" if hello.server_name else ""
                alpn = f" ALPN={','.join(hello.alpn_protocols)}" if hello.alpn_protocols else ""
                versions = ",".join(tls_version_name(v) for v in hello.supported_versions)
                version_text = f" Versions={versions}" if versions else ""
                return f"Client Hello{sni}{alpn}{version_text}"
            if tls.server_hello is not None:
                hello = tls.server_hello
                version = hello.negotiated_version or hello.legacy_version
                alpn = f" ALPN={hello.alpn_protocol}" if hello.alpn_protocol else ""
                return f"Server Hello {tls_version_name(version)} {cipher_suite_name(hello.cipher_suite)}{alpn}"
            handshake = f" {tls.handshake_name}" if tls.handshake_name else ""
            truncated = " (truncated)" if tls.is_truncated or tls.handshake_is_truncated else ""
            return f"{tls.content_type_name}{handshake}{truncated}"

        if dissection.tcp is not None:
            tcp = dissection.tcp
            flags = ",".join(tcp.active_flags) or "none"
            return (
                f"{tcp.source_port} → {tcp.destination_port} "
                f"[{flags}] Seq={tcp.sequence_number} "
                f"Ack={tcp.acknowledgment_number}"
            )

        if dissection.udp is not None:
            udp = dissection.udp
            return f"{udp.source_port} → {udp.destination_port} Len={udp.payload_length}"

        if dissection.ipv4 is not None:
            ipv4 = dissection.ipv4

            if ipv4.is_fragment:
                return (
                    f"Fragment offset={ipv4.fragment_offset * 8} "
                    f"MF={int(ipv4.more_fragments)}"
                )

            return (
                f"TTL={ipv4.ttl} "
                f"ID=0x{ipv4.identification:04x}"
            )

        if dissection.ipv6 is not None:
            ipv6 = dissection.ipv6
            return f"Hop limit={ipv6.hop_limit} Next header={ipv6.upper_layer_protocol}"

        if dissection.payload:
            return f"{len(dissection.payload)} bytes"

        return "—"


def process_packet(packet: PacketRecord) -> ProcessedPacket:
    return ProcessedPacket(
        record=packet,
        dissection=dissect_packet(packet),
    )


def iter_processed_packets(
    packets: Iterable[PacketRecord],
) -> Iterator[ProcessedPacket]:
    for packet in packets:
        yield process_packet(packet)
