from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from .pipeline import ProcessedPacket


class AnalysisCancelled(Exception):
    """Raised when a caller requests cancellation during capture analysis."""


def _check_cancelled(should_stop: Callable[[], bool] | None) -> None:
    if should_stop is not None and should_stop():
        raise AnalysisCancelled


@dataclass(frozen=True, slots=True)
class ConversationStats:
    transport: str
    endpoint_a: str
    endpoint_b: str
    packet_count: int
    byte_count: int
    first_timestamp: float | None
    last_timestamp: float | None
    protocols: tuple[str, ...]
    first_packet_number: int

    @property
    def key(self) -> str:
        return f"{self.endpoint_a} ↔ {self.endpoint_b}"


@dataclass(frozen=True, slots=True)
class TCPDiagnostic:
    packet_number: int
    conversation: str
    category: str
    detail: str


@dataclass(frozen=True, slots=True)
class ProtocolEvent:
    packet_number: int
    protocol: str
    source: str
    destination: str
    detail: str


@dataclass(frozen=True, slots=True)
class TrafficBucket:
    start_timestamp: float
    end_timestamp: float
    packet_count: int
    byte_count: int


@dataclass(frozen=True, slots=True)
class CaptureAnalysis:
    packet_count: int
    byte_count: int
    tcp_count: int
    udp_count: int
    warning_count: int
    protocol_counts: tuple[tuple[str, int], ...]
    endpoint_counts: tuple[tuple[str, int], ...]
    conversations: tuple[ConversationStats, ...]
    tcp_diagnostics: tuple[TCPDiagnostic, ...]
    protocol_events: tuple[ProtocolEvent, ...]
    traffic_buckets: tuple[TrafficBucket, ...]


@dataclass(slots=True)
class _ConversationBuilder:
    transport: str
    endpoint_a: str
    endpoint_b: str
    packet_count: int = 0
    byte_count: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    protocols: set[str] | None = None
    first_packet_number: int = 0

    def add(self, packet: ProcessedPacket) -> None:
        self.packet_count += 1
        self.byte_count += packet.length
        if self.first_packet_number == 0:
            self.first_packet_number = packet.number
        if self.protocols is None:
            self.protocols = set()
        self.protocols.add(packet.protocol)
        if packet.timestamp is not None:
            if self.first_timestamp is None or packet.timestamp < self.first_timestamp:
                self.first_timestamp = packet.timestamp
            if self.last_timestamp is None or packet.timestamp > self.last_timestamp:
                self.last_timestamp = packet.timestamp

    def finish(self) -> ConversationStats:
        return ConversationStats(
            transport=self.transport,
            endpoint_a=self.endpoint_a,
            endpoint_b=self.endpoint_b,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            first_timestamp=self.first_timestamp,
            last_timestamp=self.last_timestamp,
            protocols=tuple(sorted(self.protocols or ())),
            first_packet_number=self.first_packet_number,
        )


def _tcp_endpoints(packet: ProcessedPacket) -> tuple[str, str, str] | None:
    tcp = packet.dissection.tcp
    if tcp is None:
        return None
    if packet.dissection.ipv4 is not None:
        source = packet.dissection.ipv4.source_ip
        destination = packet.dissection.ipv4.destination_ip
    elif packet.dissection.ipv6 is not None:
        source = packet.dissection.ipv6.source_ip
        destination = packet.dissection.ipv6.destination_ip
    else:
        return None
    return f"{source}:{tcp.source_port}", f"{destination}:{tcp.destination_port}", "TCP"


def _transport_endpoints(packet: ProcessedPacket) -> tuple[str, str, str] | None:
    tcp_endpoints = _tcp_endpoints(packet)
    if tcp_endpoints is not None:
        return tcp_endpoints

    udp = packet.dissection.udp
    if udp is None:
        return None
    if packet.dissection.ipv4 is not None:
        source = packet.dissection.ipv4.source_ip
        destination = packet.dissection.ipv4.destination_ip
    elif packet.dissection.ipv6 is not None:
        source = packet.dissection.ipv6.source_ip
        destination = packet.dissection.ipv6.destination_ip
    else:
        return None
    return f"{source}:{udp.source_port}", f"{destination}:{udp.destination_port}", "UDP"


def _signed_sequence_delta(sequence: int, reference: int) -> int:
    return ((sequence - reference + (1 << 31)) % (1 << 32)) - (1 << 31)


def _tcp_diagnostics(
    packets: list[ProcessedPacket] | tuple[ProcessedPacket, ...],
    should_stop: Callable[[], bool] | None = None,
) -> tuple[TCPDiagnostic, ...]:
    flow_state: dict[tuple[str, str, str], dict[str, int | None]] = {}
    ack_counts: Counter[tuple[str, str, str, int]] = Counter()
    diagnostics: list[TCPDiagnostic] = []

    for packet in packets:
        _check_cancelled(should_stop)
        tcp = packet.dissection.tcp
        endpoints = _tcp_endpoints(packet)
        if tcp is None or endpoints is None:
            continue

        source, destination, _ = endpoints
        endpoint_a, endpoint_b = sorted((source, destination))
        direction = 0 if source == endpoint_a else 1
        flow = (endpoint_a, endpoint_b, str(direction))
        state = flow_state.setdefault(
            flow,
            {"base_sequence": None, "highest_start": None, "highest_end": None},
        )
        payload = packet.dissection.payload

        if payload:
            ip_is_truncated = (
                packet.dissection.ipv4.is_truncated
                if packet.dissection.ipv4 is not None
                else packet.dissection.ipv6.is_truncated
                if packet.dissection.ipv6 is not None
                else False
            )
            if ip_is_truncated or packet.record.original_length > packet.record.captured_length:
                continue
            data_sequence = (tcp.sequence_number + int(tcp.is_syn)) & 0xFFFFFFFF
            if state["base_sequence"] is None:
                state["base_sequence"] = data_sequence
            relative_start = _signed_sequence_delta(
                data_sequence, int(state["base_sequence"])
            )
            relative_end = relative_start + len(payload)
            highest_start = state["highest_start"]
            highest_end = state["highest_end"]

            if highest_end is not None and relative_start < highest_end:
                if highest_start is not None and relative_end <= highest_start:
                    category = "Out-of-order segment"
                else:
                    category = "Possible retransmission / overlap"
            elif highest_start is not None and relative_start < highest_start:
                category = "Out-of-order segment"
            else:
                category = ""
            if category:
                diagnostics.append(
                    TCPDiagnostic(
                        packet_number=packet.number,
                        conversation=f"{endpoint_a} ↔ {endpoint_b}",
                        category=category,
                        detail=(
                            f"Sequence offset {relative_start}, payload {len(payload)} bytes; "
                            "classification is based on capture order."
                        ),
                    )
                )

            if highest_start is None or relative_start > highest_start:
                state["highest_start"] = relative_start
            if highest_end is None or relative_end > highest_end:
                state["highest_end"] = relative_end
        elif tcp.is_ack:
            ack_key = (endpoint_a, endpoint_b, str(direction), tcp.acknowledgment_number)
            ack_counts[ack_key] += 1
            if ack_counts[ack_key] == 2:
                diagnostics.append(
                    TCPDiagnostic(
                        packet_number=packet.number,
                        conversation=f"{endpoint_a} ↔ {endpoint_b}",
                        category="Repeated ACK",
                        detail=(
                            f"ACK {tcp.acknowledgment_number} repeated "
                            f"{ack_counts[ack_key]} times without payload."
                        ),
                    )
                )

    return tuple(diagnostics)


def _protocol_events(packet: ProcessedPacket) -> list[ProtocolEvent]:
    result = packet.dissection
    events: list[ProtocolEvent] = []

    if result.dns is not None:
        dns = result.dns
        questions = ", ".join(
            f"{question.name} ({question.type_name})"
            for question in dns.questions
        ) or "No question section"
        answer_text = f" · {len(dns.answers)} answer(s)" if dns.answers else ""
        kind = "response" if dns.is_response else "query"
        detail = f"{kind}: {questions}{answer_text}"
        if dns.is_response:
            detail += f" · {dns.rcode_name}"
        events.append(
            ProtocolEvent(packet.number, result.protocol, packet.source, packet.destination, detail)
        )

    if result.http is not None:
        http = result.http
        detail = http.start_line
        if http.host:
            detail += f" · Host: {http.host}"
        if http.content_type:
            detail += f" · {http.content_type}"
        events.append(
            ProtocolEvent(packet.number, "HTTP", packet.source, packet.destination, detail)
        )

    if result.tls is not None:
        tls = result.tls
        details: list[str] = [tls.handshake_name or tls.content_type_name]
        if tls.client_hello is not None:
            hello = tls.client_hello
            if hello.server_name:
                details.append(f"SNI: {hello.server_name}")
            if hello.alpn_protocols:
                details.append(f"ALPN: {', '.join(hello.alpn_protocols)}")
            if hello.supported_versions:
                details.append(
                    "Versions: " + ", ".join(f"0x{value:04x}" for value in hello.supported_versions)
                )
        if tls.server_hello is not None:
            hello = tls.server_hello
            version = hello.negotiated_version or hello.legacy_version
            details.append(f"Version: 0x{version:04x}")
            details.append(f"Cipher: 0x{hello.cipher_suite:04x}")
            if hello.alpn_protocol:
                details.append(f"ALPN: {hello.alpn_protocol}")
        events.append(
            ProtocolEvent(
                packet.number,
                "TLS",
                packet.source,
                packet.destination,
                " · ".join(details),
            )
        )

    for warning in result.errors:
        events.append(
            ProtocolEvent(
                packet.number,
                "Warning",
                packet.source,
                packet.destination,
                warning,
            )
        )

    return events


def _traffic_buckets(
    packets: list[ProcessedPacket] | tuple[ProcessedPacket, ...],
    bucket_limit: int = 48,
    should_stop: Callable[[], bool] | None = None,
) -> tuple[TrafficBucket, ...]:
    start: float | None = None
    end: float | None = None

    for packet in packets:
        _check_cancelled(should_stop)
        timestamp = packet.timestamp
        if timestamp is None:
            continue
        if start is None or timestamp < start:
            start = timestamp
        if end is None or timestamp > end:
            end = timestamp

    if start is None or end is None:
        return ()

    span = max(0.0, end - start)
    count = min(bucket_limit, max(1, int(span) + 1))
    width = span / count if span else 1.0
    packet_counts = [0] * count
    byte_counts = [0] * count

    for packet in packets:
        _check_cancelled(should_stop)
        if packet.timestamp is None:
            continue
        index = min(count - 1, int((packet.timestamp - start) / width)) if span else 0
        packet_counts[index] += 1
        byte_counts[index] += packet.length

    return tuple(
        TrafficBucket(
            start_timestamp=start + index * width,
            end_timestamp=(start + (index + 1) * width) if span else end,
            packet_count=packet_counts[index],
            byte_count=byte_counts[index],
        )
        for index in range(count)
    )


def analyze_capture(
    packets: Iterable[ProcessedPacket],
    *,
    should_stop: Callable[[], bool] | None = None,
) -> CaptureAnalysis:
    _check_cancelled(should_stop)
    if isinstance(packets, (list, tuple)):
        packet_list = packets
    else:
        packet_list = []
        for packet in packets:
            _check_cancelled(should_stop)
            packet_list.append(packet)

    protocols: Counter[str] = Counter()
    endpoints: Counter[str] = Counter()
    builders: dict[tuple[str, str, str], _ConversationBuilder] = {}
    tcp_count = 0
    udp_count = 0
    warning_count = 0
    byte_count = 0
    events: list[ProtocolEvent] = []

    for packet in packet_list:
        _check_cancelled(should_stop)
        protocols[packet.protocol] += 1
        byte_count += packet.length
        if packet.source != "—":
            endpoints[packet.source] += 1
        if packet.destination != "—":
            endpoints[packet.destination] += 1
        tcp_count += int(packet.dissection.tcp is not None)
        udp_count += int(packet.dissection.udp is not None)
        warning_count += int(bool(packet.dissection.errors))
        events.extend(_protocol_events(packet))

        endpoint_tuple = _transport_endpoints(packet)
        if endpoint_tuple is None:
            continue
        source, destination, transport = endpoint_tuple
        endpoint_a, endpoint_b = sorted((source, destination))
        key = (transport, endpoint_a, endpoint_b)
        builder = builders.get(key)
        if builder is None:
            builder = _ConversationBuilder(transport, endpoint_a, endpoint_b)
            builders[key] = builder
        builder.add(packet)

    _check_cancelled(should_stop)
    conversations = sorted(
        (builder.finish() for builder in builders.values()),
        key=lambda item: (item.packet_count, item.byte_count),
        reverse=True,
    )
    diagnostics = _tcp_diagnostics(packet_list, should_stop)
    buckets = _traffic_buckets(packet_list, should_stop=should_stop)

    return CaptureAnalysis(
        packet_count=len(packet_list),
        byte_count=byte_count,
        tcp_count=tcp_count,
        udp_count=udp_count,
        warning_count=warning_count,
        protocol_counts=tuple(protocols.most_common()),
        endpoint_counts=tuple(endpoints.most_common()),
        conversations=tuple(conversations),
        tcp_diagnostics=diagnostics,
        protocol_events=tuple(events),
        traffic_buckets=buckets,
    )
