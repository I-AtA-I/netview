from collections import Counter, defaultdict
from dataclasses import dataclass
from math import floor
from collections.abc import Iterable

from .pipeline import ProcessedPacket


@dataclass(frozen=True, slots=True)
class ProtocolStat:
    protocol: str
    packets: int
    bytes: int


@dataclass(frozen=True, slots=True)
class EndpointStat:
    endpoint: str
    packets: int
    bytes: int


@dataclass(frozen=True, slots=True)
class ConversationStat:
    protocol: str
    endpoint_a: str
    endpoint_b: str
    packets: int
    bytes: int


@dataclass(frozen=True, slots=True)
class TimelinePoint:
    timestamp: float
    packets: int
    bytes: int


@dataclass(frozen=True, slots=True)
class CaptureStats:
    packet_count: int
    captured_bytes: int
    wire_bytes: int
    start_time: float | None
    end_time: float | None
    duration: float
    protocols: tuple[ProtocolStat, ...]
    top_talkers: tuple[EndpointStat, ...]
    conversations: tuple[ConversationStat, ...]
    timeline: tuple[TimelinePoint, ...]


def _endpoint(packet: ProcessedPacket, source: bool) -> str:
    address = packet.source if source else packet.destination
    port = packet.source_port if source else packet.destination_port
    if port is not None and address != "—":
        return f"{address}:{port}"
    return address


def analyze_capture(
    packets: Iterable[ProcessedPacket],
    bucket_seconds: float = 1.0,
    top_n: int = 10,
) -> CaptureStats:
    if bucket_seconds <= 0:
        raise ValueError("Timeline bucket must be positive")
    if top_n < 1:
        raise ValueError("top_n must be positive")

    protocol_counts: Counter[str] = Counter()
    protocol_bytes: Counter[str] = Counter()
    endpoint_packets: Counter[str] = Counter()
    endpoint_bytes: Counter[str] = Counter()
    conversation_data: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
    timeline_data: dict[float, list[int]] = defaultdict(lambda: [0, 0])
    timestamps: list[float] = []
    packet_count = captured_bytes = wire_bytes = 0

    for packet in packets:
        packet_count += 1
        captured_bytes += packet.record.captured_length
        wire_bytes += packet.record.original_length
        protocol_counts[packet.protocol] += 1
        protocol_bytes[packet.protocol] += packet.record.original_length

        src = packet.source
        dst = packet.destination
        endpoint_packets[src] += 1
        endpoint_bytes[src] += packet.record.original_length
        endpoint_packets[dst] += 1
        endpoint_bytes[dst] += packet.record.original_length

        if packet.source_port is not None and packet.destination_port is not None:
            left = _endpoint(packet, True)
            right = _endpoint(packet, False)
            endpoint_a, endpoint_b = sorted((left, right))
            transport = "TCP" if packet.dissection.tcp is not None else "UDP"
            key = (transport, endpoint_a, endpoint_b)
            conversation_data[key][0] += 1
            conversation_data[key][1] += packet.record.original_length

        if packet.timestamp is not None:
            timestamp = packet.timestamp
            timestamps.append(timestamp)
            bucket = floor(timestamp / bucket_seconds) * bucket_seconds
            timeline_data[bucket][0] += 1
            timeline_data[bucket][1] += packet.record.original_length

    protocols = tuple(
        ProtocolStat(name, count, protocol_bytes[name])
        for name, count in protocol_counts.most_common()
    )
    top_talkers = tuple(
        EndpointStat(name, endpoint_packets[name], size)
        for name, size in endpoint_bytes.most_common(top_n)
    )
    conversations = tuple(
        ConversationStat(protocol, left, right, values[0], values[1])
        for (protocol, left, right), values in sorted(
            conversation_data.items(),
            key=lambda item: item[1][1],
            reverse=True,
        )[:top_n]
    )
    timeline = tuple(
        TimelinePoint(timestamp, values[0], values[1])
        for timestamp, values in sorted(timeline_data.items())
    )

    start_time = min(timestamps) if timestamps else None
    end_time = max(timestamps) if timestamps else None

    return CaptureStats(
        packet_count=packet_count,
        captured_bytes=captured_bytes,
        wire_bytes=wire_bytes,
        start_time=start_time,
        end_time=end_time,
        duration=(end_time - start_time) if start_time is not None and end_time is not None else 0.0,
        protocols=protocols,
        top_talkers=top_talkers,
        conversations=conversations,
        timeline=timeline,
    )
