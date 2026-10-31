from __future__ import annotations

from pathlib import Path
from collections.abc import Iterator

from .live import LiveCaptureError, iter_pcap_stream, list_interfaces
from netview.core.models import PacketRecord


def iter_capture_file(path: str | Path) -> Iterator[PacketRecord]:
    """Lazily load the PCAP reader so live-capture helpers stay importable."""
    from .pcap import iter_capture_file as _iter_capture_file

    yield from _iter_capture_file(path)


def __getattr__(name: str):
    if name == "PcapReadError":
        from .pcap import PcapReadError

        return PcapReadError
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "PcapReadError",
    "iter_capture_file",
    "LiveCaptureError",
    "list_interfaces",
    "iter_pcap_stream",
]
