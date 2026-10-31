from __future__ import annotations

import re
import shutil
import struct
import subprocess
from collections.abc import Iterator
from typing import BinaryIO

from netview.core.models import PacketRecord


class LiveCaptureError(RuntimeError):
    """Raised when a live-capture operation cannot be completed."""


_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_MAX_CAPTURED_PACKET = 64 * 1024 * 1024


def _read_exact(stream: BinaryIO, size: int, *, allow_clean_eof: bool = False) -> bytes | None:
    chunks: list[bytes] = []
    remaining = size

    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            if not chunks and allow_clean_eof:
                return None
            if not chunks:
                raise LiveCaptureError("Capture stream ended unexpectedly")
            raise LiveCaptureError("Capture stream ended in the middle of a record")
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def iter_pcap_stream(stream: BinaryIO) -> Iterator[PacketRecord]:
    """Read classic PCAP records from a binary stream, including a live pipe."""
    magic = _read_exact(stream, 4)
    if magic not in _PCAP_MAGICS:
        raise LiveCaptureError("dumpcap returned an unsupported or invalid PCAP stream")

    byte_order, timestamp_resolution = _PCAP_MAGICS[magic]
    global_header = _read_exact(stream, 20)
    assert global_header is not None

    major, minor, _timezone, _sigfigs, snaplen, network = struct.unpack(
        f"{byte_order}HHIIII", global_header
    )
    if major != 2 or minor < 4:
        raise LiveCaptureError(f"Unsupported PCAP version {major}.{minor}")
    if snaplen == 0:
        raise LiveCaptureError("Invalid PCAP snapshot length")

    link_type = network & 0xFFFF
    packet_header = struct.Struct(f"{byte_order}IIII")
    packet_number = 0

    while True:
        header_bytes = _read_exact(
            stream,
            packet_header.size,
            allow_clean_eof=True,
        )
        if header_bytes is None:
            return

        seconds, subseconds, captured_length, original_length = packet_header.unpack(
            header_bytes
        )
        if captured_length > _MAX_CAPTURED_PACKET:
            raise LiveCaptureError(
                f"Captured packet is unexpectedly large ({captured_length} bytes)"
            )
        if captured_length > snaplen:
            raise LiveCaptureError(
                f"Captured packet length {captured_length} exceeds PCAP snaplen {snaplen}"
            )

        packet_data = _read_exact(stream, captured_length)
        assert packet_data is not None

        packet_number += 1
        timestamp = seconds + subseconds / timestamp_resolution
        try:
            yield PacketRecord(
                number=packet_number,
                timestamp=timestamp,
                captured_length=captured_length,
                original_length=original_length,
                link_type=link_type,
                data=packet_data,
            )
        except ValueError as exc:
            raise LiveCaptureError(
                f"Invalid packet {packet_number} in live capture: {exc}"
            ) from exc


def _parse_dumpcap_interfaces(output: str) -> list[str]:
    interfaces: list[str] = []
    for line in output.splitlines():
        match = re.match(r"^\s*\d+\.\s+(\S+)", line)
        if match:
            name = match.group(1)
            if name not in interfaces:
                interfaces.append(name)

    return sorted(
        interfaces,
        key=lambda name: (
            name.lower() in {"lo", "lo0", "loopback"},
            name.lower(),
        ),
    )


def list_interfaces() -> list[str]:
    """List interfaces through dumpcap, the privilege-separated capture helper."""
    executable = shutil.which("dumpcap")
    if executable is None:
        raise LiveCaptureError(
            "dumpcap was not found. On Arch Linux, install it with: "
            "sudo pacman -S wireshark-cli"
        )

    try:
        result = subprocess.run(
            [executable, "-D"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LiveCaptureError(f"Could not run dumpcap: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise LiveCaptureError(
            detail or f"dumpcap -D exited with status {result.returncode}"
        )

    interfaces = _parse_dumpcap_interfaces(result.stdout)
    if not interfaces and result.stderr.strip():
        raise LiveCaptureError(result.stderr.strip())
    return interfaces
