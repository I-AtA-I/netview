from collections.abc import Iterator
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.utils import RawPcapNgReader, RawPcapReader

from netview.core.models import PacketRecord


class PcapReadError(ValueError):
    pass


def iter_capture_file(path: str | Path) -> Iterator[PacketRecord]:
    source = Path(path)

    try:
        reader = RawPcapReader(str(source))
    except (OSError, Scapy_Exception, ValueError) as exc:
        raise PcapReadError(
            f"Could not open capture file: {exc}"
        ) from exc

    try:
        is_pcapng = isinstance(reader, RawPcapNgReader)

        for number, (raw_data, metadata) in enumerate(reader, start=1):
            if is_pcapng:
                link_type = metadata.linktype
                wire_length = metadata.wirelen

                if metadata.tshigh is None or metadata.tslow is None:
                    timestamp = None
                else:
                    if metadata.tsresol <= 0:
                        raise PcapReadError(
                            f"Invalid timestamp resolution in packet {number}"
                        )

                    timestamp = (
                        (metadata.tshigh << 32) + metadata.tslow
                    ) / metadata.tsresol

            else:
                link_type = reader.linktype
                wire_length = metadata.wirelen

                resolution = (
                    1_000_000_000 if reader.nano else 1_000_000
                )

                timestamp = metadata.sec + metadata.usec / resolution

            try:
                packet = PacketRecord(
                    number=number,
                    timestamp=timestamp,
                    captured_length=len(raw_data),
                    original_length=wire_length,
                    link_type=link_type,
                    data=raw_data,
                )
            except ValueError as exc:
                raise PcapReadError(
                    f"Invalid packet {number}: {exc}"
                ) from exc

            yield packet

    except PcapReadError:
        raise
    except (OSError, Scapy_Exception, ValueError, OverflowError) as exc:
        raise PcapReadError(
            f"Error reading capture file: {exc}"
        ) from exc

    finally:
        reader.close()
