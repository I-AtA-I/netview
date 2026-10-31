# NetView

A Python desktop network protocol analyzer. This repository currently contains the packet-processing foundation; the PySide6 desktop interface is planned for a later milestone.

## Current capabilities

- Ethernet II frame parsing, including 802.1Q / 802.1ad VLAN tags
- IPv4 header parsing, options, fragmentation metadata, and truncation handling
- TCP and UDP header parsing
- Ethernet/IPv4/TCP/UDP dissection pipeline
- PCAP and PCAPNG reading through Scapy's raw readers
- Unified `PacketRecord` and `ProcessedPacket` models
- A small display-filter language with `and`, `or`, `not`, parentheses, protocol names, addresses, ports, TCP flags, and frame lengths
- Automated tests for parsers, capture reading, pipeline, and filters

Scapy is used for capture-file reading only. The Ethernet, IPv4, TCP, UDP, dissection, and filter logic in this project is implemented in NetView.

## Requirements

- Python 3.10 or newer
- pip

The project is developed and tested with Python 3.14.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Run tests

```bash
pytest -v
```

## Basic usage

```python
from netview.capture import iter_capture_file
from netview.core import iter_processed_packets
from netview.filters import iter_filtered_packets

packets = iter_capture_file("capture.pcapng")
processed = iter_processed_packets(packets)

for packet in iter_filtered_packets(processed, "tcp.port == 443"):
    print(packet.number, packet.source, packet.destination, packet.info)
```

Supported initial filter examples:

```text
tcp
udp
ip.src == 192.0.2.1
tcp.port == 443
tcp.flags.syn == true
frame.len > 1000
tcp and ip.src == 192.0.2.1
(tcp or udp) and ip
not tcp
```

## Current limitations

- IPv6 parsing is not implemented yet.
- ICMP is identified by IPv4 protocol number but its header is not decoded yet.
- TCP/UDP checksum validation and IPv4 fragment reassembly are not implemented.
- Live packet capture and the graphical interface are not implemented yet.
- Display filters currently support IPv4 fields only.

## Project layout

```text
netview/
├── src/netview/
│   ├── capture/       # PCAP and PCAPNG input
│   ├── core/          # models, protocol parsers, dissection, pipeline
│   ├── filters/       # display-filter parser and evaluator
│   └── gui/           # future PySide6 interface
├── tests/
├── .gitignore
├── pyproject.toml
└── README.md
```
