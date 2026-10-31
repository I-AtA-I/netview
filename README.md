# NetView

NetView is a desktop network protocol analyzer built with Python and PySide6. It reads PCAP/PCAPNG captures, dissects supported protocols with its own parser, and provides a Wireshark-inspired packet browsing interface.

## Current features

- Read classic PCAP and PCAPNG capture files.
- Decode Ethernet II, VLAN, IPv4, TCP and UDP headers.
- Display packet metadata, protocol details and a raw hexadecimal/ASCII view.
- Filter packets with the built-in display-filter language.
- Load capture files in a background thread so the interface stays responsive during import.
- Drag and drop capture files into the application.

## Requirements

- Python 3.10 or newer
- PySide6 6.12 or newer
- Scapy 2.8 or newer (used for PCAP/PCAPNG container reading)

## Setup on Linux

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run the application:

```bash
netview
```

Or:

```bash
python -m netview
```

Run tests:

```bash
pytest -v
```

## Display filter examples

```text
tcp
udp
ip.src == 192.0.2.10
tcp.port == 443
udp.port == 53
tcp.flags.syn == true
frame.len > 1000
tcp and ip.src == 192.0.2.10
tcp or udp
not tcp
(tcp or udp) and ip
```

Supported fields and operators are implemented in `src/netview/filters/engine.py`. The initial filter engine supports IPv4 fields; IPv6 decoding and filtering are not implemented yet.

## Current scope and limitations

NetView is an early portfolio project, not a replacement for Wireshark. The current dissection engine supports Ethernet II/VLAN, IPv4, TCP and UDP. IPv6, ICMP decoding, checksum validation, fragment reassembly, live capture, TCP stream reconstruction and advanced protocol decoding remain future work.

The first GUI version loads packets into memory after reading them in batches. It keeps the UI responsive during import, but very large capture files can still consume substantial memory.

## Project layout

```text
src/netview/
├── app.py
├── capture/       # PCAP and PCAPNG reader
├── core/          # packet models, protocol parsers and dissection pipeline
├── filters/       # display-filter parser and evaluator
└── gui/           # PySide6 window, packet table model and loading worker

tests/             # parser, pipeline, capture and filter tests
```

## Authorization

Only inspect packet captures that you own or are authorized to analyze. Live capture, when added, should be used only on interfaces and networks you are permitted to monitor.
