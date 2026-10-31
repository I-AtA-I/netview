# NetView

NetView is a desktop network protocol analyzer built with Python and PySide6. It reads PCAP/PCAPNG captures, dissects supported protocols with its own parser, and provides a Wireshark-inspired packet browsing interface.

## Current features

- Read classic PCAP and PCAPNG capture files.
- Decode Ethernet II, VLAN, IPv4, TCP and UDP headers.
- Display packet metadata, protocol details and a raw hexadecimal/ASCII view.
- Filter packets with the built-in display-filter language.
- Load capture files in a background thread so the interface stays responsive during import.
- Capture packets live from one manually selected network interface.
- Stop live capture without closing the application; captured packets remain available for filtering and inspection.
- Keep promiscuous mode disabled by default.
- Drag and drop capture files into the application.

## Requirements

- Python 3.10 or newer
- PySide6 6.12 or newer
- Scapy 2.8 or newer (used for PCAP/PCAPNG file reading)
- `dumpcap` from Wireshark CLI (used for live capture on Linux)

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

## Live capture permissions on Arch Linux

NetView keeps the GUI running as your normal user. Live capture is delegated to `dumpcap`, rather than granting raw-packet privileges to the Python interpreter or running the whole GUI as root.

Install the capture helper:

```bash
sudo pacman -S wireshark-cli
```

Add your account to the `wireshark` group:

```bash
sudo usermod -aG wireshark "$USER"
```

Then fully log out of your desktop session and log back in. Verify the new group membership and that `dumpcap` can list interfaces:

```bash
id -nG
dumpcap -D
```

Start NetView normally, without `sudo`:

```bash
netview
```

NetView invokes `dumpcap` for one manually selected interface and passes packets to its own dissection engine. Promiscuous mode is disabled. The package-managed `dumpcap` permissions are preferable to giving elevated network capabilities to `/usr/bin/python` or the entire GUI application.

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

NetView is an early portfolio project, not a replacement for Wireshark. The current dissection engine supports Ethernet II/VLAN, IPv4, TCP and UDP. IPv6, ICMP decoding, checksum validation, fragment reassembly, TCP stream reconstruction and advanced protocol decoding remain future work.

Live capture uses `dumpcap` on one interface selected by the user. Promiscuous mode is explicitly disabled. On Linux, `dumpcap` must have the operating-system capture permissions configured; do not run the GUI, IDE, or Python interpreter as root just to bypass a permission error.

Only capture traffic on your own device and networks, or where you have explicit permission to monitor. Captured traffic may contain private information.

The first GUI version loads packets into memory after reading them in batches. It keeps the UI responsive during import, but very large capture files can still consume substantial memory.

## Project layout

```text
src/netview/
├── app.py
├── capture/       # PCAP/PCAPNG reader and live capture helpers
├── core/          # packet models, protocol parsers and dissection pipeline
├── filters/       # display-filter parser and evaluator
└── gui/           # PySide6 window, packet table model and capture workers

tests/             # parser, pipeline, capture and filter tests
```

## Authorization

Only inspect packet captures that you own or are authorized to analyze. Use live capture only on interfaces and networks you are permitted to monitor.
