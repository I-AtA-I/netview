# NetView

NetView is a desktop network protocol analyzer built with Python and PySide6. It reads PCAP/PCAPNG captures, dissects supported protocols with its own parser, and provides a Wireshark-inspired packet browsing interface.

## Current features

- Read classic PCAP and PCAPNG capture files.
- Decode Ethernet II, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6 headers.
- Dissect DNS over UDP/TCP, including questions and common A, AAAA, name, MX and TXT records.
- Dissect HTTP/1.x request/response start lines and selected non-credential headers.
- Dissect TLS records plus ClientHello/ServerHello metadata such as SNI, ALPN, supported versions and cipher suites.
- Identify common non-decoded Ethernet protocols such as LLDP, EAPOL, MPLS and PPPoE by EtherType.
- Display packet metadata, protocol details and a raw hexadecimal/ASCII view with field-to-byte highlighting for decoded Ethernet, ARP, IPv4/IPv6, TCP, UDP and ICMP fields.
- Search packet numbers, endpoints, protocols, packet summaries and parsed DNS/HTTP/TLS metadata with Ctrl+F.
- Add packet bookmarks and notes; notes can be saved to a JSON sidecar next to a capture and are loaded again when that capture is opened. NetView warns about unsaved note changes before replacing a capture, starting live capture or closing the application.
- Open a packet context menu for quick protocol/address/port filters, Follow TCP Stream, packet notes and clipboard copies.
- Export all or displayed packets to classic PCAP, multi-interface PCAPNG or packet-metadata CSV.
- Save and manage reusable display filters from Edit → Saved filters; filters are stored in the user's NetView configuration directory.
- Review capture-wide protocol distribution, top endpoints, TCP/UDP conversations, bytes, durations and a packet-rate timeline in the Analysis Center (Ctrl+Shift+S).
- Inspect TCP sequence overlaps, possible retransmissions, out-of-order observations and repeated ACKs using capture-based heuristics.
- Browse consolidated DNS, HTTP/1.x, TLS handshake metadata and dissection warnings, then jump from an event or conversation to its packet.
- Highlight protocol families and dissection warnings directly in the packet list.
- Filter packets with the built-in display-filter language.
- Load capture files in a background thread so the interface stays responsive during import.
- Build capture-wide Analysis Center summaries in a background thread.
- Capture packets live from one manually selected network interface.
- Pause and resume a live capture without ending the capture session or clearing the packets already collected.
- Stop live capture without closing the application; captured packets remain available for filtering and inspection.
- Reassemble IPv4 and IPv6 TCP conversations in both directions, including out-of-order segments, sequence wraparound, overlaps/retransmissions and explicit sequence gaps.
- Visualize IPv4 and IPv6 TCP conversations as a scrollable sequence graph with direction, capture time, SEQ/ACK values, flags, payload lengths and possible sequence overlaps (Ctrl+Shift+G).
- Keep promiscuous mode disabled by default.
- Drag and drop capture files into the application.

## Requirements

- Python 3.10 or newer
- PySide6 6.12 or newer
- Scapy 2.8 or newer (used for PCAP/PCAPNG file reading)
- `dumpcap` from Wireshark CLI (used for live capture)
- On Windows, Npcap is required for live packet capture.

NetView can open existing PCAP and PCAPNG files without a live-capture driver. Live capture requires the platform-specific capture support described below.

## Setup on Windows

### 1. Install Wireshark and Npcap

Download the official Wireshark Windows installer:

https://www.wireshark.org/download.html

The Wireshark installer includes the Npcap installer. Make sure Npcap is installed; without it, NetView can still open saved captures, but live capture will not work.

The default Wireshark installation directory is:

```text
C:\Program Files\Wireshark
