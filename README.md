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
- Add packet bookmarks and notes; notes can be saved to a JSON sidecar next to a capture and are loaded again when that capture is opened.
- Open a packet context menu for quick protocol/address/port filters, Follow TCP Stream, packet notes and clipboard copies.
- Export all or displayed packets to classic PCAP, multi-interface PCAPNG or packet-metadata CSV.
- Save and manage reusable display filters from Edit → Saved filters; filters are stored in the user's NetView configuration directory.
- Review capture-wide protocol distribution, top endpoints, TCP/UDP conversations, bytes, durations and a packet-rate timeline in the Analysis Center (Ctrl+Shift+S).
- Inspect TCP sequence overlaps, possible retransmissions, out-of-order observations and repeated ACKs using capture-based heuristics.
- Browse consolidated DNS, HTTP/1.x, TLS handshake metadata and dissection warnings, then jump from an event or conversation to its packet.
- Highlight protocol families and dissection warnings directly in the packet list.
- Filter packets with the built-in display-filter language.
- Load capture files in a background thread so the interface stays responsive during import.
- Capture packets live from one manually selected network interface.
- Pause and resume a live capture without ending the capture session or clearing the packets already collected.
- Stop live capture without closing the application; captured packets remain available for filtering and inspection.
- Reassemble IPv4/TCP conversations in both directions, including out-of-order segments, sequence wraparound, overlaps/retransmissions and explicit sequence gaps.
- Visualize IPv4 and IPv6 TCP conversations as a scrollable sequence graph with direction, capture time, SEQ/ACK values, flags, payload lengths and possible sequence overlaps (Ctrl+Shift+G).
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
arp
ipv6
icmp
icmpv6
dns
mdns
llmnr
http
tls
dns.qry.name == example.com
dns.qry.type == 28
http.host == example.com
http.request.method == GET
http.response.code == 200
tls.sni == example.com
tls.handshake.type == 1
tcp
udp
arp.opcode == 1
arp.src.proto_ipv4 == 192.0.2.10
ipv6.src == 2001:db8::1
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

Supported fields and operators are implemented in `src/netview/filters/engine.py`. The filter engine supports common ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP and TLS predicates. String values can be quoted when they contain spaces or filter operators, for example `http.request.uri == "/search?q=netview"`. IPv6 extension headers supported by the dissection engine are Hop-by-Hop Options, Routing, Fragment, AH, Destination Options, Mobility, HIP and Shim6. IPv6 jumbograms are not implemented.

## Current scope and limitations

NetView is an early portfolio project, not a replacement for Wireshark. Application dissection is currently packet-based: a DNS message, HTTP/1.x start line and header block, or TLS record/hello must be sufficiently present in the captured packet. Application messages split across multiple TCP segments are not yet reassembled for application decoding, even though a separate Follow TCP Stream view is available. DNS-over-TLS, DNS-over-HTTPS, HTTP/2 and HTTP/3 are not decoded. HTTP parsing deliberately omits credential-bearing Cookie and Authorization headers and does not parse message bodies. TLS support is metadata-only: NetView does not decrypt TLS application data. TLS 1.3 encrypts most handshake messages after ServerHello, and Encrypted ClientHello (ECH) can hide the server name; in those cases SNI may not be available. Checksum validation, IP fragment reassembly and TCP connection-reuse detection remain future work. TCP stream reconstruction currently groups IPv4 conversations by the endpoint/port tuple; reused tuples within one capture can therefore be combined. The separate TCP Flow Graph supports unfragmented IPv4 and IPv6 TCP conversations. Fragmented TCP packets are excluded until IP fragment reassembly is implemented. Sequence gaps are reported only between observed payload segments, because a missing tail cannot be inferred reliably.

Live capture uses `dumpcap` on one interface selected by the user. Promiscuous mode is explicitly disabled. On Linux, `dumpcap` must have the operating-system capture permissions configured; do not run the GUI, IDE, or Python interpreter as root just to bypass a permission error.

Only capture traffic on your own device and networks, or where you have explicit permission to monitor. Captured traffic may contain private information.

The GUI uses a dedicated capture sidebar and a packet workspace with protocol-aware row accents, a decoded-layer inspector and a raw byte view. Selecting a mapped protocol field highlights its corresponding captured bytes in the hex view; fields for which a reliable byte offset is not available remain unhighlighted. The Analysis Center works across the full capture and is independent of the active display filter. TCP sequence indicators are explicitly heuristic: capture gaps, truncation and capture order can resemble retransmission or reordering, so NetView does not label them as proven packet loss. TLS analysis reports visible handshake metadata only and never decrypts application data. Packet notes are stored separately from the PCAP in a *.netview.json sidecar file and can be saved with File → Save packet notes. The application loads packets into memory after reading them in batches. It keeps the UI responsive during import, but very large capture files can still consume substantial memory.

## Project layout

```text
src/netview/
├── app.py
├── capture/       # PCAP/PCAPNG reader and live capture helpers
├── core/          # packet models, protocol parsers, capture analytics and TCP reassembly
├── filters/       # display-filter parser and evaluator
└── gui/           # PySide6 window, notes, analysis center, capture workers and stream viewer

tests/             # parser, pipeline, capture and filter tests
```

## Authorization

Only inspect packet captures that you own or are authorized to analyze. Use live capture only on interfaces and networks you are permitted to monitor.

## Troubleshooting

### `ModuleNotFoundError: No module named 'tests'`

The test suite is a local Python package. Keep `tests/__init__.py` in place when running `pytest` from the repository root:

```bash
pytest -v
```

### Qt reports `Failed to create wl_display`

This means Qt selected its Wayland platform plugin but could not connect to a Wayland display. In an X11 desktop session (for example XFCE), try launching with the XCB platform plugin:

```bash
QT_QPA_PLATFORM=xcb python -m netview
```

Do not set this globally unless you specifically need it; on a working Wayland session, the default platform selection should be allowed.


## Analysis and navigation

- Ctrl+F opens packet search. Search continues after the current packet and wraps to the beginning.
- Ctrl+B adds or edits a note for the selected packet. A star appears in the packet row while a note exists.
- Ctrl+Shift+E opens the packet-note save dialog. For file captures, the default path is the capture filename followed by .netview.json; opening that capture loads the sidecar automatically.
- Ctrl+Shift+S opens the Analysis Center. Double-click a conversation, TCP diagnostic or protocol event to select its packet in the main workspace.
- Selecting a decoded field highlights its known byte range in the hexadecimal viewer. Byte ranges are only attached where parser offsets are reliable.

The Analysis Center includes:
- protocol and endpoint summaries, top conversations and a time-bucket packet chart;
- conversation endpoints, packet and byte counts, duration and first-frame navigation;
- TCP segment overlap/reordering and repeated-ACK indicators;
- DNS, HTTP and TLS metadata events with packet navigation.

TCP anomaly labels are heuristic observations from the captured sequence and ACK values. They are not proof of packet loss or a network fault. The TCP analysis does not fabricate missing bytes. TLS details are limited to metadata visible in the capture; encrypted application data is not decoded.


### Pause and resume live capture

On Linux and other POSIX systems, use **Capture → Pause live capture** or the sidebar button to temporarily suspend the running `dumpcap` process. Resume with the same control. The capture session, packet list, packet numbering and selected interface are retained; the interval while paused is simply not captured. **Stop capture** still ends the session. Pausing and resuming does not restart `dumpcap`.


### Packet workflow

Right-click a packet to apply a protocol, endpoint, port or frame-number filter; follow an IPv4/TCP stream; edit its note; or copy packet metadata and raw bytes. The File → Export packets submenu exports either the complete capture or only the rows currently displayed after filtering. Classic PCAP requires a single link type; use PCAPNG when a capture contains more than one link type. CSV contains packet metadata, not raw payload bytes.

Saved display filters are managed from Edit → Saved filters. The filter manager validates expressions before saving them and stores them in the NetView user configuration directory (under .config/netview, or the directory selected by XDG_CONFIG_HOME).


### TCP Flow Graph

Select an unfragmented IPv4 or IPv6 TCP packet and use Analyze → TCP Flow Graph (Ctrl+Shift+G), or right-click the packet and choose TCP Flow Graph. The graph shows packets in capture order between the two endpoints, including the direction, relative capture time, sequence number, acknowledgement number, TCP flags and captured payload length. Long conversations can be browsed with the scroll bars.

Orange events mark sequence ranges that overlap an earlier observed range in the same direction. This is a capture-order heuristic: overlap can be consistent with retransmission, but it is not proof of packet loss or a network fault. Truncated packets are labelled separately, and no missing payload bytes are invented.
