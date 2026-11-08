from netview.core import PacketRecord, process_packet
from netview.gui.main_window import MainWindow


def make_tcp_packet():
    ethernet = bytes.fromhex("aabbccddeeff1122334455660800")
    ipv4 = bytearray(20)
    ipv4[0] = 0x45
    ipv4[2:4] = (40).to_bytes(2, "big")
    ipv4[8] = 64
    ipv4[9] = 6
    ipv4[12:16] = bytes((192, 0, 2, 10))
    ipv4[16:20] = bytes((198, 51, 100, 20))

    tcp = bytearray(20)
    tcp[0:2] = (51515).to_bytes(2, "big")
    tcp[2:4] = (443).to_bytes(2, "big")
    tcp[4:8] = (1000).to_bytes(4, "big")
    tcp[8:12] = (2000).to_bytes(4, "big")
    tcp[12] = 0x50
    tcp[13] = 0x18
    frame = ethernet + bytes(ipv4) + bytes(tcp)

    return process_packet(PacketRecord(
        number=1,
        timestamp=1.0,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    ))


def test_packet_context_menu_builds_filters_and_stream_action(qtbot, monkeypatch):
    monkeypatch.setattr("netview.gui.main_window.list_interfaces", lambda: ["lo"])
    window = MainWindow()
    qtbot.addWidget(window)

    packet = make_tcp_packet()
    menu = window._build_packet_context_menu(packet)
    menu_actions = [action.text() for action in menu.actions()]
    filter_menu = menu.actions()[0].menu()
    filter_actions = {action.text(): action for action in filter_menu.actions()}

    assert "TCP Flow Graph" in menu_actions
    assert "Follow TCP Stream" in menu_actions
    assert "Copy packet bytes (hex)" in menu_actions
    assert "Protocol: TCP" in filter_actions
    assert "IPv4 source" in filter_actions
    assert "TCP destination port" in filter_actions

    filter_actions["Protocol: TCP"].trigger()
    assert window.filter_input.text() == "tcp"

    window.model.append_packets([packet])
    window._selected_packet = packet
    window._update_capture_controls()
    assert window.tcp_flow_action.isEnabled()

    window.close()


def test_export_actions_enable_when_capture_has_packets(qtbot, monkeypatch):
    monkeypatch.setattr("netview.gui.main_window.list_interfaces", lambda: ["lo"])
    window = MainWindow()
    qtbot.addWidget(window)

    window.model.append_packets([make_tcp_packet()])
    window._update_capture_controls()

    assert window.export_all_action.isEnabled()
    assert window.export_displayed_action.isEnabled()

    window.close()
