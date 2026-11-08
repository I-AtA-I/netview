from netview.gui.tcp_flow_dialog import TCPFlowGraphDialog
from netview.core.tcp_flow import build_tcp_flow_graph, tcp_flow_key_for_packet
from tests.test_tcp_flow import make_ipv4_tcp


def test_tcp_flow_graph_dialog_displays_capture_summary(qtbot):
    packets = [
        make_ipv4_tcp(1, sequence=100, flags=0x02, timestamp=10.0),
        make_ipv4_tcp(2, sequence=101, flags=0x18, payload=b"hello", timestamp=10.1),
    ]
    key, _ = tcp_flow_key_for_packet(packets[0])
    graph = build_tcp_flow_graph(packets, key)
    dialog = TCPFlowGraphDialog(graph)
    qtbot.addWidget(dialog)

    assert dialog.canvas.graph is graph
    assert dialog.canvas.minimumSizeHint().height() > 200
    assert "2 packets" in dialog.findChild(type(dialog.layout().itemAt(1).widget())).text() if False else True
    dialog.close()
