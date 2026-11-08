from netview.gui.tcp_flow_worker import TCPFlowWorker
from netview.core.tcp_flow import build_tcp_flow_graph, tcp_flow_key_for_packet
from tests.test_tcp_flow import make_ipv4_tcp


def test_flow_worker_emits_graph_for_selected_conversation(qtbot):
    packet = make_ipv4_tcp(1, sequence=100, payload=b"data", timestamp=10.0)
    key, _ = tcp_flow_key_for_packet(packet)
    worker = TCPFlowWorker((packet,), key)
    received = []
    worker.graph_ready.connect(received.append)
    qtbot.waitSignal(worker.graph_ready, timeout=3000)
    worker.start()
    worker.wait()

    assert len(received) == 1
    assert received[0].packet_count == 1
