from netview.gui.filter_manager import FilterManagerDialog


def test_filter_manager_saves_multiple_filters_and_applies_selected(
    qtbot, monkeypatch
):
    monkeypatch.setattr(
        "netview.gui.filter_manager.load_saved_filters",
        lambda: [],
    )
    saved = []
    monkeypatch.setattr(
        "netview.gui.filter_manager.save_saved_filters",
        lambda filters: saved.append(list(filters)),
    )

    dialog = FilterManagerDialog("tcp.port == 443")
    qtbot.addWidget(dialog)

    dialog.name_input.setText("HTTPS")
    dialog.save_filter()
    assert saved[-1] == [("HTTPS", "tcp.port == 443")]

    dialog.new_button.click()
    assert dialog.filter_list.currentRow() == -1
    dialog.name_input.setText("DNS")
    dialog.expression_input.setText("dns")
    dialog.save_filter()
    assert saved[-1] == [
        ("HTTPS", "tcp.port == 443"),
        ("DNS", "dns"),
    ]

    applied = []
    dialog.filter_applied.connect(applied.append)
    dialog.apply_selected()
    assert applied == ["dns"]
    dialog.close()
