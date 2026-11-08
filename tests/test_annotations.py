import json

import pytest

from netview.gui.annotations import (
    annotation_sidecar_path,
    load_annotations,
    save_annotations,
)


def test_sidecar_path_is_next_to_capture(tmp_path):
    capture = tmp_path / "office.pcap"
    assert annotation_sidecar_path(capture) == tmp_path / "office.pcap.netview.json"


def test_save_and_load_annotations(tmp_path):
    path = tmp_path / "notes.json"
    notes = {1: "Check the DNS query", 7: "Important TLS handshake"}

    save_annotations(path, notes)

    assert load_annotations(path) == notes


def test_missing_annotation_file_returns_empty_dict(tmp_path):
    assert load_annotations(tmp_path / "missing.json") == {}


def test_invalid_annotation_format_is_rejected(tmp_path):
    path = tmp_path / "notes.json"
    path.write_text(json.dumps({"version": 2, "annotations": {}}), encoding="utf-8")

    with pytest.raises(ValueError):
        load_annotations(path)


def test_invalid_note_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        save_annotations(tmp_path / "notes.json", {1: "x" * 5000})
