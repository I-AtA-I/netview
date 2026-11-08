import json

import pytest

from netview.filters.saved_filters import load_saved_filters, save_saved_filters


def test_saved_filters_round_trip_and_create_parent_directory(tmp_path):
    path = tmp_path / "config" / "netview" / "filters.json"
    filters = [
        ("HTTPS", "tcp.port == 443"),
        ("DNS", "dns"),
    ]

    save_saved_filters(filters, path)

    assert load_saved_filters(path) == filters


def test_saved_filters_validate_expressions(tmp_path):
    path = tmp_path / "filters.json"

    with pytest.raises(ValueError):
        save_saved_filters([("Broken", "tcp.port ==")], path)

    assert not path.exists()


def test_saved_filters_reject_duplicate_names(tmp_path):
    path = tmp_path / "filters.json"
    with pytest.raises(ValueError, match="already exists"):
        save_saved_filters([
            ("HTTPS", "tcp.port == 443"),
            ("https", "tcp.port == 80"),
        ], path)


def test_saved_filters_reject_malformed_json(tmp_path):
    path = tmp_path / "filters.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(ValueError, match="Could not read"):
        load_saved_filters(path)


def test_saved_filters_reject_invalid_schema(tmp_path):
    path = tmp_path / "filters.json"
    path.write_text(json.dumps({"filters": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="JSON list"):
        load_saved_filters(path)
