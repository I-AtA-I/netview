from __future__ import annotations

import json
import os
from pathlib import Path
from collections.abc import Iterable

from netview.filters.engine import compile_filter


def default_saved_filters_path() -> Path:
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_root / "netview" / "saved_filters.json"


def _validated_filters(filters: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    names: set[str] = set()
    for name, expression in filters:
        clean_name = name.strip()
        clean_expression = expression.strip()
        if not clean_name:
            raise ValueError("Filter name cannot be empty")
        if not clean_expression:
            raise ValueError("Filter expression cannot be empty")
        key = clean_name.casefold()
        if key in names:
            raise ValueError(f"A filter named '{clean_name}' already exists")
        compile_filter(clean_expression)
        names.add(key)
        result.append({"name": clean_name, "expression": clean_expression})
    return result


def load_saved_filters(path: str | Path | None = None) -> list[tuple[str, str]]:
    source = Path(path) if path is not None else default_saved_filters_path()
    if not source.exists():
        return []
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read saved filters: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError("Saved filters file must contain a JSON list")

    filters: list[tuple[str, str]] = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Saved filter {index} must be an object")
        name = item.get("name")
        expression = item.get("expression")
        if not isinstance(name, str) or not isinstance(expression, str):
            raise ValueError(f"Saved filter {index} must have a name and expression")
        filters.append((name, expression))
    _validated_filters(filters)
    return filters


def save_saved_filters(
    filters: Iterable[tuple[str, str]],
    path: str | Path | None = None,
) -> Path:
    destination = Path(path) if path is not None else default_saved_filters_path()
    payload = _validated_filters(filters)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return destination
