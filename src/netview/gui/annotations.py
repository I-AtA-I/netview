from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping


MAX_NOTE_LENGTH = 4096


def annotation_sidecar_path(capture_path: str | Path) -> Path:
    return Path(f"{Path(capture_path)}.netview.json")


def load_annotations(path: str | Path) -> dict[int, str]:
    annotation_file = Path(path)
    if not annotation_file.exists():
        return {}

    try:
        payload = json.loads(annotation_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read packet notes: {exc}") from exc

    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("Unsupported packet notes file format")

    raw_annotations = payload.get("annotations", {})
    if not isinstance(raw_annotations, dict):
        raise ValueError("Invalid packet notes: annotations must be an object")

    annotations: dict[int, str] = {}
    for raw_number, note in raw_annotations.items():
        try:
            number = int(raw_number)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid packet number in packet notes") from exc
        if number < 1 or not isinstance(note, str) or len(note) > MAX_NOTE_LENGTH:
            raise ValueError("Invalid packet note entry")
        if note.strip():
            annotations[number] = note
    return annotations


def save_annotations(path: str | Path, annotations: Mapping[int, str]) -> None:
    cleaned: dict[str, str] = {}
    for number, note in annotations.items():
        if not isinstance(number, int) or number < 1:
            raise ValueError("Packet numbers must be positive integers")
        if not isinstance(note, str) or len(note) > MAX_NOTE_LENGTH:
            raise ValueError("Packet notes must be text up to 4096 characters")
        if note.strip():
            cleaned[str(number)] = note

    annotation_file = Path(path)
    payload = {
        "version": 1,
        "annotations": dict(sorted(cleaned.items(), key=lambda item: int(item[0]))),
    }
    temporary_file = annotation_file.with_name(annotation_file.name + ".tmp")
    try:
        temporary_file.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_file.replace(annotation_file)
    except OSError:
        try:
            temporary_file.unlink(missing_ok=True)
        except OSError:
            pass
        raise
