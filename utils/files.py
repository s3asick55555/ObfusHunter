from __future__ import annotations

from pathlib import Path

from config import ALLOWED_EXTENSIONS


def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def safe_delete(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
