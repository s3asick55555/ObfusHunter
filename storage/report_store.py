from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


def save_report(report_dir: Path, payload: Dict[str, Any]) -> str:
    report_id = uuid.uuid4().hex
    report_path = report_dir / f"{report_id}.json"
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return report_id


def load_report(report_dir: Path, report_id: str) -> Optional[Dict[str, Any]]:
    report_path = report_dir / f"{report_id}.json"
    if not report_path.exists():
        return None
    return json.loads(report_path.read_text(encoding="utf-8"))
