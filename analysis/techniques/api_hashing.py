from __future__ import annotations

from typing import Any, Dict


def score_api_hashing(disasm: Dict[str, Any], import_obf: Dict[str, Any]) -> Dict[str, Any]:
    summary = disasm.get("summary", {}) if disasm else {}
    evidence = disasm.get("evidence", {}) if disasm else {}

    rotate_count = summary.get("rotate_count", 0)
    segment_access = summary.get("segment_peb_access_count", 0)
    import_count = import_obf.get("import_count", 0)
    has_getproc = import_obf.get("has_getprocaddress", False)

    points = 0
    if rotate_count >= 2 and import_count <= 15 and not has_getproc:
        points += 18
    if rotate_count >= 2 and segment_access:
        points += 10

    return {
        "score": min(points, 30),
        "rotate_count": rotate_count,
        "segment_peb_access_count": segment_access,
        "import_count": import_count,
        "has_getprocaddress": has_getproc,
        "evidence": {
            "rotate_samples": evidence.get("rotate_samples", [])[:6],
            "segment_peb_access_samples": evidence.get("segment_peb_access_samples", [])[:6],
        },
    }
