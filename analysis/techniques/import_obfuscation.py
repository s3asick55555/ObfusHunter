from __future__ import annotations

from typing import Any, Dict


def summarize_import_obfuscation(import_obf: Dict[str, Any]) -> Dict[str, Any]:
    if not import_obf:
        return {"score": 0}

    import_count = import_obf.get("import_count", 0)
    dynamic_apis = import_obf.get("dynamic_resolution_apis", [])
    has_loader = import_obf.get("has_loadlibrary", False)
    has_getproc = import_obf.get("has_getprocaddress", False)

    points = 0
    gate_reason = None
    if import_count >= 30:
        gate_reason = "import table is large; dynamic resolution alone is not strong evidence"
    elif dynamic_apis and (has_loader or has_getproc):
        if import_count <= 10:
            points += 18
        elif import_count <= 15:
            points += 12
        elif import_count <= 25:
            points += 8
        else:
            gate_reason = "import table size weakens dynamic resolution signal"

    return {
        "score": min(points, 30),
        "import_count": import_count,
        "dynamic_resolution_apis": dynamic_apis,
        "has_loadlibrary": has_loader,
        "has_getprocaddress": has_getproc,
        "evidence": import_obf.get("evidence", [])[:10],
        "gate_reason": gate_reason,
    }
