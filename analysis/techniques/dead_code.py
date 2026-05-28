from __future__ import annotations

from typing import Any, Dict


def score_dead_code(disasm: Dict[str, Any]) -> Dict[str, Any]:
    summary = disasm.get("summary", {}) if disasm else {}
    evidence = disasm.get("evidence", {}) if disasm else {}

    opaque_count = summary.get("basic_opaque_predicate_count", 0)
    sink_count = summary.get("cfg_sink_vertex_count", 0)
    sink_ratio = summary.get("cfg_sink_vertex_ratio", 0.0)
    instruction_count = summary.get("instruction_count", 0)
    cfg_block_count = summary.get("cfg_block_count", 0)
    opaque_ratio = opaque_count / max(instruction_count, 1)

    points = 0
    if opaque_count >= 8 and opaque_ratio >= 0.006:
        points += 18
    elif opaque_count >= 30 and opaque_ratio >= 0.003:
        points += 12
    if cfg_block_count >= 20 and sink_ratio >= 0.08:
        points += 12
    elif cfg_block_count >= 50 and sink_ratio >= 0.05:
        points += 8

    return {
        "score": min(points, 30),
        "opaque_predicate_count": opaque_count,
        "opaque_predicate_ratio": round(opaque_ratio, 6),
        "sink_vertex_count": sink_count,
        "sink_vertex_ratio": sink_ratio,
        "cfg_block_count": cfg_block_count,
        "evidence": {
            "opaque_predicates": evidence.get("basic_opaque_predicate_samples", [])[:8],
            "sink_vertices": evidence.get("sink_vertex_samples", [])[:8],
        },
    }
