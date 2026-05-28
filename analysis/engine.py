from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict

from .disasm import summarize_disassembly
from .pe import analyze_pe
from .techniques.api_hashing import score_api_hashing
from .techniques.dead_code import score_dead_code
from .techniques.import_obfuscation import summarize_import_obfuscation
from .techniques.pe_packing import detect_packing
from .techniques.string_xor import detect_xor_strings


def sha256_file(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()



def summarize_packing(packing: Dict[str, Any]) -> Dict[str, Any]:
    points = 0
    if packing.get("packer_section_names"):
        points += 20
    if packing.get("high_entropy_sections"):
        points += 18
    if packing.get("writable_executable_sections"):
        points += 12

    return {
        "score": min(points, 30),
        **packing,
    }


def summarize_xor(xor_result: Dict[str, Any], disasm: Dict[str, Any]) -> Dict[str, Any]:
    summary = disasm.get("summary", {}) if disasm else {}
    evidence = disasm.get("evidence", {}) if disasm else {}

    points = 0
    best_text_score = 0.0
    for hit in xor_result.get("hits", []):
        best_text_score = max(best_text_score, hit.get("best_text_score", 0.0))
    if xor_result.get("xor_keys"):
        points += 10
        if best_text_score >= 0.8:
            points += 6
    if summary.get("memory_xor_immediate_count", 0):
        points += 5
    if summary.get("stack_string_xor_count", 0):
        points += 7

    xor_result = dict(xor_result)
    xor_result["stack_string_xor_count"] = summary.get("stack_string_xor_count", 0)
    xor_result["memory_xor_immediate_count"] = summary.get("memory_xor_immediate_count", 0)
    xor_result["evidence"] = {
        "memory_xor_immediate_samples": evidence.get("memory_xor_immediate_samples", [])[:6],
        "stack_string_xor_samples": evidence.get("stack_string_xor_samples", [])[:6],
    }
    xor_result["best_text_score"] = round(best_text_score, 3)
    xor_result["score"] = min(points, 30)

    return xor_result


def build_indicators(techniques: Dict[str, Dict[str, Any]]) -> list[Dict[str, Any]]:
    indicators = []

    def add(technique: str, indicator: str, points: int, severity: str, reason: str, evidence: Any = None):
        item = {
            "technique": technique,
            "indicator": indicator,
            "points": points,
            "severity": severity,
            "reason": reason,
        }
        if evidence:
            item["evidence"] = evidence
        indicators.append(item)

    packing = techniques["pe_packing"]
    if packing.get("packer_section_names"):
        add(
            "PE Packing",
            "Packer-like section name",
            20,
            "HIGH",
            "Known packer section names were found.",
            evidence=packing.get("packer_section_names", [])[:6],
        )
    if packing.get("high_entropy_sections"):
        add(
            "PE Packing",
            "High entropy sections",
            18,
            "HIGH",
            "Entropy indicates packed or encrypted payload.",
            evidence=packing.get("high_entropy_sections", [])[:6],
        )
    if packing.get("writable_executable_sections"):
        add(
            "PE Packing",
            "Writable + executable sections",
            12,
            "MEDIUM",
            "W+X sections are common in unpacking stubs or self-modifying code.",
            evidence=packing.get("writable_executable_sections", [])[:6],
        )

    import_obf = techniques["import_obfuscation"]
    if import_obf.get("dynamic_resolution_apis"):
        add(
            "Import Obfuscation",
            "Dynamic API resolution imports",
            18 if import_obf.get("import_count", 0) <= 10 else 12,
            "HIGH" if import_obf.get("import_count", 0) <= 10 else "MEDIUM",
            "Import table contains LoadLibrary/GetProcAddress style resolvers.",
            evidence=import_obf.get("evidence", [])[:6],
        )

    xor = techniques["string_xor"]
    if xor.get("xor_keys") or xor.get("stack_string_xor_count"):
        add(
            "String Encryption (XOR)",
            "Printable strings after XOR decode",
            16,
            "MEDIUM",
            "Printable strings emerged after single-byte XOR or stack decoding.",
            evidence={
                "examples": xor.get("hits", [])[:4],
                "stack_samples": xor.get("evidence", {}).get("stack_string_xor_samples", [])[:4],
                "iocs": xor.get("iocs", [])[:8],
            },
        )

    dead = techniques["dead_code"]
    if dead.get("opaque_predicate_count"):
        add(
            "Dead Code Insertion",
            "Opaque predicate patterns",
            18,
            "MEDIUM",
            "Flag-setting idioms followed by conditional jumps.",
            evidence=dead.get("evidence", {}).get("opaque_predicates", [])[:4],
        )
    if dead.get("sink_vertex_count"):
        add(
            "Dead Code Insertion",
            "Sink / dead-end CFG blocks",
            12,
            "MEDIUM",
            "CFG contains blocks with no normal exits.",
            evidence=dead.get("evidence", {}).get("sink_vertices", [])[:4],
        )

    api_hash = techniques["api_hashing"]
    if api_hash.get("rotate_count", 0) >= 2:
        add(
            "API Hashing",
            "Rotate-heavy arithmetic",
            18,
            "MEDIUM",
            "Rotate operations with small import table suggest API hashing.",
            evidence=api_hash.get("evidence", {}).get("rotate_samples", [])[:4],
        )

    return indicators


def analyze_file(file_path: str) -> Dict[str, Any]:
    file_path_obj = Path(file_path)
    file_size = os.path.getsize(file_path)

    pe, pe_info = analyze_pe(file_path)
    if pe is None:
        return {
            "file": {
                "name": file_path_obj.name,
                "size": file_size,
                "sha256": sha256_file(file_path),
            },
            "pe": pe_info,
            "summary": {
                "score": 0,
                "status": "UNSUPPORTED / NOT PE",
                "techniques": [],
            },
            "indicators": [],
        }

    if not pe_info.get("supported", True):
        return {
            "file": {
                "name": file_path_obj.name,
                "size": file_size,
                "sha256": sha256_file(file_path),
            },
            "pe": pe_info,
            "sections": pe_info.get("sections", []),
            "imports": pe_info.get("imports", []),
            "import_obfuscation": pe_info.get("import_obfuscation", {}),
            "disassembly": {"supported": False, "reason": pe_info.get("error")},
            "techniques": {},
            "summary": {
                "score": 0,
                "status": "UNSUPPORTED / .NET MSIL",
                "techniques": [],
            },
            "indicators": [],
        }

    entry_point_va = None
    if pe_info.get("entry_point") and pe_info.get("image_base"):
        entry_point_va = int(pe_info["image_base"], 16) + int(pe_info["entry_point"], 16)

    disasm = summarize_disassembly(pe, entry_point_va=entry_point_va)

    packing = detect_packing(pe_info.get("sections", []), pe_info.get("total_entropy", 0.0))
    packing_summary = summarize_packing(packing)

    import_obf_summary = summarize_import_obfuscation(pe_info.get("import_obfuscation", {}))

    xor_result = detect_xor_strings(
        file_path,
        sections=pe_info.get("sections", []),
        memory_xor_samples=disasm.get("evidence", {}).get("memory_xor_immediate_samples", []),
    )
    xor_summary = summarize_xor(xor_result, disasm)

    dead_code = score_dead_code(disasm)
    api_hash = score_api_hashing(disasm, pe_info.get("import_obfuscation", {}))

    packing_strong = bool(packing_summary.get("packer_section_names")) or (
        packing_summary.get("high_entropy_sections")
        and packing_summary.get("total_entropy", 0.0) >= 7.2
    )
    if packing_strong:
        if xor_summary.get("iocs") or xor_summary.get("meaningful_example_count", 0) >= 2:
            xor_summary["score"] = min(xor_summary.get("score", 0), 8)
            xor_summary["gate_reason"] = "packed file: XOR signal reduced to avoid noise"
        else:
            xor_summary["score"] = 0
            xor_summary["gate_reason"] = "packed file: XOR signal too noisy"

        disasm_summary = disasm.get("summary", {})
        if disasm_summary.get("instruction_count", 0) < 200:
            dead_code["score"] = 0
            dead_code["gate_reason"] = "packed stub too small for dead-code heuristics"

    techniques = {
        "pe_packing": packing_summary,
        "import_obfuscation": import_obf_summary,
        "string_xor": xor_summary,
        "dead_code": dead_code,
        "api_hashing": api_hash,
    }

    total_score = sum(item.get("score", 0) for item in techniques.values())
    total_score = min(100, round(total_score * (100 / 150)))

    if not pe_info.get("supported", True):
        status = "UNSUPPORTED / .NET MSIL"
    elif total_score >= 70:
        status = "HIGHLY OBFUSCATED"
    elif total_score >= 45:
        status = "OBFUSCATED"
    elif total_score > 0:
        status = "POSSIBLY OBFUSCATED"
    else:
        status = "NO STRONG OBFUSCATION INDICATORS"

    indicators = build_indicators(techniques)

    return {
        "file": {
            "name": file_path_obj.name,
            "size": file_size,
            "sha256": sha256_file(file_path),
        },
        "pe": pe_info,
        "sections": pe_info.get("sections", []),
        "imports": pe_info.get("imports", []),
        "import_obfuscation": pe_info.get("import_obfuscation", {}),
        "disassembly": disasm,
        "techniques": techniques,
        "summary": {
            "score": total_score,
            "status": status,
            "techniques": [
                name.replace("_", " ").title()
                for name, info in techniques.items()
                if info.get("score", 0) > 0
            ],
        },
        "indicators": indicators,
    }
