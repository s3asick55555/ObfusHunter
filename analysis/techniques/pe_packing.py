from __future__ import annotations

from typing import Any, Dict, List

from ..pe import COMMON_PACKER_SECTION_NAMES


def detect_packing(sections: List[Dict[str, Any]], total_entropy: float) -> Dict[str, Any]:
    high_entropy_sections = [
        {
            "section": section["name"],
            "entropy": section["entropy"],
            "reason": "Very high entropy; possible packed or encrypted payload.",
        }
        for section in sections
        if section.get("entropy", 0.0) > 7.2 and section.get("raw_size", 0) > 512
    ]

    packer_section_names = [
        section["name"]
        for section in sections
        if (section.get("name") or "").lower() in COMMON_PACKER_SECTION_NAMES
    ]

    wx_sections = [
        section
        for section in sections
        if "EXECUTE" in section.get("flags", []) and "WRITE" in section.get("flags", [])
    ]

    return {
        "total_entropy": total_entropy,
        "high_entropy_sections": high_entropy_sections,
        "packer_section_names": packer_section_names,
        "writable_executable_sections": wx_sections,
    }
