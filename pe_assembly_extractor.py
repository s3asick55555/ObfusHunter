#!/usr/bin/env python3
"""Legacy PE assembly extractor backed by the unified analysis engine."""

from __future__ import annotations

import sys

from analysis_engine import analyze_binary


def analyze_pe_file(file_path: str, max_instructions: int = 20) -> None:
    result = analyze_binary(file_path)
    pe = result["pe_analysis"]
    capstone = pe.get("capstone", {})

    print("=" * 80)
    print("PE Assembly Extractor & Section Analyzer")
    print("=" * 80)
    print(f"File: {file_path}")
    print("=" * 80)

    if not pe.get("valid_pe"):
        print(pe.get("error", "Not a valid PE file."))
        return

    print("\n[PE HEADER INFORMATION]")
    print(f"  Architecture:       {pe['architecture']}")
    print(f"  Entry Point:        {pe['entry_point']}")
    print(f"  Image Base:         {pe['image_base']}")
    print(f"  Number of Sections: {len(pe['sections'])}")

    print("\n" + "=" * 80)
    print("SECTION PROPERTIES")
    print("=" * 80)
    for section in pe["sections"]:
        print(f"\n[{section['name']}]")
        print(f"  Virtual Address:    {section['virtual_address']}")
        print(f"  Virtual Size:       {section['virtual_size']:,} bytes")
        print(f"  Raw Size:           {section['raw_size']:,} bytes")
        print(f"  Entropy:            {section['entropy']:.4f}")
        print(f"  ASCII Ratio:        {section['printable_ascii_ratio']:.4f}")
        if section["characteristics"]:
            print(f"  Characteristics:    {', '.join(section['characteristics'])}")

    print("\n" + "=" * 80)
    print("ASSEMBLY CODE EXTRACTION")
    print("=" * 80)
    if capstone.get("supported") is False:
        print(capstone.get("reason", "Unsupported architecture."))
        return

    for section in capstone.get("sections", []):
        print(f"\n[{section['name']}] Disassembly")
        print(f"  Base Address: {section['virtual_address']}")
        print(f"  Total instructions: {section['instruction_count']}")
        for instruction in section.get("sample_instructions", [])[:max_instructions]:
            print(
                f"  {instruction['address']:>12} "
                f"{instruction['mnemonic']:<8} {instruction['op_str']}"
            )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pe_assembly_extractor.py <file_path>")
    else:
        analyze_pe_file(sys.argv[1])
