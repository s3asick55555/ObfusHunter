#!/usr/bin/env python3
"""Advanced Windows PE analysis CLI backed by the presentation-scope engine."""

from __future__ import annotations

import os
import sys

from analysis_engine import analyze_binary


def analyze_pe(file_path: str) -> None:
    result = analyze_binary(file_path)
    pe = result["pe_analysis"]

    print(f"--- Advanced Obfuscation Analysis: {os.path.basename(file_path)} ---")

    if not pe.get("valid_pe"):
        print(pe.get("error", "Not a valid PE file."))
        return

    print("\n[Section Entropy]")
    for section in pe["sections"]:
        print(f"  {section['name']:8}: {section['entropy']:.4f}")
        if section["entropy"] > 7.2:
            print(f"    [!] High entropy in {section['name']} - likely encrypted/packed.")

    print("\n[Import Analysis]")
    import_count = len(pe["imports"])
    print(f"  Total Imports: {import_count}")
    if import_count == 0:
        print("    [!] No imports found - highly suspicious!")
    elif import_count < 10:
        print("    [!] Very few imports - typical for packed files.")

    if pe["suspicious_imports"]:
        print(f"  Suspicious APIs: {len(pe['suspicious_imports'])}")
        for row in pe["suspicious_imports"][:10]:
            print(f"    {row['dll']}!{row['api']}")

    import_obf = pe.get("import_obfuscation", {})
    if import_obf.get("dynamic_resolution_apis"):
        print("\n[Import Obfuscation]")
        print(f"  Dynamic resolver APIs: {', '.join(import_obf['dynamic_resolution_apis'])}")

    xor_analysis = result["xor_analysis"]
    if xor_analysis.get("xor_keys") or xor_analysis.get("stack_string_xor_hits"):
        print("\n[XOR Indicators]")
        if xor_analysis.get("xor_keys"):
            print(f"  Single-byte XOR keys with printable decoded strings: {', '.join(xor_analysis['xor_keys'][:5])}")
        if xor_analysis.get("stack_string_xor_hits"):
            print(f"  Stack-based XOR string patterns: {len(xor_analysis['stack_string_xor_hits'])}")

    techniques = result["obfuscation"]["possible_techniques"]
    if techniques:
        print("\n[Techniques]")
        for technique in techniques:
            print(f"  - {technique}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 advanced_detection.py <file_path>")
    else:
        analyze_pe(sys.argv[1])
