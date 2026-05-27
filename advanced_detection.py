#!/usr/bin/env python3
"""Legacy advanced analysis CLI backed by the unified analysis engine."""

from __future__ import annotations

import os
import sys

from analysis_engine import analyze_binary


def analyze_pe(file_path: str) -> None:
    result = analyze_binary(file_path)
    pe = result["pe_analysis"]
    content = result["content_indicators"]

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

    base64_strings = content["base64_sequences"]
    if base64_strings["count"]:
        print(f"\n[Base64 Strings] Found {base64_strings['count']} potential Base64 strings.")
        for value in base64_strings["examples"][:5]:
            print(f"  {value[:50]}...")

    padding = content["padding"]
    if padding["has_large_null_padding"] or padding["has_large_repeated_byte_run"]:
        print("\n[Binary Padding]")
        print(
            "  [!] Significant repeated-byte padding detected "
            f"({padding['largest_repeated_byte']} x {padding['largest_repeated_run']})."
        )

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
