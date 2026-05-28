#!/usr/bin/env python3
"""Quick Windows PE analysis CLI backed by the presentation-scope engine."""

from __future__ import annotations

import os
import sys

from analysis_engine import analyze_binary


def analyze_file(file_path: str) -> None:
    result = analyze_binary(file_path)
    pe = result["pe_analysis"]
    obf = result["obfuscation"]

    print(f"--- Analyzing: {os.path.basename(file_path)} ---")

    if not pe.get("valid_pe"):
        print(f"Format check: {pe.get('error', 'Not a valid PE file')}")
        return

    print(f"Format: Windows PE Executable ({pe['architecture']})")
    print(f"Total Entropy: {pe['total_entropy']:.4f}")
    print(f"Obfuscation Score: {obf['score']} ({obf['status']})")

    if pe["total_entropy"] > 7.0:
        print("[!] ALERT: Very high overall entropy. Likely packed or encrypted.")
    elif pe["total_entropy"] > 6.0:
        print("[?] WARNING: High entropy detected.")

    if pe.get("packer_section_names"):
        print(f"[!] ALERT: Found packer-like section names: {', '.join(pe['packer_section_names'])}")

    if pe.get("high_entropy_sections"):
        for section in pe["high_entropy_sections"]:
            print(f"[!] ALERT: High entropy section {section['section']} ({section['entropy']})")

    if result["xor_analysis"].get("xor_keys"):
        print(f"[!] ALERT: XOR keys that decode printable strings: {', '.join(result['xor_analysis']['xor_keys'][:5])}")
    if result["xor_analysis"].get("stack_string_xor_hits"):
        print(f"[!] ALERT: Stack-based XOR string patterns: {len(result['xor_analysis']['stack_string_xor_hits'])}")

    import_obf = pe.get("import_obfuscation", {})
    if import_obf.get("dynamic_resolution_apis"):
        print(f"[!] ALERT: Dynamic API resolution imports: {', '.join(import_obf['dynamic_resolution_apis'])}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detect_obfuscation.py <file_path>")
    else:
        analyze_file(sys.argv[1])
