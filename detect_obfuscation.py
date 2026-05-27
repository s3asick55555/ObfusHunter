#!/usr/bin/env python3
"""Legacy CLI entry point backed by the unified analysis engine."""

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
        print(f"[!] ALERT: Possible XOR keys: {', '.join(result['xor_analysis']['xor_keys'][:5])}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detect_obfuscation.py <file_path>")
    else:
        analyze_file(sys.argv[1])
