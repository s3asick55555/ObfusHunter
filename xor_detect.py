#!/usr/bin/env python3
"""Standalone printable-string XOR scanner for Windows PE triage."""

from __future__ import annotations

import sys

from analysis_engine import detect_xor_strings


def detect_xor(file_path: str) -> None:
    result = detect_xor_strings(file_path)
    print(f"--- Printable XOR String Analysis: {file_path} ---")
    print(f"Tested bytes: {result.get('tested_bytes', 0)}")

    hits = result.get("hits", [])
    if not hits:
        print("No single-byte XOR keys produced new printable strings.")
        return

    for hit in hits:
        print(
            f"Key {hit['key']}: "
            f"{hit['printable_string_count']} printable strings, "
            f"{hit['printable_character_count']} printable characters"
            f"{' (seen in XOR instruction)' if hit.get('instruction_key_hint') else ''}"
        )
        for example in hit.get("examples", [])[:3]:
            region = f" [{example['region']}]" if example.get("region") else ""
            score = f" score={example['text_score']}" if example.get("text_score") is not None else ""
            print(f"  {example['offset']}{region}: {example['decoded']}{score}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python xor_detect.py <file_path>")
        sys.exit(1)
    detect_xor(sys.argv[1])
