#!/usr/bin/env python3
"""Baseline control-flow CLI backed by the unified analysis engine."""

from __future__ import annotations

import sys

from analysis_engine import analyze_binary


def analyze_control_flow(file_path: str) -> None:
    result = analyze_binary(file_path)
    pe = result["pe_analysis"]
    capstone = pe.get("capstone", {})
    summary = capstone.get("summary", {})
    print(f"--- Baseline Control-Flow Analysis: {file_path} ---")

    if not pe.get("valid_pe"):
        print(pe.get("error", "Not a valid PE file."))
        return

    if capstone.get("supported") is False:
        print(capstone.get("reason", "Unsupported architecture."))
        return

    print("\n[Statistics]")
    print(f"  Total Instructions: {summary.get('instruction_count', 0)}")
    print(f"  CFG Blocks: {summary.get('cfg_block_count', 0)}")
    print(f"  CFG Edges: {summary.get('cfg_edge_count', 0)}")
    print(f"  Basic opaque predicates: {summary.get('basic_opaque_predicate_count', 0)}")
    print(f"  Sink vertices: {summary.get('cfg_sink_vertex_count', 0)}")
    print(f"  Sink vertex ratio: {summary.get('cfg_sink_vertex_ratio', 0):.2%}")
    print(f"  Conditional Jump Ratio: {summary.get('conditional_jump_ratio', 0):.2%}")
    print(f"  Unconditional Jump Ratio: {summary.get('unconditional_jump_ratio', 0):.2%}")

    print("\n[Baseline Scope]")
    print("  Active techniques: basic opaque predicates and sink/dead-end CFG blocks.")
    print("  This output supports the Dead Code Insertion section of ideas3.md.")

    suspicious = summary.get("suspicious_windows", [])
    if suspicious:
        print("\n[Suspicious Windows]")
        for window in suspicious[:10]:
            print(f"  {window['address']} {window['section']}: {window['pattern']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cf_detect.py <file_path>")
    else:
        analyze_control_flow(sys.argv[1])
