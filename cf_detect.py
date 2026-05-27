#!/usr/bin/env python3
"""Legacy control-flow CLI backed by the unified analysis engine."""

from __future__ import annotations

import sys

from analysis_engine import analyze_binary


def analyze_control_flow(file_path: str) -> None:
    result = analyze_binary(file_path)
    pe = result["pe_analysis"]
    capstone = pe.get("capstone", {})
    summary = capstone.get("summary", {})

    print(f"--- Control Flow Obfuscation Analysis: {file_path} ---")

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
    print(f"  CFG Flattening Score: {summary.get('cfg_flattening_score', 0):.3f}")
    print(f"  Dispatcher Blocks: {summary.get('cfg_dispatcher_block_count', 0)}")
    print(f"  Unreachable Block Ratio: {summary.get('cfg_unreachable_block_ratio', 0):.2%}")
    print(f"  NOP-like Ratio: {summary.get('nop_like_ratio', 0):.2%}")
    print(f"  Indirect Branch/Call Ratio: {summary.get('indirect_branch_call_ratio', 0):.2%}")
    print(f"  Conditional Jump Ratio: {summary.get('conditional_jump_ratio', 0):.2%}")
    print(f"  Unconditional Jump Ratio: {summary.get('unconditional_jump_ratio', 0):.2%}")

    if summary.get("nop_like_ratio", 0) > 0.1:
        print("  [!] High NOP density - possible junk code insertion.")
    if summary.get("indirect_branch_call_ratio", 0) > 0.025:
        print("  [!] High ratio of indirect transfers - possible control-flow flattening.")
    if summary.get("cfg_flattening_score", 0) > 0.2:
        print("  [!] CFG hub-and-spoke structure detected - strong flattening candidate.")
    if summary.get("push_ret_dispatch_count", 0) > 0:
        print("  [!] Push-ret dispatch blocks detected - possible RET-based dispatch.")

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
