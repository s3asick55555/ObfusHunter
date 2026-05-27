#!/usr/bin/env python3
"""
Unified static analysis engine for obfuscation detection.

This module merges the original repository heuristics with the more complete
web-oriented implementation from `obfuscation_detector_web/`.
"""

from __future__ import annotations

import math
import os
import re
import statistics
import base64
import binascii
from collections import Counter, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_EIP, X86_REG_INVALID, X86_REG_RIP


SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "OpenProcess",
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
}

COMMON_PACKER_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".adata",
    ".petite",
    ".mpress",
    ".themida",
    ".vmp0",
    ".vmp1",
    ".enigma",
    ".packed",
    ".rsrc1",
}

XOR_TARGETS = [
    b"http://",
    b"https://",
    b"cmd.exe",
    b"powershell.exe",
    b"VirtualAlloc",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"GetProcAddress",
    b"LoadLibrary",
    b"kernel32",
    b"user32",
    b"advapi32",
]

BASE64_PATTERN = re.compile(rb"[A-Za-z0-9+/]{12,}={0,2}")


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for bytes."""
    if not data:
        return 0.0

    counts = Counter(data)
    entropy = 0.0
    length = len(data)

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def printable_ascii_ratio(data: bytes) -> float:
    """Ratio of printable ASCII bytes."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(data)


def zero_ratio(data: bytes) -> float:
    """Ratio of null bytes."""
    if not data:
        return 0.0
    return data.count(0) / len(data)


def safe_decode(value: bytes) -> str:
    return value.decode(errors="ignore").strip("\x00").strip()


def format_instruction_bytes(raw_bytes: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in raw_bytes)


def build_instruction_evidence(insn: Any, section: str, note: Optional[str] = None) -> Dict[str, Any]:
    evidence = {
        "section": section,
        "address": hex(insn.address),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "bytes": format_instruction_bytes(bytes(insn.bytes)),
    }
    if note:
        evidence["note"] = note
    return evidence


def section_is_executable(section: pefile.SectionStructure) -> bool:
    return bool(section.Characteristics & 0x20000000)


def section_is_writable(section: pefile.SectionStructure) -> bool:
    return bool(section.Characteristics & 0x80000000)


def section_is_readable(section: pefile.SectionStructure) -> bool:
    return bool(section.Characteristics & 0x40000000)


def get_capstone_engine(machine: int) -> Optional[Cs]:
    """Return a Capstone engine for x86/x64 PE files."""
    if machine == 0x14C:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif machine == 0x8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        return None

    md.detail = True
    return md


def is_dotnet_pe(pe: pefile.PE) -> bool:
    """Return True for managed PE files that contain a CLR/.NET header."""
    try:
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return bool(clr_dir.VirtualAddress and clr_dir.Size)
    except Exception:
        return False


def collect_iat_addresses(pe: pefile.PE) -> set[int]:
    """Collect import address table entries used by common thunk stubs."""
    addresses: set[int] = set()
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return addresses

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.address:
                addresses.add(int(imp.address))

    return addresses


def get_memory_operand_target(insn: Any) -> Optional[int]:
    """Resolve the effective address of a simple x86/x64 memory operand."""
    if not getattr(insn, "operands", None) or len(insn.operands) != 1:
        return None

    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None

    mem = operand.mem
    base = mem.base
    index = mem.index
    disp = int(mem.disp)

    if base in {X86_REG_INVALID, 0} and index in {X86_REG_INVALID, 0}:
        return disp

    if index in {X86_REG_INVALID, 0} and base in {X86_REG_RIP, X86_REG_EIP}:
        return int(insn.address + insn.size + disp)

    return None


def classify_architecture(machine: int) -> str:
    if machine == 0x14C:
        return "x86 (32-bit)"
    if machine == 0x8664:
        return "x86-64 (64-bit)"
    if machine == 0x1C0:
        return "ARM"
    if machine == 0xAA64:
        return "ARM64"
    return f"Unknown (0x{machine:04x})"


def extract_imports(pe: pefile.PE) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    imports: List[Dict[str, str]] = []
    suspicious: List[Dict[str, str]] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports, suspicious

    suspicious_api_names = {name.lower() for name in SUSPICIOUS_APIS}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="ignore") if entry.dll else "[unknown]"
        for imp in entry.imports:
            api_name = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
            row = {"dll": dll_name, "api": api_name}
            imports.append(row)
            if api_name.lower() in suspicious_api_names:
                suspicious.append(row)

    return imports, suspicious


def detect_xor_strings(file_path: str, sample_size: int = 2 * 1024 * 1024) -> Dict[str, Any]:
    """
    Quick XOR-key scan.

    This intentionally checks only single-byte XOR and is kept separate from
    the more exhaustive standalone XOR utilities in the repository.
    """
    result: Dict[str, Any] = {
        "xor_keys": [],
        "hits": [],
        "tested_bytes": 0,
    }

    try:
        data = Path(file_path).read_bytes()[:sample_size]
        result["tested_bytes"] = len(data)

        for key in range(1, 256):
            decoded = bytes(b ^ key for b in data)
            hit_targets = [t.decode(errors="ignore") for t in XOR_TARGETS if t in decoded]
            if hit_targets:
                result["xor_keys"].append(f"0x{key:02x}")
                result["hits"].append({"key": f"0x{key:02x}", "targets": hit_targets[:5]})

        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def detect_base64_sequences(data: bytes, limit: int = 20) -> Dict[str, Any]:
    """
    Find likely Base64-encoded strings.

    The old detector treated any long alphanumeric token as Base64. This
    version decodes candidates and keeps only those that successfully decode
    into mostly printable text, which filters out plain identifiers such as
    `EnterCriticalSection`.
    """
    matches = []
    decoded_examples = []
    seen = set()

    for match in BASE64_PATTERN.findall(data):
        if match in seen:
            continue
        seen.add(match)

        padded = match + (b"=" * ((4 - len(match) % 4) % 4))
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue

        if len(decoded) < 8:
            continue

        if printable_ascii_ratio(decoded) < 0.85:
            continue

        original = match.decode(errors="ignore")
        decoded_text = decoded.decode(errors="ignore")
        matches.append(original)
        decoded_examples.append({
            "encoded": original,
            "decoded": decoded_text,
        })

    return {
        "count": len(matches),
        "examples": matches[:limit],
        "decoded_examples": decoded_examples[:limit],
    }


def detect_padding_sequences(data: bytes, threshold: int = 10 * 1024) -> Dict[str, Any]:
    """Detect unusually large repeated-byte runs such as large null padding."""
    if not data:
        return {
            "has_large_null_padding": False,
            "has_large_repeated_byte_run": False,
            "largest_repeated_run": 0,
            "largest_repeated_byte": None,
        }

    longest_run = 1
    longest_byte = data[0]
    current_run = 1
    current_byte = data[0]

    for byte in data[1:]:
        if byte == current_byte:
            current_run += 1
        else:
            if current_run > longest_run:
                longest_run = current_run
                longest_byte = current_byte
            current_byte = byte
            current_run = 1

    if current_run > longest_run:
        longest_run = current_run
        longest_byte = current_byte

    return {
        "has_large_null_padding": b"\x00" * threshold in data,
        "has_large_repeated_byte_run": longest_run >= threshold,
        "largest_repeated_run": longest_run,
        "largest_repeated_byte": f"0x{longest_byte:02x}",
    }


def is_conditional_jump(mnemonic: str) -> bool:
    return mnemonic.startswith("j") and mnemonic not in {"jmp"}


def is_unconditional_jump(mnemonic: str) -> bool:
    return mnemonic == "jmp"


def is_return(mnemonic: str) -> bool:
    return mnemonic.startswith("ret")


def get_direct_branch_target(insn) -> Optional[int]:
    if not getattr(insn, "operands", None):
        return None
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type == X86_OP_IMM:
        return int(operand.imm)
    return None


def build_cfg_for_section(
    instructions: List[Any],
    section_name: str,
    section_start: int,
    section_end: int,
    entry_point_va: Optional[int],
) -> Dict[str, Any]:
    """Recover basic blocks and a simple CFG from linear disassembly."""
    if not instructions:
        return {
            "entry_block": None,
            "block_count": 0,
            "edge_count": 0,
            "reachable_block_count": 0,
            "unreachable_block_count": 0,
            "unreachable_block_ratio": 0.0,
            "avg_block_size": 0.0,
            "small_block_ratio": 0.0,
            "jmp_only_block_ratio": 0.0,
            "back_edge_ratio": 0.0,
            "dispatcher_block_count": 0,
            "dispatcher_hub_ratio": 0.0,
            "flattening_score": 0.0,
            "push_ret_dispatch_count": 0,
            "ret_thunk_count": 0,
            "suspicious_blocks": [],
            "unreachable_blocks": [],
            "ret_thunk_blocks": [],
            "blocks": [],
        }

    leaders = {instructions[0].address}
    address_to_index = {insn.address: index for index, insn in enumerate(instructions)}

    for index, insn in enumerate(instructions):
        mnemonic = insn.mnemonic.lower()
        next_insn = instructions[index + 1] if index + 1 < len(instructions) else None

        if is_conditional_jump(mnemonic) or is_unconditional_jump(mnemonic):
            target = get_direct_branch_target(insn)
            if target is not None and section_start <= target < section_end:
                leaders.add(target)
            if next_insn is not None:
                leaders.add(next_insn.address)
        elif is_return(mnemonic) and next_insn is not None:
            leaders.add(next_insn.address)

    blocks = []
    current_block: List[Any] = []
    leader_list = sorted(leaders)

    for insn in instructions:
        if current_block and insn.address in leaders:
            blocks.append(current_block)
            current_block = []
        current_block.append(insn)

    if current_block:
        blocks.append(current_block)

    block_entries = []
    block_lookup = {}
    for block in blocks:
        start = block[0].address
        end = block[-1].address
        entry = {
            "start": start,
            "end": end,
            "instruction_count": len(block),
            "terminator": block[-1].mnemonic.lower(),
            "instructions": block,
            "successors": [],
            "predecessors": [],
        }
        block_entries.append(entry)
        block_lookup[start] = entry

    for index, entry in enumerate(block_entries):
        last = entry["instructions"][-1]
        mnemonic = last.mnemonic.lower()
        next_block = block_entries[index + 1] if index + 1 < len(block_entries) else None

        def add_successor(target_block: Optional[Dict[str, Any]], edge_type: str) -> None:
            if target_block is None:
                return
            edge = {"target": target_block["start"], "type": edge_type}
            if edge not in entry["successors"]:
                entry["successors"].append(edge)
                target_block["predecessors"].append(entry["start"])

        if is_conditional_jump(mnemonic):
            target = get_direct_branch_target(last)
            add_successor(block_lookup.get(target), "branch")
            add_successor(next_block, "fallthrough")
        elif is_unconditional_jump(mnemonic):
            target = get_direct_branch_target(last)
            if target is not None:
                add_successor(block_lookup.get(target), "jump")
            else:
                entry["successors"].append({"target": None, "type": "indirect_jump"})
        elif is_return(mnemonic):
            pass
        else:
            add_successor(next_block, "fallthrough")

    if entry_point_va is not None and block_entries:
        entry_block = None
        for block in block_entries:
            if block["start"] <= entry_point_va <= block["end"]:
                entry_block = block["start"]
                break
        if entry_block is None:
            entry_block = block_entries[0]["start"]
    else:
        entry_block = block_entries[0]["start"] if block_entries else None

    roots = set()
    if entry_block is not None:
        roots.add(entry_block)
    for block in block_entries:
        if not block["predecessors"]:
            roots.add(block["start"])
        for insn in block["instructions"]:
            if insn.mnemonic.lower() == "call":
                target = get_direct_branch_target(insn)
                if target is not None and target in block_lookup:
                    roots.add(target)

    reachable = set()
    if roots:
        queue = deque(sorted(roots))
        while queue:
            node = queue.popleft()
            if node in reachable:
                continue
            reachable.add(node)
            for edge in block_lookup[node]["successors"]:
                target = edge["target"]
                if target is not None and target not in reachable:
                    queue.append(target)

    edge_count = sum(1 for block in block_entries for edge in block["successors"] if edge["target"] is not None)
    back_edge_count = sum(
        1
        for block in block_entries
        for edge in block["successors"]
        if edge["target"] is not None and edge["target"] <= block["start"]
    )

    small_blocks = [block for block in block_entries if block["instruction_count"] <= 2]
    jmp_only_blocks = [
        block
        for block in block_entries
        if block["instruction_count"] <= 2
        and is_unconditional_jump(block["terminator"])
        and any(edge["target"] is not None for edge in block["successors"])
    ]

    push_ret_dispatch_blocks = 0
    ret_thunk_count = 0
    suspicious_blocks = []
    ret_thunk_evidence = []

    for block in block_entries:
        instructions_in_block = block["instructions"]
        if len(instructions_in_block) == 2:
            first = instructions_in_block[0]
            second = instructions_in_block[1]
            if first.mnemonic.lower() == "push" and get_direct_branch_target(first) is not None and is_return(second.mnemonic.lower()):
                push_ret_dispatch_blocks += 1
                suspicious_blocks.append({
                    "block": hex(block["start"]),
                    "pattern": "push immediate; ret dispatch stub",
                    "instructions": [
                        build_instruction_evidence(first, section=section_name, note="push target"),
                        build_instruction_evidence(second, section=section_name, note="ret dispatch"),
                    ],
                })

        if len(instructions_in_block) == 1 and is_return(instructions_in_block[0].mnemonic.lower()):
            ret_thunk_count += 1
            ret_thunk_evidence.append({
                "block": hex(block["start"]),
                "instruction": build_instruction_evidence(instructions_in_block[0], section=section_name, note="ret-only thunk block"),
            })

    dispatcher_blocks = []
    for block in block_entries:
        indegree = len(set(block["predecessors"]))
        direct_successors = [edge for edge in block["successors"] if edge["target"] is not None]
        outdegree = len({edge["target"] for edge in direct_successors})
        if (indegree >= 4 and outdegree >= 2) or (indegree >= 3 and outdegree >= 3):
            dispatcher_blocks.append(block)
            suspicious_blocks.append({
                "block": hex(block["start"]),
                "pattern": f"dispatcher-like hub (in={indegree}, out={outdegree})",
                "instructions": [
                    build_instruction_evidence(insn, section=section_name)
                    for insn in block["instructions"][:3]
                ],
            })

    block_count = len(block_entries)
    reachable_count = len(reachable)
    unreachable_count = block_count - reachable_count
    avg_block_size = statistics.mean(block["instruction_count"] for block in block_entries) if block_entries else 0.0
    small_block_ratio = len(small_blocks) / block_count if block_count else 0.0
    jmp_only_block_ratio = len(jmp_only_blocks) / block_count if block_count else 0.0
    back_edge_ratio = back_edge_count / edge_count if edge_count else 0.0
    dispatcher_hub_ratio = len(dispatcher_blocks) / block_count if block_count else 0.0
    unreachable_block_ratio = unreachable_count / block_count if block_count else 0.0
    flattening_score = min(
        1.0,
        dispatcher_hub_ratio * 2.0
        + jmp_only_block_ratio
        + min(back_edge_ratio, 0.5)
        + min(unreachable_block_ratio, 0.5) / 2.0,
    )

    return {
        "entry_block": hex(entry_block) if entry_block is not None else None,
        "root_block_count": len(roots),
        "block_count": block_count,
        "edge_count": edge_count,
        "reachable_block_count": reachable_count,
        "unreachable_block_count": unreachable_count,
        "unreachable_block_ratio": round(unreachable_block_ratio, 6),
        "avg_block_size": round(avg_block_size, 6),
        "small_block_ratio": round(small_block_ratio, 6),
        "jmp_only_block_ratio": round(jmp_only_block_ratio, 6),
        "back_edge_ratio": round(back_edge_ratio, 6),
        "dispatcher_block_count": len(dispatcher_blocks),
        "dispatcher_hub_ratio": round(dispatcher_hub_ratio, 6),
        "flattening_score": round(flattening_score, 6),
        "push_ret_dispatch_count": push_ret_dispatch_blocks,
        "ret_thunk_count": ret_thunk_count,
        "suspicious_blocks": suspicious_blocks[:25],
        "unreachable_blocks": [
            {
                "block": hex(block["start"]),
                "terminator": block["terminator"],
                "instructions": [
                    build_instruction_evidence(insn, section=section_name)
                    for insn in block["instructions"][:3]
                ],
            }
            for block in block_entries
            if block["start"] not in reachable
        ][:25],
        "ret_thunk_blocks": ret_thunk_evidence[:25],
        "blocks": [
            {
                "start": hex(block["start"]),
                "end": hex(block["end"]),
                "instruction_count": block["instruction_count"],
                "terminator": block["terminator"],
                "successors": [
                    {
                        "target": hex(edge["target"]) if edge["target"] is not None else None,
                        "type": edge["type"],
                    }
                    for edge in block["successors"]
                ],
            }
            for block in block_entries[:120]
        ],
    }


def disassemble_executable_sections(
    pe: pefile.PE,
    entry_point_va: Optional[int] = None,
    max_bytes_per_section: int = 512 * 1024,
) -> Dict[str, Any]:
    """
    Disassemble executable sections and derive obfuscation-oriented features.

    Only x86/x64 is supported by this implementation. Unsupported architectures
    return a graceful "unsupported" result.
    """
    md = get_capstone_engine(pe.FILE_HEADER.Machine)
    if md is None:
        return {
            "supported": False,
            "reason": "Capstone disassembly is implemented for x86/x64 PE files only.",
            "sections": [],
            "summary": {},
        }

    section_results = []
    global_counts = Counter()
    suspicious_windows = []
    cfg_totals = Counter()
    iat_addresses = collect_iat_addresses(pe)
    global_evidence = {
        "nop_like_samples": [],
        "indirect_branch_call_samples": [],
        "conditional_jump_samples": [],
        "compare_test_samples": [],
        "segment_peb_access_samples": [],
        "anti_disassembly_trap_samples": [],
        "rotate_samples": [],
        "call_pop_getpc_samples": [],
    }

    for section in pe.sections:
        if not section_is_executable(section):
            continue

        name = safe_decode(section.Name)
        data = section.get_data()[:max_bytes_per_section]
        va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

        counts = Counter()
        instructions = []
        last_instructions: List[Any] = []
        section_evidence = {
            "nop_like_samples": [],
            "indirect_branch_call_samples": [],
            "conditional_jump_samples": [],
            "compare_test_samples": [],
            "segment_peb_access_samples": [],
            "anti_disassembly_trap_samples": [],
            "rotate_samples": [],
            "call_pop_getpc_samples": [],
        }

        try:
            disassembled = list(md.disasm(data, va))
            for insn in disassembled:
                counts["total"] += 1
                global_counts["total"] += 1

                mnemonic = insn.mnemonic.lower()
                op_str = insn.op_str.lower()

                counts[f"mnemonic_{mnemonic}"] += 1
                global_counts[f"mnemonic_{mnemonic}"] += 1

                if mnemonic in {"nop", "xchg"} and op_str in {"", "eax, eax", "rax, rax"}:
                    counts["junk_nop_like"] += 1
                    global_counts["junk_nop_like"] += 1
                    if len(section_evidence["nop_like_samples"]) < 10:
                        evidence = build_instruction_evidence(insn, name, note="NOP-like / junk-style instruction")
                        section_evidence["nop_like_samples"].append(evidence)
                        global_evidence["nop_like_samples"].append(evidence)

                memory_target = get_memory_operand_target(insn) if mnemonic in {"jmp", "call"} else None
                is_iat_thunk = memory_target in iat_addresses if memory_target is not None else False

                if mnemonic in {"jmp", "call"} and ("[" in op_str and "]" in op_str) and not is_iat_thunk:
                    counts["indirect_branch_call"] += 1
                    global_counts["indirect_branch_call"] += 1
                    if len(section_evidence["indirect_branch_call_samples"]) < 12:
                        evidence = build_instruction_evidence(insn, name, note="memory-indirect branch/call")
                        section_evidence["indirect_branch_call_samples"].append(evidence)
                        global_evidence["indirect_branch_call_samples"].append(evidence)

                if mnemonic.startswith("j") and mnemonic != "jmp":
                    counts["conditional_jump"] += 1
                    global_counts["conditional_jump"] += 1
                    if len(section_evidence["conditional_jump_samples"]) < 12:
                        evidence = build_instruction_evidence(insn, name, note="conditional branch")
                        section_evidence["conditional_jump_samples"].append(evidence)
                        global_evidence["conditional_jump_samples"].append(evidence)

                if mnemonic == "jmp":
                    counts["unconditional_jump"] += 1
                    global_counts["unconditional_jump"] += 1

                if mnemonic == "call":
                    counts["call"] += 1
                    global_counts["call"] += 1

                if mnemonic == "ret":
                    counts["ret"] += 1
                    global_counts["ret"] += 1

                if mnemonic in {"rol", "ror"}:
                    counts["rotate"] += 1
                    global_counts["rotate"] += 1
                    if len(section_evidence["rotate_samples"]) < 10:
                        evidence = build_instruction_evidence(insn, name, note="rotate instruction")
                        section_evidence["rotate_samples"].append(evidence)
                        global_evidence["rotate_samples"].append(evidence)

                if mnemonic in {"ud2", "icebp", "hlt"}:
                    counts["anti_disassembly_trap"] += 1
                    global_counts["anti_disassembly_trap"] += 1
                    if len(section_evidence["anti_disassembly_trap_samples"]) < 10:
                        evidence = build_instruction_evidence(insn, name, note="trap / anti-disassembly instruction")
                        section_evidence["anti_disassembly_trap_samples"].append(evidence)
                        global_evidence["anti_disassembly_trap_samples"].append(evidence)

                if mnemonic in {"jmp", "call"} and op_str and "[" not in op_str and any(
                    op_str == reg for reg in {
                        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                    }
                ):
                    counts["register_indirect_transfer"] += 1
                    global_counts["register_indirect_transfer"] += 1
                    if len(section_evidence["indirect_branch_call_samples"]) < 12:
                        evidence = build_instruction_evidence(insn, name, note="register-indirect branch/call")
                        section_evidence["indirect_branch_call_samples"].append(evidence)
                        global_evidence["indirect_branch_call_samples"].append(evidence)

                if mnemonic in {"xor", "sub"}:
                    ops = [op.strip() for op in op_str.split(",")]
                    if len(ops) == 2 and ops[0] == ops[1]:
                        counts["zeroing_idiom"] += 1
                        global_counts["zeroing_idiom"] += 1

                if mnemonic in {"cmp", "test"}:
                    counts["compare_test"] += 1
                    global_counts["compare_test"] += 1
                    if len(section_evidence["compare_test_samples"]) < 12:
                        evidence = build_instruction_evidence(insn, name, note="compare/test instruction")
                        section_evidence["compare_test_samples"].append(evidence)
                        global_evidence["compare_test_samples"].append(evidence)

                if mnemonic in {"push", "pop"}:
                    counts["stack_op"] += 1
                    global_counts["stack_op"] += 1

                if "fs:" in op_str or "gs:" in op_str:
                    counts["segment_peb_access"] += 1
                    global_counts["segment_peb_access"] += 1
                    if len(section_evidence["segment_peb_access_samples"]) < 10:
                        evidence = build_instruction_evidence(insn, name, note="segment-based PEB/TEB access")
                        section_evidence["segment_peb_access_samples"].append(evidence)
                        global_evidence["segment_peb_access_samples"].append(evidence)

                last_instructions.append(insn)
                if len(last_instructions) > 5:
                    last_instructions.pop(0)

                if len(last_instructions) >= 2:
                    prev = last_instructions[-2]
                    cur = last_instructions[-1]
                    prev_target = get_direct_branch_target(prev)
                    call_span = (prev_target - (prev.address + prev.size)) if prev_target is not None else None
                    if prev.mnemonic.lower() == "call" and cur.mnemonic.lower() == "pop" and call_span is not None and abs(call_span) <= 64:
                        counts["call_pop_getpc"] += 1
                        global_counts["call_pop_getpc"] += 1
                        evidence = {
                            "section": name,
                            "address": hex(prev.address),
                            "pattern": "call followed by pop; possible GetPC / shellcode-style position discovery",
                            "instructions": [
                                build_instruction_evidence(prev, name, note="call"),
                                build_instruction_evidence(cur, name, note="pop"),
                            ],
                        }
                        suspicious_windows.append(evidence)
                        section_evidence["call_pop_getpc_samples"].append(evidence)
                        global_evidence["call_pop_getpc_samples"].append(evidence)

                if len(instructions) < 200:
                    instructions.append({
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "bytes": format_instruction_bytes(bytes(insn.bytes)),
                    })

        except Exception as exc:
            section_results.append({
                "name": name,
                "error": f"Disassembly error: {exc}",
                "instruction_count": counts["total"],
            })
            continue

        cfg = build_cfg_for_section(
            disassembled,
            section_name=name,
            section_start=va,
            section_end=va + len(data),
            entry_point_va=entry_point_va if entry_point_va is not None and va <= entry_point_va < va + len(data) else None,
        )

        cfg_totals["block_count"] += cfg["block_count"]
        cfg_totals["edge_count"] += cfg["edge_count"]
        cfg_totals["reachable_block_count"] += cfg["reachable_block_count"]
        cfg_totals["unreachable_block_count"] += cfg["unreachable_block_count"]
        cfg_totals["dispatcher_block_count"] += cfg["dispatcher_block_count"]
        cfg_totals["push_ret_dispatch_count"] += cfg["push_ret_dispatch_count"]
        cfg_totals["ret_thunk_count"] += cfg["ret_thunk_count"]
        cfg_totals["avg_block_size_sum"] += cfg["avg_block_size"] * max(cfg["block_count"], 1)
        cfg_totals["small_block_weight"] += cfg["small_block_ratio"] * cfg["block_count"]
        cfg_totals["jmp_only_block_weight"] += cfg["jmp_only_block_ratio"] * cfg["block_count"]
        cfg_totals["back_edge_weight"] += cfg["back_edge_ratio"] * max(cfg["edge_count"], 1)
        cfg_totals["flattening_weight"] += cfg["flattening_score"] * max(cfg["block_count"], 1)
        cfg_totals["unreachable_weight"] += cfg["unreachable_block_ratio"] * cfg["block_count"]

        total = max(counts["total"], 1)
        derived = {
            "nop_like_ratio": counts["junk_nop_like"] / total,
            "indirect_branch_call_ratio": counts["indirect_branch_call"] / total,
            "conditional_jump_ratio": counts["conditional_jump"] / total,
            "unconditional_jump_ratio": counts["unconditional_jump"] / total,
            "compare_test_ratio": counts["compare_test"] / total,
            "stack_op_ratio": counts["stack_op"] / total,
            "zeroing_idiom_ratio": counts["zeroing_idiom"] / total,
            "ret_ratio": counts["ret"] / total,
            "rotate_ratio": counts["rotate"] / total,
            "register_indirect_transfer_ratio": counts["register_indirect_transfer"] / total,
            "segment_peb_access_ratio": counts["segment_peb_access"] / total,
            "anti_disassembly_trap_ratio": counts["anti_disassembly_trap"] / total,
            "call_pop_getpc_count": counts["call_pop_getpc"],
        }

        section_results.append({
            "name": name,
            "virtual_address": hex(section.VirtualAddress),
            "instruction_count": counts["total"],
            "counts": dict(counts),
            "derived": {k: round(v, 6) if isinstance(v, float) else v for k, v in derived.items()},
            "cfg": cfg,
            "evidence": {
                key: values[:10]
                for key, values in section_evidence.items()
                if values
            },
            "sample_instructions": instructions,
        })

    total = max(global_counts["total"], 1)
    total_blocks = max(cfg_totals["block_count"], 1)
    total_edges = max(cfg_totals["edge_count"], 1)
    summary = {
        "instruction_count": global_counts["total"],
        "nop_like_ratio": global_counts["junk_nop_like"] / total,
        "indirect_branch_call_ratio": global_counts["indirect_branch_call"] / total,
        "conditional_jump_ratio": global_counts["conditional_jump"] / total,
        "unconditional_jump_ratio": global_counts["unconditional_jump"] / total,
        "compare_test_ratio": global_counts["compare_test"] / total,
        "stack_op_ratio": global_counts["stack_op"] / total,
        "zeroing_idiom_ratio": global_counts["zeroing_idiom"] / total,
        "ret_ratio": global_counts["ret"] / total,
        "rotate_ratio": global_counts["rotate"] / total,
        "register_indirect_transfer_ratio": global_counts["register_indirect_transfer"] / total,
        "segment_peb_access_ratio": global_counts["segment_peb_access"] / total,
        "anti_disassembly_trap_ratio": global_counts["anti_disassembly_trap"] / total,
        "call_pop_getpc_count": global_counts["call_pop_getpc"],
        "cfg_block_count": cfg_totals["block_count"],
        "cfg_edge_count": cfg_totals["edge_count"],
        "cfg_unreachable_block_count": cfg_totals["unreachable_block_count"],
        "cfg_unreachable_block_ratio": cfg_totals["unreachable_weight"] / total_blocks,
        "cfg_avg_block_size": cfg_totals["avg_block_size_sum"] / total_blocks,
        "cfg_small_block_ratio": cfg_totals["small_block_weight"] / total_blocks,
        "cfg_jmp_only_block_ratio": cfg_totals["jmp_only_block_weight"] / total_blocks,
        "cfg_back_edge_ratio": cfg_totals["back_edge_weight"] / total_edges,
        "cfg_dispatcher_block_count": cfg_totals["dispatcher_block_count"],
        "cfg_dispatcher_hub_ratio": cfg_totals["dispatcher_block_count"] / total_blocks,
        "cfg_flattening_score": cfg_totals["flattening_weight"] / total_blocks,
        "push_ret_dispatch_count": cfg_totals["push_ret_dispatch_count"],
        "ret_thunk_count": cfg_totals["ret_thunk_count"],
        "evidence": {
            "nop_like_samples": global_evidence["nop_like_samples"][:10],
            "indirect_branch_call_samples": global_evidence["indirect_branch_call_samples"][:12],
            "conditional_jump_samples": global_evidence["conditional_jump_samples"][:12],
            "compare_test_samples": global_evidence["compare_test_samples"][:12],
            "segment_peb_access_samples": global_evidence["segment_peb_access_samples"][:10],
            "anti_disassembly_trap_samples": global_evidence["anti_disassembly_trap_samples"][:10],
            "rotate_samples": global_evidence["rotate_samples"][:10],
            "call_pop_getpc_samples": global_evidence["call_pop_getpc_samples"][:10],
        },
        "suspicious_windows": suspicious_windows[:50],
    }

    return {
        "supported": True,
        "sections": section_results,
        "summary": {k: round(v, 6) if isinstance(v, float) else v for k, v in summary.items()},
    }


def analyze_pe_file(file_path: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "valid_pe": False,
        "analysis_target": "native_pe",
        "supported_for_analysis": True,
        "architecture": None,
        "entry_point": None,
        "image_base": None,
        "sections": [],
        "total_entropy": 0.0,
        "high_entropy_sections": [],
        "imports": [],
        "suspicious_imports": [],
        "packer_section_names": [],
        "error": None,
    }

    try:
        pe = pefile.PE(file_path, fast_load=False)
        results["valid_pe"] = True
        results["architecture"] = classify_architecture(pe.FILE_HEADER.Machine)
        results["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        results["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
        if is_dotnet_pe(pe):
            results["analysis_target"] = "dotnet_msil"
            results["supported_for_analysis"] = False
            results["error"] = ".NET / MSIL PE detected. This analyzer only supports native PE binaries and should not score managed assemblies."
            return results

        file_data = Path(file_path).read_bytes()
        results["total_entropy"] = round(calculate_entropy(file_data), 4)

        for section in pe.sections:
            name = safe_decode(section.Name)
            data = section.get_data()
            entropy = calculate_entropy(data)
            flags = []

            if section_is_executable(section):
                flags.append("EXECUTE")
            if section_is_readable(section):
                flags.append("READ")
            if section_is_writable(section):
                flags.append("WRITE")

            results["sections"].append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 4),
                "printable_ascii_ratio": round(printable_ascii_ratio(data), 4),
                "zero_ratio": round(zero_ratio(data), 4),
                "characteristics": flags,
            })

            if entropy > 7.2 and len(data) > 512:
                results["high_entropy_sections"].append({
                    "section": name,
                    "entropy": round(entropy, 4),
                    "reason": "Very high entropy; possible packed, encrypted, or compressed data.",
                })

            if name.lower() in COMMON_PACKER_SECTION_NAMES:
                results["packer_section_names"].append(name)

        imports, suspicious = extract_imports(pe)
        results["imports"] = imports
        results["suspicious_imports"] = suspicious
        entry_point_va = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        results["capstone"] = disassemble_executable_sections(pe, entry_point_va=entry_point_va)

    except pefile.PEFormatError:
        results["error"] = "Not a valid PE file"
    except Exception as exc:
        results["error"] = str(exc)

    return results


def build_feature_vector(file_path: str, pe_analysis: Dict[str, Any], xor_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Build a flat feature vector suitable for CSV export or ML inference."""
    sections = pe_analysis.get("sections", [])
    executable_sections = [s for s in sections if "EXECUTE" in s.get("characteristics", [])]
    writable_executable_sections = [
        s for s in sections
        if "EXECUTE" in s.get("characteristics", []) and "WRITE" in s.get("characteristics", [])
    ]
    entropies = [s.get("entropy", 0.0) for s in sections]

    cap = pe_analysis.get("capstone", {}).get("summary", {})

    features = {
        "file_size": os.path.getsize(file_path),
        "valid_pe": int(bool(pe_analysis.get("valid_pe"))),
        "section_count": len(sections),
        "executable_section_count": len(executable_sections),
        "writable_executable_section_count": len(writable_executable_sections),
        "total_entropy": pe_analysis.get("total_entropy", 0.0),
        "max_section_entropy": max(entropies) if entropies else 0.0,
        "mean_section_entropy": statistics.mean(entropies) if entropies else 0.0,
        "high_entropy_section_count": len(pe_analysis.get("high_entropy_sections", [])),
        "import_count": len(pe_analysis.get("imports", [])),
        "suspicious_import_count": len(pe_analysis.get("suspicious_imports", [])),
        "packer_section_name_count": len(pe_analysis.get("packer_section_names", [])),
        "xor_key_count": len(xor_analysis.get("xor_keys", [])),
        "instruction_count": cap.get("instruction_count", 0),
        "nop_like_ratio": cap.get("nop_like_ratio", 0.0),
        "indirect_branch_call_ratio": cap.get("indirect_branch_call_ratio", 0.0),
        "conditional_jump_ratio": cap.get("conditional_jump_ratio", 0.0),
        "unconditional_jump_ratio": cap.get("unconditional_jump_ratio", 0.0),
        "compare_test_ratio": cap.get("compare_test_ratio", 0.0),
        "stack_op_ratio": cap.get("stack_op_ratio", 0.0),
        "zeroing_idiom_ratio": cap.get("zeroing_idiom_ratio", 0.0),
        "ret_ratio": cap.get("ret_ratio", 0.0),
        "rotate_ratio": cap.get("rotate_ratio", 0.0),
        "register_indirect_transfer_ratio": cap.get("register_indirect_transfer_ratio", 0.0),
        "segment_peb_access_ratio": cap.get("segment_peb_access_ratio", 0.0),
        "anti_disassembly_trap_ratio": cap.get("anti_disassembly_trap_ratio", 0.0),
        "call_pop_getpc_count": cap.get("call_pop_getpc_count", 0),
        "cfg_block_count": cap.get("cfg_block_count", 0),
        "cfg_edge_count": cap.get("cfg_edge_count", 0),
        "cfg_unreachable_block_count": cap.get("cfg_unreachable_block_count", 0),
        "cfg_unreachable_block_ratio": cap.get("cfg_unreachable_block_ratio", 0.0),
        "cfg_avg_block_size": cap.get("cfg_avg_block_size", 0.0),
        "cfg_small_block_ratio": cap.get("cfg_small_block_ratio", 0.0),
        "cfg_jmp_only_block_ratio": cap.get("cfg_jmp_only_block_ratio", 0.0),
        "cfg_back_edge_ratio": cap.get("cfg_back_edge_ratio", 0.0),
        "cfg_dispatcher_block_count": cap.get("cfg_dispatcher_block_count", 0),
        "cfg_dispatcher_hub_ratio": cap.get("cfg_dispatcher_hub_ratio", 0.0),
        "cfg_flattening_score": cap.get("cfg_flattening_score", 0.0),
        "push_ret_dispatch_count": cap.get("push_ret_dispatch_count", 0),
        "ret_thunk_count": cap.get("ret_thunk_count", 0),
    }

    return {k: round(v, 6) if isinstance(v, float) else v for k, v in features.items()}


def score_obfuscation(pe_analysis: Dict[str, Any], xor_analysis: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Any]:
    """Rule-based scoring with explicit technique hints."""
    score = 0
    details: List[Dict[str, Any]] = []
    techniques = set()
    cap_summary = pe_analysis.get("capstone", {}).get("summary", {})
    cap_sections = pe_analysis.get("capstone", {}).get("sections", [])

    def add(
        points: int,
        indicator: str,
        value: Any,
        severity: str,
        reason: str,
        technique: str,
        evidence: Optional[Any] = None,
    ):
        nonlocal score
        score += points
        techniques.add(technique)
        detail = {
            "indicator": indicator,
            "value": value,
            "severity": severity,
            "reason": reason,
            "technique": technique,
            "points": points,
        }
        if evidence:
            detail["evidence"] = evidence
        details.append(detail)

    if not pe_analysis.get("valid_pe"):
        return {
            "score": 0,
            "status": "UNSUPPORTED / NOT PE",
            "color": "secondary",
            "details": [{
                "indicator": "PE parsing",
                "severity": "INFO",
                "reason": pe_analysis.get("error", "Not a PE file"),
                "points": 0,
            }],
            "possible_techniques": [],
        }

    if not pe_analysis.get("supported_for_analysis", True):
        return {
            "score": 0,
            "status": "UNSUPPORTED / .NET MSIL",
            "color": "secondary",
            "details": [{
                "indicator": "Managed PE format",
                "severity": "INFO",
                "reason": pe_analysis.get("error", ".NET / MSIL binaries need a separate analyzer."),
                "points": 0,
            }],
            "possible_techniques": [],
        }

    if features["total_entropy"] > 7.2:
        add(
            25,
            "High overall entropy",
            features["total_entropy"],
            "HIGH",
            "Overall entropy above 7.2 often indicates compression, encryption, or packing.",
            "Packing / encryption / compression",
        )

    if features["high_entropy_section_count"] > 0:
        add(
            20,
            "High entropy section(s)",
            features["high_entropy_section_count"],
            "HIGH",
            "One or more PE sections have unusually high entropy.",
            "Packed or encrypted sections",
            evidence=pe_analysis.get("high_entropy_sections", [])[:10],
        )

    if features["writable_executable_section_count"] > 0:
        add(
            15,
            "Writable + executable section",
            features["writable_executable_section_count"],
            "HIGH",
            "Sections marked both writable and executable can support unpacking or self-modifying code.",
            "Self-modifying code / unpacking stub",
        )

    if features["packer_section_name_count"] > 0:
        add(
            20,
            "Packer-like section name",
            pe_analysis.get("packer_section_names", []),
            "HIGH",
            "Known packer section names were found.",
            "Known packer artifact",
            evidence=[{"section": name, "reason": "matches known packer section naming"} for name in pe_analysis.get("packer_section_names", [])[:10]],
        )

    if 0 < features["import_count"] < 10:
        add(
            10,
            "Very few imports",
            features["import_count"],
            "LOW",
            "Packed binaries often import very few APIs and resolve others dynamically.",
            "Import hiding / dynamic API resolution",
            evidence=pe_analysis.get("imports", [])[:10],
        )

    if features["suspicious_import_count"] >= 2 or (
        features["suspicious_import_count"] >= 1 and features["import_count"] < 20
    ):
        add(
            15,
            "Suspicious APIs",
            features["suspicious_import_count"],
            "MEDIUM",
            "Memory allocation, memory protection, injection, or dynamic-loading APIs were imported.",
            "Loader behavior / dynamic API resolution",
            evidence=pe_analysis.get("suspicious_imports", [])[:15],
        )

    if features["xor_key_count"] > 0:
        add(
            20,
            "Possible XOR-encoded strings",
            xor_analysis.get("xor_keys", [])[:10],
            "MEDIUM",
            "Common strings appeared after single-byte XOR decoding.",
            "XOR string encoding",
            evidence=xor_analysis.get("hits", [])[:10],
        )

    if features["nop_like_ratio"] > 0.06:
        add(
            12,
            "High NOP/junk-like ratio",
            features["nop_like_ratio"],
            "MEDIUM",
            "A high density of NOP-like instructions can indicate junk-code insertion.",
            "Junk code insertion",
            evidence=cap_summary.get("evidence", {}).get("nop_like_samples", [])[:10],
        )

    if features["indirect_branch_call_ratio"] > 0.04:
        add(
            15,
            "High indirect branch/call density",
            features["indirect_branch_call_ratio"],
            "MEDIUM",
            "Indirect transfers can make static control-flow recovery harder.",
            "Control-flow obfuscation",
            evidence=cap_summary.get("evidence", {}).get("indirect_branch_call_samples", [])[:12],
        )

    if features["cfg_dispatcher_block_count"] >= 3 and features["cfg_flattening_score"] > 0.35:
        add(
            18,
            "Dispatcher-style CFG hub",
            {
                "dispatcher_blocks": features["cfg_dispatcher_block_count"],
                "flattening_score": features["cfg_flattening_score"],
            },
            "HIGH",
            "Recovered basic blocks contain dispatcher-like hubs and graph structure consistent with CFG flattening.",
            "Control-flow flattening",
            evidence=[
                {"section": section.get("name"), **block}
                for section in cap_sections
                for block in section.get("cfg", {}).get("suspicious_blocks", [])
                if "dispatcher-like hub" in block.get("pattern", "")
            ][:10],
        )

    if features["unconditional_jump_ratio"] > 0.08 and features["conditional_jump_ratio"] > 0.06:
        add(
            15,
            "Jump-heavy executable code",
            {
                "jmp": features["unconditional_jump_ratio"],
                "conditional": features["conditional_jump_ratio"],
            },
            "MEDIUM",
            "Jump-heavy code may indicate dispatcher-style control-flow flattening.",
            "Control-flow flattening",
            evidence=(cap_summary.get("evidence", {}).get("conditional_jump_samples", [])[:6] + cap_summary.get("evidence", {}).get("indirect_branch_call_samples", [])[:6])[:12],
        )

    if features["compare_test_ratio"] > 0.08 and features["conditional_jump_ratio"] > 0.08:
        add(
            10,
            "Compare/test + conditional jump density",
            {
                "compare_test": features["compare_test_ratio"],
                "conditional_jump": features["conditional_jump_ratio"],
            },
            "LOW",
            "Dense compare/test and conditional-jump patterns may indicate opaque predicates.",
            "Opaque predicates",
            evidence=(cap_summary.get("evidence", {}).get("compare_test_samples", [])[:6] + cap_summary.get("evidence", {}).get("conditional_jump_samples", [])[:6])[:12],
        )

    if features["cfg_jmp_only_block_ratio"] > 0.3 and features["cfg_small_block_ratio"] > 0.45:
        add(
            12,
            "JMP trampoline / block-splitting pattern",
            {
                "jmp_only_block_ratio": features["cfg_jmp_only_block_ratio"],
                "small_block_ratio": features["cfg_small_block_ratio"],
            },
            "MEDIUM",
            "The recovered CFG contains many tiny blocks that terminate in jumps, which is common in trampoline-based control-flow obfuscation.",
            "Jump trampolines / basic-block splitting",
            evidence=[
                {"section": section.get("name"), **block}
                for section in cap_sections
                for block in section.get("cfg", {}).get("blocks", [])
                if block.get("instruction_count", 0) <= 2 and block.get("terminator") == "jmp"
            ][:10],
        )

    if features["cfg_unreachable_block_ratio"] > 0.35 and features["cfg_block_count"] >= 25:
        add(
            10,
            "High unreachable CFG block ratio",
            features["cfg_unreachable_block_ratio"],
            "MEDIUM",
            "A large fraction of recovered basic blocks are not reachable from the section entry, which can indicate junk code or anti-disassembly data-in-code regions.",
            "Junk code / anti-disassembly",
            evidence=[
                {"section": section.get("name"), **block}
                for section in cap_sections
                for block in section.get("cfg", {}).get("unreachable_blocks", [])
            ][:10],
        )

    if features["push_ret_dispatch_count"] > 0:
        add(
            15,
            "Push-ret dispatch stubs",
            features["push_ret_dispatch_count"],
            "HIGH",
            "Basic blocks containing push-immediate followed by ret are commonly used for RET-based dispatch or trampoline obfuscation.",
            "RET-based control-flow obfuscation",
            evidence=[
                {"section": section.get("name"), **block}
                for section in cap_sections
                for block in section.get("cfg", {}).get("suspicious_blocks", [])
                if "push immediate; ret dispatch stub" in block.get("pattern", "")
            ][:10],
        )

    if features["ret_thunk_count"] > 6 and features["ret_ratio"] > 0.03:
        add(
            8,
            "Many RET thunk blocks",
            {
                "ret_thunk_count": features["ret_thunk_count"],
                "ret_ratio": features["ret_ratio"],
            },
            "LOW",
            "An unusual number of RET-only blocks can appear in retpoline-like or RET-based dispatch patterns.",
            "RET-based control-flow obfuscation",
            evidence=[
                {"section": section.get("name"), **block}
                for section in cap_sections
                for block in section.get("cfg", {}).get("ret_thunk_blocks", [])
            ][:10],
        )

    if features["segment_peb_access_ratio"] > 0 and features["import_count"] < 20:
        add(
            12,
            "PEB/TEB access pattern",
            {
                "segment_access_ratio": features["segment_peb_access_ratio"],
                "import_count": features["import_count"],
            },
            "MEDIUM",
            "FS/GS segment access with a small visible import table can indicate PEB walking or manual import resolution.",
            "Manual API resolution / PEB walking",
            evidence=cap_summary.get("evidence", {}).get("segment_peb_access_samples", [])[:10],
        )

    if features["rotate_ratio"] > 0.015 and features["suspicious_import_count"] == 0 and features["import_count"] < 20:
        add(
            8,
            "Rotate-heavy low-import code",
            {
                "rotate_ratio": features["rotate_ratio"],
                "import_count": features["import_count"],
            },
            "LOW",
            "ROL/ROR-heavy code with few imports may indicate API hashing or custom decoder logic.",
            "API hashing / custom decoder",
            evidence=cap_summary.get("evidence", {}).get("rotate_samples", [])[:10],
        )

    if features["anti_disassembly_trap_ratio"] > 0:
        add(
            10,
            "Anti-disassembly trap instructions",
            features["anti_disassembly_trap_ratio"],
            "MEDIUM",
            "Instructions such as INT3 or UD2 can be used to break linear sweep disassembly or frustrate analysts.",
            "Anti-disassembly traps",
            evidence=cap_summary.get("evidence", {}).get("anti_disassembly_trap_samples", [])[:10],
        )

    if features["call_pop_getpc_count"] >= 3 and (
        features["import_count"] < 20
        or features["total_entropy"] > 6.8
        or features["xor_key_count"] > 0
        or features["segment_peb_access_ratio"] > 0
    ):
        add(
            10,
            "Call-pop GetPC pattern",
            features["call_pop_getpc_count"],
            "LOW",
            "Call followed by pop can be used to discover the current code address.",
            "Shellcode-style position-independent code",
            evidence=cap_summary.get("evidence", {}).get("call_pop_getpc_samples", [])[:10],
        )

    score = min(score, 100)

    if score >= 70:
        status, color = "HIGHLY OBFUSCATED", "danger"
    elif score >= 45:
        status, color = "OBFUSCATED", "warning"
    elif score > 0:
        status, color = "POSSIBLY OBFUSCATED", "info"
    else:
        status, color = "NO STRONG OBFUSCATION INDICATORS", "success"

    return {
        "score": score,
        "status": status,
        "color": color,
        "details": details,
        "possible_techniques": sorted(techniques),
    }


def analyze_binary(file_path: str) -> Dict[str, Any]:
    file_path_obj = Path(file_path)
    raw_data = file_path_obj.read_bytes()

    pe_analysis = analyze_pe_file(file_path)
    xor_analysis = detect_xor_strings(file_path)
    content_indicators = {
        "base64_sequences": detect_base64_sequences(raw_data),
        "padding": detect_padding_sequences(raw_data),
    }
    features = build_feature_vector(file_path, pe_analysis, xor_analysis)
    obfuscation = score_obfuscation(pe_analysis, xor_analysis, features)

    return {
        "filename": file_path_obj.name,
        "file_size": os.path.getsize(file_path),
        "pe_analysis": pe_analysis,
        "xor_analysis": xor_analysis,
        "content_indicators": content_indicators,
        "features": features,
        "obfuscation": obfuscation,
    }
