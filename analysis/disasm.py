from __future__ import annotations

from collections import Counter, deque
from typing import Any, Dict, List, Optional, Tuple

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_EIP, X86_REG_INVALID, X86_REG_RIP


def build_instruction_evidence(insn: Any, section: str, note: Optional[str] = None) -> Dict[str, Any]:
    evidence = {
        "section": section,
        "address": hex(insn.address),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "bytes": " ".join(f"{byte:02x}" for byte in bytes(insn.bytes)),
    }
    if note:
        evidence["note"] = note
    return evidence


def get_capstone_engine(machine: int) -> Optional[Cs]:
    if machine == 0x14C:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif machine == 0x8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        return None

    md.detail = True
    return md


def get_pointer_size(machine: int) -> int:
    if machine == 0x14C:
        return 4
    if machine == 0x8664:
        return 8
    return 4


def get_memory_operand_target(insn: Any) -> Optional[int]:
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


def collect_iat_addresses(pe: pefile.PE) -> set[int]:
    addresses: set[int] = set()
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return addresses

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.address:
                addresses.add(int(imp.address))

    return addresses


def immediate_to_little_endian_bytes(value: int, size: int) -> bytes:
    width = max(int(size or 1), 1)
    mask = (1 << (width * 8)) - 1
    return int(value & mask).to_bytes(width, byteorder="little", signed=False)


def get_stack_memory_reference(insn: Any, operand: Any, stack_depth: int) -> Optional[Dict[str, Any]]:
    if operand.type != X86_OP_MEM:
        return None

    try:
        base_name = insn.reg_name(operand.mem.base).lower()
    except Exception:
        return None

    if base_name in {"esp", "rsp"}:
        base_kind = "sp"
    elif base_name in {"ebp", "rbp"}:
        base_kind = "bp"
    else:
        return None

    disp = int(getattr(operand.mem, "disp", 0) or 0)
    size = max(int(getattr(operand, "size", 0) or 1), 1)
    resolved_offset = stack_depth + disp if base_kind == "sp" else disp
    return {
        "base_kind": base_kind,
        "offset": resolved_offset,
        "size": size,
    }


def extract_ascii_from_stack_snapshot(
    snapshot: Dict[Tuple[str, int], int],
    base_kind: str,
    offsets: set[int],
    min_length: int = 4,
) -> Optional[str]:
    if not offsets:
        return None

    segments: List[str] = []
    current: List[int] = []
    for offset in range(min(offsets), max(offsets) + 1):
        value = snapshot.get((base_kind, offset))
        if value is None:
            if len(current) >= min_length:
                segments.append(bytes(current).decode("ascii", errors="ignore"))
            current = []
            continue
        if 32 <= value <= 126:
            current.append(value)
        else:
            if len(current) >= min_length:
                segments.append(bytes(current).decode("ascii", errors="ignore"))
            current = []

    if len(current) >= min_length:
        segments.append(bytes(current).decode("ascii", errors="ignore"))

    if not segments:
        return None

    preview = segments[0]
    return preview[:32] + ("..." if len(preview) > 32 else "")


def detect_stack_string_xor_patterns(
    disassembled: List[Any],
    section_name: str,
    pointer_size: int,
    max_hits: int = 8,
) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    stack_depth = 0
    stack_bytes: Dict[Tuple[str, int], int] = {}
    recent_writes: List[Dict[str, Any]] = []
    active_candidate: Optional[Dict[str, Any]] = None

    def reset_tracking() -> None:
        nonlocal stack_depth, stack_bytes, recent_writes, active_candidate
        stack_depth = 0
        stack_bytes = {}
        recent_writes = []
        active_candidate = None

    def finalize_candidate() -> None:
        nonlocal active_candidate
        if active_candidate is None:
            return
        if len(active_candidate["xor_instructions"]) < 2 or len(active_candidate["offsets"]) < 2:
            active_candidate = None
            return

        decoded_preview = extract_ascii_from_stack_snapshot(
            active_candidate["snapshot"],
            active_candidate["base_kind"],
            active_candidate["offsets"],
        )
        if not decoded_preview:
            active_candidate = None
            return

        key_text = ", ".join(sorted(set(active_candidate["keys"]))[:3])
        pattern = "stack-built bytes XOR-decoded on the stack"
        if key_text:
            pattern += f" (keys: {key_text})"

        instructions = active_candidate["write_instructions"] + active_candidate["xor_instructions"]
        hits.append({
            "block": hex(active_candidate["address"]),
            "section": section_name,
            "pattern": pattern,
            "preview": decoded_preview,
            "instructions": instructions[:10],
        })
        active_candidate = None

    for index, insn in enumerate(disassembled):
        mnemonic = insn.mnemonic.lower()
        operands = list(getattr(insn, "operands", []) or [])

        if mnemonic == "push" and operands and operands[0].type == X86_OP_IMM:
            stack_depth -= pointer_size
            raw = immediate_to_little_endian_bytes(int(operands[0].imm), pointer_size)
            for byte_index, value in enumerate(raw):
                stack_bytes[("sp", stack_depth + byte_index)] = value
            recent_writes.append({
                "index": index,
                "base_kind": "sp",
                "offset": stack_depth,
                "size": len(raw),
                "instruction": build_instruction_evidence(insn, section_name, note="push immediate stack data"),
            })
        elif mnemonic == "pop":
            stack_depth += pointer_size
        elif (
            mnemonic in {"sub", "add"}
            and len(operands) == 2
            and operands[0].type != X86_OP_IMM
            and operands[1].type == X86_OP_IMM
        ):
            try:
                reg_name = insn.reg_name(operands[0].reg).lower()
            except Exception:
                reg_name = ""
            adjust = int(operands[1].imm)
            if reg_name in {"esp", "rsp"}:
                if mnemonic == "sub":
                    stack_depth -= adjust
                else:
                    stack_depth += adjust
        elif mnemonic == "mov" and len(operands) == 2 and operands[1].type == X86_OP_IMM:
            stack_ref = get_stack_memory_reference(insn, operands[0], stack_depth)
            if stack_ref is not None:
                raw = immediate_to_little_endian_bytes(int(operands[1].imm), stack_ref["size"])
                for byte_index, value in enumerate(raw):
                    stack_bytes[(stack_ref["base_kind"], stack_ref["offset"] + byte_index)] = value
                recent_writes.append({
                    "index": index,
                    "base_kind": stack_ref["base_kind"],
                    "offset": stack_ref["offset"],
                    "size": stack_ref["size"],
                    "instruction": build_instruction_evidence(insn, section_name, note="immediate stack write"),
                })
        elif mnemonic == "xor" and len(operands) == 2 and operands[1].type == X86_OP_IMM:
            stack_ref = get_stack_memory_reference(insn, operands[0], stack_depth)
            if stack_ref is not None:
                raw_key = immediate_to_little_endian_bytes(int(operands[1].imm), stack_ref["size"])
                touched_offsets = set(range(stack_ref["offset"], stack_ref["offset"] + stack_ref["size"]))
                for byte_index, key_byte in enumerate(raw_key):
                    slot = (stack_ref["base_kind"], stack_ref["offset"] + byte_index)
                    if slot in stack_bytes:
                        stack_bytes[slot] ^= key_byte

                write_matches = [
                    event
                    for event in recent_writes
                    if index - event["index"] <= 24
                    and event["base_kind"] == stack_ref["base_kind"]
                    and abs(event["offset"] - stack_ref["offset"]) <= 64
                ]

                if write_matches:
                    if (
                        active_candidate is not None
                        and (
                            active_candidate["base_kind"] != stack_ref["base_kind"]
                            or index - active_candidate["last_index"] > 8
                        )
                    ):
                        finalize_candidate()

                    if active_candidate is None:
                        active_candidate = {
                            "address": insn.address,
                            "base_kind": stack_ref["base_kind"],
                            "last_index": index,
                            "offsets": set(),
                            "keys": [],
                            "write_instructions": [event["instruction"] for event in write_matches[:4]],
                            "xor_instructions": [],
                            "snapshot": dict(stack_bytes),
                        }

                    active_candidate["last_index"] = index
                    active_candidate["offsets"].update(touched_offsets)
                    active_candidate["keys"].append(
                        f"0x{int(operands[1].imm) & ((1 << (stack_ref['size'] * 8)) - 1):0{stack_ref['size'] * 2}x}"
                    )
                    active_candidate["xor_instructions"].append(
                        build_instruction_evidence(insn, section_name, note="stack XOR decode")
                    )
                    active_candidate["snapshot"] = dict(stack_bytes)

        recent_writes = [event for event in recent_writes if index - event["index"] <= 32]

        if mnemonic in {"ret", "retn", "retf", "jmp"}:
            finalize_candidate()
            reset_tracking()
            continue

        if active_candidate is not None and index - active_candidate["last_index"] > 8:
            finalize_candidate()

        if len(hits) >= max_hits:
            break

    finalize_candidate()
    return hits[:max_hits]


def is_conditional_jump(mnemonic: str) -> bool:
    return mnemonic.startswith("j") and mnemonic not in {"jmp"}


def is_unconditional_jump(mnemonic: str) -> bool:
    return mnemonic == "jmp"


def is_return(mnemonic: str) -> bool:
    return mnemonic.startswith("ret")


def get_direct_branch_target(insn: Any) -> Optional[int]:
    if not getattr(insn, "operands", None) or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type == X86_OP_IMM:
        return int(operand.imm)
    return None


def instruction_uses_same_operand_twice(insn: Any) -> bool:
    operands = [part.strip().lower() for part in str(getattr(insn, "op_str", "")).split(",")]
    return len(operands) == 2 and operands[0] and operands[0] == operands[1]


def classify_basic_opaque_predicate(prev: Any, cur: Any) -> Optional[str]:
    prev_mnemonic = prev.mnemonic.lower()
    cur_mnemonic = cur.mnemonic.lower()
    if not is_conditional_jump(cur_mnemonic):
        return None

    if prev_mnemonic in {"cmp", "test"} and instruction_uses_same_operand_twice(prev):
        return "compare/test of the same operand forces a constant branch condition"
    if prev_mnemonic in {"xor", "sub"} and instruction_uses_same_operand_twice(prev):
        return "zeroing the same operand before a conditional jump forces a constant branch condition"
    return None


def build_cfg_for_section(
    instructions: List[Any],
    section_name: str,
    section_start: int,
    section_end: int,
    entry_point_va: Optional[int],
) -> Dict[str, Any]:
    if not instructions:
        return {
            "block_count": 0,
            "edge_count": 0,
            "reachable_block_count": 0,
            "unreachable_block_count": 0,
            "unreachable_block_ratio": 0.0,
            "sink_vertices": [],
        }

    leaders = {instructions[0].address}
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

    sink_vertices = []
    for block in block_entries:
        if (
            not block["successors"]
            and not is_return(block["terminator"])
            and block["terminator"] not in {"jmp", "call"}
        ):
            sink_vertices.append({
                "block": hex(block["start"]),
                "terminator": block["terminator"],
                "pattern": "basic block ends without a normal exit edge; possible junk or decode dead-end",
                "instructions": [
                    build_instruction_evidence(insn, section=section_name)
                    for insn in block["instructions"][:3]
                ],
            })

    block_count = len(block_entries)
    reachable_count = len(reachable)
    unreachable_count = block_count - reachable_count
    sink_ratio = len(sink_vertices) / block_count if block_count else 0.0

    return {
        "block_count": block_count,
        "edge_count": sum(
            1 for block in block_entries for edge in block["successors"] if edge["target"] is not None
        ),
        "reachable_block_count": reachable_count,
        "unreachable_block_count": unreachable_count,
        "unreachable_block_ratio": unreachable_count / block_count if block_count else 0.0,
        "sink_vertices": sink_vertices[:10],
        "sink_vertex_ratio": sink_ratio,
    }


def summarize_disassembly(
    pe: pefile.PE,
    entry_point_va: Optional[int] = None,
    max_bytes_per_section: int = 512 * 1024,
) -> Dict[str, Any]:
    md = get_capstone_engine(pe.FILE_HEADER.Machine)
    if md is None:
        return {
            "supported": False,
            "reason": "Capstone disassembly is implemented for x86/x64 PE files only.",
        }

    pointer_size = get_pointer_size(pe.FILE_HEADER.Machine)
    global_counts = Counter()
    global_evidence = {
        "rotate_samples": [],
        "segment_peb_access_samples": [],
        "memory_xor_immediate_samples": [],
        "basic_opaque_predicate_samples": [],
        "sink_vertex_samples": [],
        "stack_string_xor_samples": [],
    }
    sink_vertices_total = 0
    block_total = 0

    for section in pe.sections:
        if not (section.Characteristics & 0x20000000):
            continue

        name = section.Name.decode(errors="ignore").strip("\x00")
        data = section.get_data()[:max_bytes_per_section]
        va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

        try:
            disassembled = list(md.disasm(data, va))
        except Exception:
            continue

        last_instructions: List[Any] = []
        for insn in disassembled:
            global_counts["total"] += 1
            mnemonic = insn.mnemonic.lower()
            op_str = insn.op_str.lower()

            if mnemonic in {"rol", "ror"}:
                global_counts["rotate"] += 1
                if len(global_evidence["rotate_samples"]) < 10:
                    global_evidence["rotate_samples"].append(
                        build_instruction_evidence(insn, name, note="rotate instruction")
                    )

            if "fs:" in op_str or "gs:" in op_str:
                global_counts["segment_peb_access"] += 1
                if len(global_evidence["segment_peb_access_samples"]) < 10:
                    global_evidence["segment_peb_access_samples"].append(
                        build_instruction_evidence(insn, name, note="segment-based PEB/TEB access")
                    )

            if mnemonic == "xor" and getattr(insn, "operands", None) and len(insn.operands) == 2:
                dst, src = insn.operands
                if dst.type == X86_OP_MEM and src.type == X86_OP_IMM:
                    key = int(src.imm) & 0xFF
                    if key:
                        global_counts["memory_xor_immediate"] += 1
                        if len(global_evidence["memory_xor_immediate_samples"]) < 10:
                            evidence = build_instruction_evidence(
                                insn,
                                name,
                                note=f"memory XOR immediate key 0x{key:02x}",
                            )
                            evidence["key"] = f"0x{key:02x}"
                            evidence["key_value"] = key
                            global_evidence["memory_xor_immediate_samples"].append(evidence)

            last_instructions.append(insn)
            if len(last_instructions) > 5:
                last_instructions.pop(0)

            if len(last_instructions) >= 2:
                prev = last_instructions[-2]
                cur = last_instructions[-1]
                opaque_reason = classify_basic_opaque_predicate(prev, cur)
                if opaque_reason:
                    global_counts["basic_opaque_predicate"] += 1
                    evidence = {
                        "section": name,
                        "address": hex(prev.address),
                        "pattern": opaque_reason,
                        "instructions": [
                            build_instruction_evidence(prev, name, note="flag-setting instruction"),
                            build_instruction_evidence(cur, name, note="conditional jump"),
                        ],
                    }
                    if len(global_evidence["basic_opaque_predicate_samples"]) < 10:
                        global_evidence["basic_opaque_predicate_samples"].append(evidence)

        stack_hits = detect_stack_string_xor_patterns(
            disassembled,
            section_name=name,
            pointer_size=pointer_size,
        )
        if stack_hits:
            global_counts["stack_string_xor"] += len(stack_hits)
            global_evidence["stack_string_xor_samples"].extend(stack_hits[:8])

        cfg = build_cfg_for_section(
            disassembled,
            section_name=name,
            section_start=va,
            section_end=va + len(data),
            entry_point_va=entry_point_va if entry_point_va and va <= entry_point_va < va + len(data) else None,
        )
        sink_vertices_total += len(cfg.get("sink_vertices", []))
        block_total += cfg.get("block_count", 0)
        if cfg.get("sink_vertices"):
            global_evidence["sink_vertex_samples"].extend(cfg["sink_vertices"][:8])

    total = max(global_counts["total"], 1)
    summary = {
        "instruction_count": global_counts["total"],
        "rotate_count": global_counts["rotate"],
        "rotate_ratio": global_counts["rotate"] / total,
        "segment_peb_access_count": global_counts["segment_peb_access"],
        "segment_peb_access_ratio": global_counts["segment_peb_access"] / total,
        "memory_xor_immediate_count": global_counts["memory_xor_immediate"],
        "basic_opaque_predicate_count": global_counts["basic_opaque_predicate"],
        "stack_string_xor_count": global_counts["stack_string_xor"],
        "cfg_block_count": block_total,
        "cfg_sink_vertex_count": sink_vertices_total,
        "cfg_sink_vertex_ratio": sink_vertices_total / max(block_total, 1),
    }

    return {
        "supported": True,
        "summary": {k: round(v, 6) if isinstance(v, float) else v for k, v in summary.items()},
        "evidence": {k: v[:10] for k, v in global_evidence.items() if v},
    }
