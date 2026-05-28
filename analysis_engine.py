#!/usr/bin/env python3
"""Static Windows PE obfuscation analyzer for the ideas3.md presentation scope."""

from __future__ import annotations

import math
import os
import statistics
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

MIN_XOR_PRINTABLE_LENGTH = 8
MAX_XOR_KEYS_REPORTED = 8
MAX_XOR_BYTES_PER_REGION = 512 * 1024
TEXT_PUNCTUATION_BYTES = set(b" .,;:'\"!?()[]/-_\\")
TEXT_VOWEL_BYTES = set(b"aeiouAEIOU")
TEXT_TRAILING_PUNCTUATION_BYTES = set(b".,;:!?)]\"'")
TEXT_SUSPICIOUS_SEPARATOR_BYTES = set(b"#$%&*+=|{}<>`~")
XOR_PRIMARY_SECTION_PRIORITIES = {
    ".data": 0,
    ".rdata": 1,
    ".sdata": 2,
}
XOR_NOISY_SECTION_NAMES = {
    ".debug",
    ".edata",
    ".idata",
    ".pdata",
    ".reloc",
    ".rsrc",
    ".tls",
}

DYNAMIC_RESOLUTION_APIS = {
    "loadlibrarya",
    "loadlibraryw",
    "loadlibraryexa",
    "loadlibraryexw",
    "getprocaddress",
    "ldrloaddll",
    "ldrgetprocedureaddress",
}


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


def is_printable_ascii_byte(value: int) -> bool:
    return 32 <= value <= 126


def longest_alpha_run(value: bytes) -> int:
    longest = 0
    current = 0
    for byte in value:
        if 65 <= byte <= 90 or 97 <= byte <= 122:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def printable_text_score(value: bytes) -> float:
    """Estimate whether printable bytes look like readable text, not just symbols."""
    if not value:
        return 0.0

    length = len(value)
    printable_count = sum(1 for b in value if is_printable_ascii_byte(b))
    printable_ratio = printable_count / length
    if printable_ratio < 0.85:
        return round(printable_ratio * 0.25, 3)

    alpha_count = sum(1 for b in value if 65 <= b <= 90 or 97 <= b <= 122)
    digit_count = sum(1 for b in value if 48 <= b <= 57)
    whitespace_count = sum(1 for b in value if b in (9, 10, 13, 32))
    punctuation_count = sum(1 for b in value if b in TEXT_PUNCTUATION_BYTES)
    vowel_count = sum(1 for b in value if b in TEXT_VOWEL_BYTES)
    suspicious_separator_count = sum(1 for b in value if b in TEXT_SUSPICIOUS_SEPARATOR_BYTES)
    wordish_count = alpha_count + digit_count + whitespace_count + punctuation_count
    unusual_count = max(0, printable_count - wordish_count)
    most_common_ratio = Counter(value).most_common(1)[0][1] / length

    alpha_ratio = alpha_count / length
    digit_ratio = digit_count / length
    punctuation_ratio = punctuation_count / length
    unusual_ratio = unusual_count / length

    score = printable_ratio * 0.30
    score += min(alpha_ratio / 0.55, 1.0) * 0.45
    score += min((wordish_count / length) / 0.90, 1.0) * 0.10
    if whitespace_count:
        score += 0.08
    if longest_alpha_run(value) >= 4:
        score += 0.10
    if alpha_count >= 5:
        vowel_ratio = vowel_count / alpha_count
        if 0.20 <= vowel_ratio <= 0.55:
            score += 0.08
        elif vowel_ratio < 0.15 or vowel_ratio > 0.70:
            score -= 0.20

    if digit_ratio > 0.45:
        score -= min((digit_ratio - 0.45) / 0.35, 1.0) * 0.10
    if punctuation_ratio > 0.50:
        score -= min((punctuation_ratio - 0.50) / 0.30, 1.0) * 0.15
    if unusual_ratio > 0.10:
        score -= min((unusual_ratio - 0.10) / 0.25, 1.0) * 0.15
    if suspicious_separator_count:
        score -= min(suspicious_separator_count / 3, 1.0) * 0.12
    if most_common_ratio > 0.35:
        score -= min((most_common_ratio - 0.35) / 0.40, 1.0) * 0.15

    return round(max(0.0, min(1.0, score)), 3)


def is_interesting_printable_string(value: bytes) -> bool:
    """Filter out padding-like printable runs after XOR decoding."""
    if len(value) < MIN_XOR_PRINTABLE_LENGTH:
        return False

    if not any((65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) for b in value):
        return False

    counts = Counter(value)
    if len(counts) < 4:
        return False

    most_common_ratio = counts.most_common(1)[0][1] / len(value)
    return most_common_ratio <= 0.65 and printable_text_score(value) >= 0.55


def trim_printable_run(offset: int, value: bytes) -> Tuple[int, bytes]:
    """Drop punctuation-only edges that often come from decoded padding bytes."""
    start = 0
    end = len(value)
    while start < end and not (
        48 <= value[start] <= 57 or 65 <= value[start] <= 90 or 97 <= value[start] <= 122
    ):
        start += 1
    while end > start and not (
        48 <= value[end - 1] <= 57
        or 65 <= value[end - 1] <= 90
        or 97 <= value[end - 1] <= 122
        or value[end - 1] in TEXT_TRAILING_PUNCTUATION_BYTES
    ):
        end -= 1
    return offset + start, value[start:end]


def classify_xor_decode(original: bytes, decoded: bytes) -> Optional[Dict[str, Any]]:
    """Return evidence metadata when XOR output is materially text-like."""
    if not is_interesting_printable_string(decoded):
        return None

    original_printable_ratio = printable_ascii_ratio(original)
    decoded_text_score = printable_text_score(decoded)
    original_text_score = printable_text_score(original)

    if original_printable_ratio < 0.35:
        return {
            "reason": "ciphertext bytes were mostly non-printable",
            "text_score": decoded_text_score,
            "original_printable_ratio": round(original_printable_ratio, 3),
        }

    if decoded_text_score >= 0.72 and decoded_text_score - original_text_score >= 0.30:
        return {
            "reason": "decoded bytes are more text-like than ciphertext",
            "text_score": decoded_text_score,
            "original_text_score": original_text_score,
            "original_printable_ratio": round(original_printable_ratio, 3),
        }

    return None


def build_xor_run_evidence(
    original: bytes,
    decoded: bytes,
    start: int,
    end: int,
    min_length: int,
) -> Optional[Dict[str, Any]]:
    segment = decoded[start:end]
    original_segment = original[start:end]
    trimmed_start, trimmed_segment = trim_printable_run(start, segment)
    trim_delta = trimmed_start - start
    trimmed_original = original_segment[trim_delta:trim_delta + len(trimmed_segment)]

    if len(trimmed_segment) < min_length:
        return None

    classification = classify_xor_decode(trimmed_original, trimmed_segment)
    if not classification:
        return None

    evidence = {
        "offset": hex(trimmed_start),
        "length": len(trimmed_segment),
        "decoded": trimmed_segment[:80].decode("ascii", errors="ignore"),
    }
    evidence.update(classification)
    return evidence


def zero_ratio(data: bytes) -> float:
    """Ratio of null bytes."""
    if not data:
        return 0.0
    return data.count(0) / len(data)


def safe_decode(value: bytes) -> str:
    return value.decode(errors="ignore").strip("\x00").strip()


def detect_binary_format(file_path: str) -> str:
    """Best-effort file type detection for the current PE-only baseline build."""
    return "pe"


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


def get_pointer_size(machine: int) -> int:
    if machine == 0x14C:
        return 4
    if machine == 0x8664:
        return 8
    return 4


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


def get_memory_xor_immediate_key(insn: Any) -> Optional[int]:
    """Detect instructions like `xor byte ptr [addr/reg], 5Ah`."""
    if insn.mnemonic.lower() != "xor":
        return None
    if not getattr(insn, "operands", None) or len(insn.operands) != 2:
        return None

    destination, source = insn.operands
    if destination.type != X86_OP_MEM or source.type != X86_OP_IMM:
        return None

    key = int(source.imm) & 0xff
    if key == 0:
        return None
    return key


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
    max_hits: int = 10,
) -> List[Dict[str, Any]]:
    """Detect stack-built bytes that are XOR-decoded in place on the stack."""
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

        key_text = ", ".join(sorted(set(active_candidate["keys"]))[:4])
        pattern = "stack-built bytes XOR-decoded on the stack"
        pattern += f" -> {decoded_preview}"
        if key_text:
            pattern += f" (keys: {key_text})"

        instructions = active_candidate["write_instructions"] + active_candidate["xor_instructions"]
        hits.append({
            "block": hex(active_candidate["address"]),
            "section": section_name,
            "pattern": pattern,
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
                    active_candidate["keys"].append(f"0x{int(operands[1].imm) & ((1 << (stack_ref['size'] * 8)) - 1):0{stack_ref['size'] * 2}x}")
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


def get_import_names(imports: List[Dict[str, str]]) -> set[str]:
    return {str(row.get("api", "")).lower() for row in imports}


def summarize_import_obfuscation(imports: List[Dict[str, str]]) -> Dict[str, Any]:
    import_names = get_import_names(imports)
    dynamic_apis = sorted(api for api in import_names if api in DYNAMIC_RESOLUTION_APIS)
    return {
        "import_count": len(imports),
        "dynamic_resolution_apis": dynamic_apis,
        "has_loadlibrary": any(api.startswith("loadlibrary") or api == "ldrloaddll" for api in dynamic_apis),
        "has_getprocaddress": any(api in {"getprocaddress", "ldrgetprocedureaddress"} for api in dynamic_apis),
        "evidence": [
            row for row in imports
            if str(row.get("api", "")).lower() in DYNAMIC_RESOLUTION_APIS
        ][:12],
    }


def normalize_section_name(name: str) -> str:
    return (name or "").strip().lower().split("$", 1)[0]


def get_xor_section_priority(section: pefile.SectionStructure) -> Optional[int]:
    """Rank PE sections for string-decode scans, preferring real string/data areas."""
    if section_is_executable(section):
        return None

    name = normalize_section_name(safe_decode(section.Name))
    if name in XOR_NOISY_SECTION_NAMES:
        return None
    if name in XOR_PRIMARY_SECTION_PRIORITIES:
        return XOR_PRIMARY_SECTION_PRIORITIES[name]
    if section_is_writable(section):
        return 10
    if section_is_readable(section):
        return 20
    return 30


def get_xor_scan_regions(file_path: str, sample_size: int) -> List[Dict[str, Any]]:
    """Prefer PE data sections for XOR string scans; fall back to raw bytes."""
    regions: List[Dict[str, Any]] = []

    try:
        pe = pefile.PE(file_path, fast_load=True)
        candidates = []
        for section in pe.sections:
            priority = get_xor_section_priority(section)
            if priority is None:
                continue

            data = section.get_data()
            if len(data) < MIN_XOR_PRINTABLE_LENGTH:
                continue

            candidates.append((
                priority,
                int(section.PointerToRawData),
                safe_decode(section.Name) or "section",
                data,
            ))

        remaining = sample_size
        for _, offset, name, data in sorted(candidates, key=lambda item: (item[0], item[1])):
            if remaining <= 0:
                break
            region_size = min(len(data), remaining, MAX_XOR_BYTES_PER_REGION)
            regions.append({
                "name": name,
                "offset": offset,
                "data": data[:region_size],
            })
            remaining -= region_size
    except Exception:
        regions = []

    if regions:
        return regions

    data = Path(file_path).read_bytes()[:sample_size]
    return [{"name": "file", "offset": 0, "data": data}]


def find_printable_xor_runs(
    original: bytes,
    decoded: bytes,
    min_length: int = MIN_XOR_PRINTABLE_LENGTH,
    limit: int = 8,
    base_offset: int = 0,
    region_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    runs: List[Dict[str, Any]] = []
    start: Optional[int] = None

    for index, value in enumerate(decoded):
        if is_printable_ascii_byte(value):
            if start is None:
                start = index
            continue

        if start is not None:
            evidence = build_xor_run_evidence(original, decoded, start, index, min_length)
            if evidence:
                evidence["offset"] = hex(base_offset + int(evidence["offset"], 16))
                if region_name:
                    evidence["region"] = region_name
                runs.append(evidence)
                if len(runs) >= limit:
                    return runs
            start = None

    if start is not None:
        evidence = build_xor_run_evidence(original, decoded, start, len(decoded), min_length)
        if evidence:
            evidence["offset"] = hex(base_offset + int(evidence["offset"], 16))
            if region_name:
                evidence["region"] = region_name
            runs.append(evidence)

    return runs[:limit]


def detect_xor_strings(
    file_path: str,
    pe_analysis: Optional[Dict[str, Any]] = None,
    sample_size: int = 2 * 1024 * 1024,
) -> Dict[str, Any]:
    """
    Quick XOR-key scan.

    This checks single-byte XOR keys by looking for readable printable strings:
    either ciphertext becomes printable, or already-printable ciphertext becomes
    materially more text-like after decoding. It does not match against a fixed
    list of common malware strings.
    """
    result: Dict[str, Any] = {
        "xor_keys": [],
        "hits": [],
        "stack_string_xor_hits": [],
        "tested_bytes": 0,
        "scan_regions": [],
    }

    try:
        regions = get_xor_scan_regions(file_path, sample_size)
        result["scan_regions"] = [
            {"name": region["name"], "offset": hex(region["offset"]), "size": len(region["data"])}
            for region in regions
        ]
        result["tested_bytes"] = sum(len(region["data"]) for region in regions)

        hinted_keys = set()
        if pe_analysis:
            cap_summary = pe_analysis.get("capstone", {}).get("summary", {})
            for sample in cap_summary.get("evidence", {}).get("memory_xor_immediate_samples", []):
                key = sample.get("key_value")
                if isinstance(key, int) and 1 <= key <= 255:
                    hinted_keys.add(key)

        key_hits = []
        for key in range(1, 256):
            runs = []
            for region in regions:
                original = region["data"]
                decoded = bytes(b ^ key for b in original)
                runs.extend(find_printable_xor_runs(
                    original,
                    decoded,
                    limit=max(1, 8 - len(runs)),
                    base_offset=region["offset"],
                    region_name=region["name"],
                ))
                if len(runs) >= 8:
                    break
            if not runs:
                continue
            key_hits.append({
                "key_value": key,
                "key": f"0x{key:02x}",
                "instruction_key_hint": key in hinted_keys,
                "printable_string_count": len(runs),
                "printable_character_count": sum(item["length"] for item in runs),
                "best_text_score": max(item.get("text_score", 0.0) for item in runs),
                "examples": runs[:5],
            })

        key_hits.sort(key=lambda item: (
            not item["instruction_key_hint"],
            -item["best_text_score"],
            -item["printable_character_count"],
            -item["printable_string_count"],
            item["key_value"],
        ))
        for item in key_hits:
            item.pop("key_value", None)
        result["hits"] = key_hits[:MAX_XOR_KEYS_REPORTED]
        result["xor_keys"] = [item["key"] for item in result["hits"]]

        if pe_analysis:
            cap_summary = pe_analysis.get("capstone", {}).get("summary", {})
            result["stack_string_xor_hits"] = cap_summary.get("evidence", {}).get("stack_string_xor_samples", [])[:10]

        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


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
            "sink_vertex_count": 0,
            "sink_vertex_ratio": 0.0,
            "suspicious_blocks": [],
            "sink_vertices": [],
            "unreachable_blocks": [],
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

    sink_vertices = []
    suspicious_blocks = []

    for block in block_entries:
        instructions_in_block = block["instructions"]
        if (
            not block["successors"]
            and not is_return(block["terminator"])
            and block["terminator"] not in {"jmp", "call"}
        ):
            sink_entry = {
                "block": hex(block["start"]),
                "terminator": block["terminator"],
                "pattern": "basic block ends without a normal exit edge; possible junk or decode dead-end",
                "instructions": [
                    build_instruction_evidence(insn, section=section_name)
                    for insn in instructions_in_block[:3]
                ],
            }
            sink_vertices.append(sink_entry)
            suspicious_blocks.append(sink_entry)

    block_count = len(block_entries)
    reachable_count = len(reachable)
    unreachable_count = block_count - reachable_count
    avg_block_size = statistics.mean(block["instruction_count"] for block in block_entries) if block_entries else 0.0
    small_block_ratio = len(small_blocks) / block_count if block_count else 0.0
    jmp_only_block_ratio = len(jmp_only_blocks) / block_count if block_count else 0.0
    back_edge_ratio = back_edge_count / edge_count if edge_count else 0.0
    unreachable_block_ratio = unreachable_count / block_count if block_count else 0.0
    sink_vertex_ratio = len(sink_vertices) / block_count if block_count else 0.0

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
        "sink_vertex_count": len(sink_vertices),
        "sink_vertex_ratio": round(sink_vertex_ratio, 6),
        "suspicious_blocks": suspicious_blocks[:25],
        "sink_vertices": sink_vertices[:25],
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
    cfg_totals = Counter()
    iat_addresses = collect_iat_addresses(pe)
    pointer_size = get_pointer_size(pe.FILE_HEADER.Machine)
    global_evidence = {
        "nop_like_samples": [],
        "indirect_branch_call_samples": [],
        "conditional_jump_samples": [],
        "compare_test_samples": [],
        "segment_peb_access_samples": [],
        "rotate_samples": [],
        "stack_string_xor_samples": [],
        "memory_xor_immediate_samples": [],
        "basic_opaque_predicate_samples": [],
        "sink_vertex_samples": [],
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
            "rotate_samples": [],
            "stack_string_xor_samples": [],
            "memory_xor_immediate_samples": [],
            "basic_opaque_predicate_samples": [],
            "sink_vertex_samples": [],
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

                memory_xor_key = get_memory_xor_immediate_key(insn)
                if memory_xor_key is not None:
                    counts["memory_xor_immediate"] += 1
                    global_counts["memory_xor_immediate"] += 1
                    if len(section_evidence["memory_xor_immediate_samples"]) < 10:
                        evidence = build_instruction_evidence(
                            insn,
                            name,
                            note=f"memory XOR immediate key 0x{memory_xor_key:02x}",
                        )
                        evidence["key"] = f"0x{memory_xor_key:02x}"
                        evidence["key_value"] = memory_xor_key
                        section_evidence["memory_xor_immediate_samples"].append(evidence)
                        global_evidence["memory_xor_immediate_samples"].append(evidence)

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
                    opaque_reason = classify_basic_opaque_predicate(prev, cur)
                    if opaque_reason:
                        counts["basic_opaque_predicate"] += 1
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
                        section_evidence["basic_opaque_predicate_samples"].append(evidence)
                        global_evidence["basic_opaque_predicate_samples"].append(evidence)

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

        stack_string_xor_hits = detect_stack_string_xor_patterns(
            disassembled,
            section_name=name,
            pointer_size=pointer_size,
        )
        counts["stack_string_xor"] += len(stack_string_xor_hits)
        global_counts["stack_string_xor"] += len(stack_string_xor_hits)
        if stack_string_xor_hits:
            section_evidence["stack_string_xor_samples"] = stack_string_xor_hits[:10]
            global_evidence["stack_string_xor_samples"].extend(stack_string_xor_hits[:10])

        cfg = build_cfg_for_section(
            disassembled,
            section_name=name,
            section_start=va,
            section_end=va + len(data),
            entry_point_va=entry_point_va if entry_point_va is not None and va <= entry_point_va < va + len(data) else None,
        )
        if cfg.get("sink_vertices"):
            section_evidence["sink_vertex_samples"] = cfg["sink_vertices"][:10]
            global_evidence["sink_vertex_samples"].extend(cfg["sink_vertices"][:10])

        cfg_totals["block_count"] += cfg["block_count"]
        cfg_totals["edge_count"] += cfg["edge_count"]
        cfg_totals["reachable_block_count"] += cfg["reachable_block_count"]
        cfg_totals["unreachable_block_count"] += cfg["unreachable_block_count"]
        cfg_totals["avg_block_size_sum"] += cfg["avg_block_size"] * max(cfg["block_count"], 1)
        cfg_totals["small_block_weight"] += cfg["small_block_ratio"] * cfg["block_count"]
        cfg_totals["jmp_only_block_weight"] += cfg["jmp_only_block_ratio"] * cfg["block_count"]
        cfg_totals["back_edge_weight"] += cfg["back_edge_ratio"] * max(cfg["edge_count"], 1)
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
            "stack_string_xor_count": counts["stack_string_xor"],
            "memory_xor_immediate_count": counts["memory_xor_immediate"],
            "basic_opaque_predicate_count": counts["basic_opaque_predicate"],
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
        "rotate_count": global_counts["rotate"],
        "rotate_ratio": global_counts["rotate"] / total,
        "register_indirect_transfer_ratio": global_counts["register_indirect_transfer"] / total,
        "segment_peb_access_count": global_counts["segment_peb_access"],
        "segment_peb_access_ratio": global_counts["segment_peb_access"] / total,
        "stack_string_xor_count": global_counts["stack_string_xor"],
        "memory_xor_immediate_count": global_counts["memory_xor_immediate"],
        "basic_opaque_predicate_count": global_counts["basic_opaque_predicate"],
        "cfg_block_count": cfg_totals["block_count"],
        "cfg_edge_count": cfg_totals["edge_count"],
        "cfg_unreachable_block_count": cfg_totals["unreachable_block_count"],
        "cfg_unreachable_block_ratio": cfg_totals["unreachable_weight"] / total_blocks,
        "cfg_avg_block_size": cfg_totals["avg_block_size_sum"] / total_blocks,
        "cfg_small_block_ratio": cfg_totals["small_block_weight"] / total_blocks,
        "cfg_jmp_only_block_ratio": cfg_totals["jmp_only_block_weight"] / total_blocks,
        "cfg_back_edge_ratio": cfg_totals["back_edge_weight"] / total_edges,
        "cfg_sink_vertex_count": cfg_totals["sink_vertex_count"],
        "cfg_sink_vertex_ratio": cfg_totals["sink_vertex_count"] / total_blocks,
        "evidence": {
            "nop_like_samples": global_evidence["nop_like_samples"][:10],
            "indirect_branch_call_samples": global_evidence["indirect_branch_call_samples"][:12],
            "conditional_jump_samples": global_evidence["conditional_jump_samples"][:12],
            "compare_test_samples": global_evidence["compare_test_samples"][:12],
            "segment_peb_access_samples": global_evidence["segment_peb_access_samples"][:10],
            "rotate_samples": global_evidence["rotate_samples"][:10],
            "stack_string_xor_samples": global_evidence["stack_string_xor_samples"][:10],
            "memory_xor_immediate_samples": global_evidence["memory_xor_immediate_samples"][:10],
            "basic_opaque_predicate_samples": global_evidence["basic_opaque_predicate_samples"][:10],
            "sink_vertex_samples": global_evidence["sink_vertex_samples"][:10],
        },
    }

    return {
        "supported": True,
        "sections": section_results,
        "summary": {k: round(v, 6) if isinstance(v, float) else v for k, v in summary.items()},
    }


def empty_pe_analysis(error: Optional[str] = None) -> Dict[str, Any]:
    return {
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
        "import_obfuscation": {
            "import_count": 0,
            "dynamic_resolution_apis": [],
            "has_loadlibrary": False,
            "has_getprocaddress": False,
            "evidence": [],
        },
        "packer_section_names": [],
        "error": error,
    }


def analyze_pe_file(file_path: str) -> Dict[str, Any]:
    results = empty_pe_analysis()

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
        results["import_obfuscation"] = summarize_import_obfuscation(imports)
        entry_point_va = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        results["capstone"] = disassemble_executable_sections(pe, entry_point_va=entry_point_va)

    except pefile.PEFormatError:
        results["error"] = "Not a valid PE file"
    except Exception as exc:
        results["error"] = str(exc)

    return results


def build_feature_vector(
    file_path: str,
    analysis_type: str,
    pe_analysis: Dict[str, Any],
    xor_analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a flat feature vector for the active five-technique PE baseline."""
    sections = pe_analysis.get("sections", [])
    executable_sections = [s for s in sections if "EXECUTE" in s.get("characteristics", [])]
    writable_executable_sections = [
        s for s in sections
        if "EXECUTE" in s.get("characteristics", []) and "WRITE" in s.get("characteristics", [])
    ]
    entropies = [s.get("entropy", 0.0) for s in sections]

    cap = pe_analysis.get("capstone", {}).get("summary", {})
    import_obf = pe_analysis.get("import_obfuscation", {})

    features = {
        "file_size": os.path.getsize(file_path),
        "analysis_type_pe": int(analysis_type == "pe"),
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
        "xor_printable_string_count": sum(hit.get("printable_string_count", 0) for hit in xor_analysis.get("hits", [])),
        "xor_printable_character_count": sum(hit.get("printable_character_count", 0) for hit in xor_analysis.get("hits", [])),
        "stack_string_xor_count": len(xor_analysis.get("stack_string_xor_hits", [])),
        "memory_xor_immediate_count": cap.get("memory_xor_immediate_count", 0),
        "instruction_count": cap.get("instruction_count", 0),
        "basic_opaque_predicate_count": cap.get("basic_opaque_predicate_count", 0),
        "cfg_block_count": cap.get("cfg_block_count", 0),
        "cfg_sink_vertex_count": cap.get("cfg_sink_vertex_count", 0),
        "cfg_sink_vertex_ratio": cap.get("cfg_sink_vertex_ratio", 0.0),
        "dynamic_resolution_api_count": len(import_obf.get("dynamic_resolution_apis", [])),
        "has_loadlibrary_import": int(bool(import_obf.get("has_loadlibrary"))),
        "has_getprocaddress_import": int(bool(import_obf.get("has_getprocaddress"))),
        "rotate_count": cap.get("rotate_count", 0),
        "rotate_ratio": cap.get("rotate_ratio", 0.0),
        "segment_peb_access_count": cap.get("segment_peb_access_count", 0),
        "segment_peb_access_ratio": cap.get("segment_peb_access_ratio", 0.0),
    }

    return {k: round(v, 6) if isinstance(v, float) else v for k, v in features.items()}


def score_pe_obfuscation(
    pe_analysis: Dict[str, Any],
    xor_analysis: Dict[str, Any],
    features: Dict[str, Any],
) -> Dict[str, Any]:
    """Rule-based scoring limited to the Windows malware techniques in ideas3.md."""
    score = 0
    details: List[Dict[str, Any]] = []
    techniques = set()
    cap_summary = pe_analysis.get("capstone", {}).get("summary", {})
    import_obf = pe_analysis.get("import_obfuscation", {})

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

    if features["packer_section_name_count"] > 0:
        add(
            20,
            "Packer-like section name",
            pe_analysis.get("packer_section_names", []),
            "HIGH",
            "Known packer section names were found.",
            "PE Packing",
            evidence=[{"section": name, "reason": "matches known packer section naming"} for name in pe_analysis.get("packer_section_names", [])[:10]],
        )

    if features["total_entropy"] > 7.2 or features["high_entropy_section_count"] > 0:
        add(
            18 if features["high_entropy_section_count"] > 0 else 12,
            "High entropy consistent with packing",
            {
                "total_entropy": features["total_entropy"],
                "high_entropy_sections": features["high_entropy_section_count"],
            },
            "HIGH" if features["high_entropy_section_count"] > 0 else "MEDIUM",
            "Overall or section-level entropy is high enough to be consistent with a common packer or compressed payload.",
            "PE Packing",
            evidence=pe_analysis.get("high_entropy_sections", [])[:10],
        )

    if features["writable_executable_section_count"] > 0:
        add(
            12,
            "Writable and executable section",
            features["writable_executable_section_count"],
            "MEDIUM",
            "At least one PE section is both writable and executable, a common unpacking-stub or self-modifying-code artifact.",
            "PE Packing",
            evidence=[
                section for section in pe_analysis.get("sections", [])
                if "WRITE" in section.get("characteristics", []) and "EXECUTE" in section.get("characteristics", [])
            ][:10],
        )

    if (
        features["dynamic_resolution_api_count"] > 0
        and (
            features["has_getprocaddress_import"]
            or features["has_loadlibrary_import"]
            or features["import_count"] <= 10
        )
    ):
        add(
            18 if features["import_count"] <= 10 else 12,
            "Dynamic API resolution imports",
            {
                "imports": features["import_count"],
                "apis": import_obf.get("dynamic_resolution_apis", []),
            },
            "HIGH" if features["import_count"] <= 10 else "MEDIUM",
            "The import table contains loader/resolver APIs such as LoadLibrary or GetProcAddress, which matches runtime API resolution in the script.",
            "Import Obfuscation",
            evidence=import_obf.get("evidence", [])[:12],
        )

    if features["basic_opaque_predicate_count"] > 0:
        add(
            18,
            "Basic opaque predicate pattern",
            features["basic_opaque_predicate_count"],
            "MEDIUM",
            "Capstone recovered compare/test-same-operand or zeroing-idiom patterns immediately followed by conditional jumps.",
            "Dead Code Insertion",
            evidence=cap_summary.get("evidence", {}).get("basic_opaque_predicate_samples", [])[:10],
        )

    if features["cfg_sink_vertex_count"] > 0:
        add(
            16 if features["cfg_sink_vertex_ratio"] >= 0.05 else 10,
            "Sink / dead-end basic blocks",
            {
                "sink_vertices": features["cfg_sink_vertex_count"],
                "sink_ratio": features["cfg_sink_vertex_ratio"],
            },
            "MEDIUM",
            "Recovered CFG contains basic blocks that end without a normal exit edge, which is consistent with junk blocks or decode dead-ends.",
            "Dead Code Insertion",
            evidence=cap_summary.get("evidence", {}).get("sink_vertex_samples", [])[:10],
        )

    if features["xor_key_count"] > 0 or features["stack_string_xor_count"] > 0:
        add(
            20,
            "Possible XOR-encoded strings",
            {
                "single_byte_keys": xor_analysis.get("xor_keys", [])[:10],
                "stack_string_xor_hits": features["stack_string_xor_count"],
                "memory_xor_immediate_instructions": features["memory_xor_immediate_count"],
            },
            "MEDIUM",
            "Readable strings appeared after single-byte XOR decoding, stack-built bytes were XOR-decoded in place, or code used memory XOR with an immediate key.",
            "String Encryption (XOR)",
            evidence=(
                xor_analysis.get("hits", [])[:8]
                + xor_analysis.get("stack_string_xor_hits", [])[:8]
                + cap_summary.get("evidence", {}).get("memory_xor_immediate_samples", [])[:8]
            )[:12],
        )

    if (
        features["rotate_count"] >= 2
        and features["import_count"] <= 15
        and not features["has_getprocaddress_import"]
    ) or (
        features["rotate_count"] >= 2
        and features["segment_peb_access_count"] > 0
    ):
        add(
            18,
            "API hashing style arithmetic",
            {
                "rotate_instructions": features["rotate_count"],
                "segment_peb_access": features["segment_peb_access_count"],
                "imports": features["import_count"],
                "getprocaddress_imported": bool(features["has_getprocaddress_import"]),
            },
            "MEDIUM",
            "Rotate-heavy code with a small import table and no visible GetProcAddress import is consistent with API-name hashing or export-table walking.",
            "API Hashing",
            evidence=(
                cap_summary.get("evidence", {}).get("rotate_samples", [])[:6]
                + cap_summary.get("evidence", {}).get("segment_peb_access_samples", [])[:6]
            )[:12],
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


def score_obfuscation(
    analysis_type: str,
    pe_analysis: Dict[str, Any],
    xor_analysis: Dict[str, Any],
    features: Dict[str, Any],
) -> Dict[str, Any]:
    return score_pe_obfuscation(pe_analysis, xor_analysis, features)


def analyze_binary(file_path: str) -> Dict[str, Any]:
    file_path_obj = Path(file_path)
    analysis_type = detect_binary_format(file_path)
    pe_analysis = analyze_pe_file(file_path)
    xor_analysis = detect_xor_strings(file_path, pe_analysis=pe_analysis)
    features = build_feature_vector(
        file_path,
        analysis_type,
        pe_analysis,
        xor_analysis,
    )
    obfuscation = score_obfuscation(
        analysis_type,
        pe_analysis,
        xor_analysis,
        features,
    )

    return {
        "filename": file_path_obj.name,
        "file_size": os.path.getsize(file_path),
        "analysis_type": analysis_type,
        "pe_analysis": pe_analysis,
        "xor_analysis": xor_analysis,
        "features": features,
        "obfuscation": obfuscation,
    }
