from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pefile

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
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(data)


def zero_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return data.count(0) / len(data)


def safe_decode(value: bytes) -> str:
    return value.decode(errors="ignore").strip("\x00").strip()


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


def is_dotnet_pe(pe: pefile.PE) -> bool:
    try:
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return bool(clr_dir.VirtualAddress and clr_dir.Size)
    except Exception:
        return False


def section_is_executable(section: pefile.SectionStructure) -> bool:
    return bool(section.Characteristics & 0x20000000)


def section_is_writable(section: pefile.SectionStructure) -> bool:
    return bool(section.Characteristics & 0x80000000)


def section_is_readable(section: pefile.SectionStructure) -> bool:
    return bool(section.Characteristics & 0x40000000)


def extract_imports(pe: pefile.PE) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    imports: List[Dict[str, str]] = []
    suspicious: List[Dict[str, str]] = []

    suspicious_names = {name.lower() for name in SUSPICIOUS_APIS}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore") if entry.dll else "[unknown]"
            for imp in entry.imports:
                api_name = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                row = {"dll": dll_name, "api": api_name}
                imports.append(row)
                if api_name.lower() in suspicious_names:
                    suspicious.append(row)

    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore") if entry.dll else "[delay]"
            for imp in entry.imports:
                api_name = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                row = {"dll": dll_name, "api": api_name, "kind": "delay"}
                imports.append(row)
                if api_name.lower() in suspicious_names:
                    suspicious.append(row)

    return imports, suspicious


def summarize_import_obfuscation(imports: List[Dict[str, str]]) -> Dict[str, Any]:
    import_names = {str(row.get("api", "")).lower() for row in imports}
    dynamic_apis = sorted(api for api in import_names if api in DYNAMIC_RESOLUTION_APIS)
    return {
        "import_count": len(imports),
        "dynamic_resolution_apis": dynamic_apis,
        "has_loadlibrary": any(api.startswith("loadlibrary") or api == "ldrloaddll" for api in dynamic_apis),
        "has_getprocaddress": any(api in {"getprocaddress", "ldrgetprocedureaddress"} for api in dynamic_apis),
        "evidence": [row for row in imports if str(row.get("api", "")).lower() in DYNAMIC_RESOLUTION_APIS][:12],
    }


def analyze_pe(file_path: str) -> Tuple[Optional[pefile.PE], Dict[str, Any]]:
    result: Dict[str, Any] = {
        "valid": False,
        "supported": True,
        "architecture": None,
        "entry_point": None,
        "image_base": None,
        "is_dotnet": False,
        "sections": [],
        "total_entropy": 0.0,
        "imports": [],
        "suspicious_imports": [],
        "import_obfuscation": {
            "import_count": 0,
            "dynamic_resolution_apis": [],
            "has_loadlibrary": False,
            "has_getprocaddress": False,
            "evidence": [],
        },
        "error": None,
    }

    try:
        pe = pefile.PE(file_path, fast_load=False)
        result["valid"] = True
        result["architecture"] = classify_architecture(pe.FILE_HEADER.Machine)
        result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        result["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)

        if is_dotnet_pe(pe):
            result["is_dotnet"] = True
            result["supported"] = False
            result["error"] = ".NET / MSIL PE detected. This analyzer targets native PE only."
            return pe, result

        file_data = Path(file_path).read_bytes()
        result["total_entropy"] = round(calculate_entropy(file_data), 4)

        for section in pe.sections:
            name = safe_decode(section.Name)
            data = section.get_data()
            flags = []
            if section_is_executable(section):
                flags.append("EXECUTE")
            if section_is_readable(section):
                flags.append("READ")
            if section_is_writable(section):
                flags.append("WRITE")

            result["sections"].append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "raw_offset": int(section.PointerToRawData),
                "entropy": round(calculate_entropy(data), 4),
                "printable_ascii_ratio": round(printable_ascii_ratio(data), 4),
                "zero_ratio": round(zero_ratio(data), 4),
                "flags": flags,
            })

        imports, suspicious = extract_imports(pe)
        result["imports"] = imports
        result["suspicious_imports"] = suspicious
        result["import_obfuscation"] = summarize_import_obfuscation(imports)

        return pe, result
    except pefile.PEFormatError:
        result["error"] = "Not a valid PE file"
    except Exception as exc:
        result["error"] = str(exc)

    return None, result
