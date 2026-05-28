from __future__ import annotations

from collections import Counter
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


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

IOC_LIMIT = 24
URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
DOMAIN_REGEX = re.compile(r"\b[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\.(?:[a-z]{2,})(?:\.[a-z]{2,})?\b", re.IGNORECASE)
REGISTRY_REGEX = re.compile(r"\bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s\"']+", re.IGNORECASE)


def printable_ascii_ratio(data: bytes) -> float:
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
    if len(value) < MIN_XOR_PRINTABLE_LENGTH:
        return False
    if not any((65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) for b in value):
        return False
    counts = Counter(value)
    if len(counts) < 4:
        return False
    most_common_ratio = counts.most_common(1)[0][1] / len(value)
    return most_common_ratio <= 0.65 and printable_text_score(value) >= 0.55


def trim_printable_run(offset: int, value: bytes) -> tuple[int, bytes]:
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


def normalize_section_name(name: str) -> str:
    return (name or "").strip().lower().split("$", 1)[0]


def get_xor_section_priority(section: Dict[str, Any]) -> Optional[int]:
    if "EXECUTE" in section.get("flags", []):
        return None

    name = normalize_section_name(section.get("name", ""))
    if name in XOR_NOISY_SECTION_NAMES:
        return None
    if name in XOR_PRIMARY_SECTION_PRIORITIES:
        return XOR_PRIMARY_SECTION_PRIORITIES[name]
    if "WRITE" in section.get("flags", []):
        return 10
    if "READ" in section.get("flags", []):
        return 20
    return 30


def get_xor_scan_regions(file_path: str, sections: List[Dict[str, Any]], sample_size: int) -> List[Dict[str, Any]]:
    regions: List[Dict[str, Any]] = []
    data = Path(file_path).read_bytes()

    candidates = []
    for section in sections:
        priority = get_xor_section_priority(section)
        if priority is None:
            continue
        offset = int(section.get("raw_offset", 0))
        size = int(section.get("raw_size", 0))
        if size < MIN_XOR_PRINTABLE_LENGTH:
            continue
        candidates.append((priority, offset, section.get("name", "section"), size))

    remaining = sample_size
    for _, offset, name, size in sorted(candidates, key=lambda item: (item[0], item[1])):
        if remaining <= 0:
            break
        region_size = min(size, remaining, MAX_XOR_BYTES_PER_REGION)
        regions.append({
            "name": name,
            "offset": offset,
            "data": data[offset:offset + region_size],
        })
        remaining -= region_size

    if regions:
        return regions

    return [{"name": "file", "offset": 0, "data": data[:sample_size]}]


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
    sections: List[Dict[str, Any]],
    memory_xor_samples: Optional[List[Dict[str, Any]]] = None,
    sample_size: int = 2 * 1024 * 1024,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "xor_keys": [],
        "hits": [],
        "tested_bytes": 0,
        "scan_regions": [],
        "iocs": [],
        "meaningful_example_count": 0,
    }

    regions = get_xor_scan_regions(file_path, sections, sample_size)
    result["scan_regions"] = [
        {"name": region["name"], "offset": hex(region["offset"]), "size": len(region["data"])}
        for region in regions
    ]
    result["tested_bytes"] = sum(len(region["data"]) for region in regions)

    hinted_keys = set()
    if memory_xor_samples:
        for sample in memory_xor_samples:
            key = sample.get("key_value")
            if isinstance(key, int) and 1 <= key <= 255:
                hinted_keys.add(key)

    key_hits = []
    meaningful_total = 0
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
            "meaningful_examples": sum(
                1
                for item in runs
                if item.get("text_score", 0.0) >= 0.72 and item.get("length", 0) >= 12
            ),
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
    meaningful_total = sum(item.get("meaningful_examples", 0) for item in result["hits"])
    result["meaningful_example_count"] = meaningful_total

    iocs: List[str] = []
    seen = set()
    for hit in result["hits"]:
        for example in hit.get("examples", []):
            decoded = example.get("decoded", "")
            if not decoded:
                continue
            for regex in (URL_REGEX, IP_REGEX, REGISTRY_REGEX):
                for match in regex.findall(decoded):
                    if match not in seen:
                        seen.add(match)
                        iocs.append(match)
            for match in DOMAIN_REGEX.findall(decoded):
                if match not in seen and not any(match in url for url in seen):
                    seen.add(match)
                    iocs.append(match)
            if len(iocs) >= IOC_LIMIT:
                break
        if len(iocs) >= IOC_LIMIT:
            break
    result["iocs"] = iocs[:IOC_LIMIT]

    return result
