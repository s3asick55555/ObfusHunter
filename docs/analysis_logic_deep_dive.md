# ObfusHunter - Analysis Deep Dive

This document explains the analysis logic in depth. It focuses on how signals are extracted, how evidence is built, and how scores are computed for each technique.

## 1. Execution Flow (Detailed)

1. Web route `/api/analyze` saves the uploaded sample to disk.
2. analysis/engine.py::analyze_file() orchestrates the pipeline:
    - Parse PE headers and sections (analysis/pe.py)
    - Summarize disassembly signals (analysis/disasm.py)
    - Run each technique module in analysis/techniques/
    - Apply gating rules for packed samples
    - Build indicators list for UI
    - Normalize total score to 0..100

The report JSON includes:

- file metadata (name, size, sha256)
- pe metadata (sections, imports)
- disassembly summary and evidence
- technique results and indicators
- summary status and score

## 2. PE Parsing (analysis/pe.py)

### 2.1 PE validity and metadata

- Uses pefile.PE() to parse headers.
- Extracts architecture, entry point, image base.
- Detects .NET/MSIL (CLR directory present) and exits early.

### 2.2 Sections

For each section:

- entropy (Shannon) from raw bytes
- printable ASCII ratio
- zero-byte ratio
- flags: READ, WRITE, EXECUTE
- raw size and raw offset

These fields are used by PE Packing and XOR scanning.

### 2.3 Import Table

- Normal imports (DIRECTORY_ENTRY_IMPORT)
- Delay imports (DIRECTORY_ENTRY_DELAY_IMPORT)

This is important because some samples resolve APIs via delay-load. Both tables feed into Import Obfuscation logic.

## 3. Disassembly Summary (analysis/disasm.py)

This module extracts a lightweight summary rather than full CFG recovery.

### 3.1 Capstone setup

- Only x86 and x64 are supported.
- Only executable sections are disassembled.
- Disassembly is capped by max bytes per section for performance.

### 3.2 Signals collected

- rotate_count (ROL/ROR): used for API Hashing
- memory_xor_immediate_count: used for String XOR
- stack_string_xor_count: used for String XOR
- basic_opaque_predicate_count: used for Dead Code
- cfg_sink_vertex_count and ratio: used for Dead Code
- segment_peb_access_count: used for API Hashing

### 3.3 Evidence samples

For each signal, sample instructions are recorded and returned in the report:

- rotate_samples
- memory_xor_immediate_samples
- stack_string_xor_samples
- basic_opaque_predicate_samples
- sink_vertex_samples
- segment_peb_access_samples

These are shown in the UI under Evidence.

## 4. Technique Logic (Per-Module)

### 4.1 PE Packing (analysis/techniques/pe_packing.py)

Evidence rules:

- High entropy section: entropy > 7.2 and raw_size > 512 bytes
- Known packer section name: UPX0/UPX1/etc
- W+X section: section has both WRITE and EXECUTE

Score:

- +20 for packer section name
- +18 for high entropy sections
- +12 for W+X sections
- score capped at 30

### 4.2 String Encryption (XOR) (analysis/techniques/string_xor.py)

#### 4.2.1 Scan regions

- Prioritize .data, .rdata, .sdata
- Skip executable sections and noisy sections (.rsrc, .reloc, etc.)

#### 4.2.2 XOR brute force

- Try all single-byte XOR keys (1..255)
- For each key, decode region bytes and look for printable runs

#### 4.2.3 Text scoring

A decoded string is considered "interesting" if:

- Length >= 8 bytes
- Contains letters or digits
- Not too repetitive
- Text score >= 0.55

A "meaningful example" additionally requires:

- text_score >= 0.72
- length >= 12

#### 4.2.4 IOC extraction

From decoded strings, extract:

- URLs
- IP addresses
- domains
- registry paths

#### 4.2.5 XOR score

- +10 if xor_keys detected
- +6 more if best_text_score >= 0.8
- +5 if memory XOR immediate ops in disassembly
- +7 if stack XOR decode detected
- score capped at 30

### 4.3 Import Obfuscation (analysis/techniques/import_obfuscation.py)

Signals:

- presence of LoadLibrary and GetProcAddress (or LdrLoadDll / LdrGetProcedureAddress)
- import_count thresholds

Gating by import table size:

- <= 10 imports: strong signal
- 11..15 imports: medium signal
- 16..25 imports: weak signal
- > = 30 imports: no signal

Score:

- +18 (<=10 imports)
- +12 (<=15 imports)
- +8 (<=25 imports)
- score capped at 30

### 4.4 Dead Code Insertion (analysis/techniques/dead_code.py)

Signals:

- opaque predicate patterns
- sink blocks in CFG

Thresholds:

- opaque predicates:
    - > = 8 and ratio >= 0.006 => +18
    - or >= 30 and ratio >= 0.003 => +12
- sink blocks:
    - cfg_block_count >= 20 and sink_ratio >= 0.08 => +12
    - or cfg_block_count >= 50 and sink_ratio >= 0.05 => +8

Score capped at 30.

### 4.5 API Hashing (analysis/techniques/api_hashing.py)

Signals:

- rotate_count >= 2
- small import table without GetProcAddress
- PEB/TEB access (fs:/gs:)

Score:

- +18 for rotate_count >= 2 and import_count <= 15 and no GetProcAddress
- +10 if rotate_count >= 2 and PEB/TEB access present
- score capped at 30

## 5. Gating for Packed Files

If strong packing is detected (packer section names or high entropy + total entropy >= 7.2):

- XOR score reduced or zeroed if no meaningful evidence
- Dead code scoring disabled when disassembly stub is too small

This avoids false positives caused by compressed payloads.

## 6. Score Normalization and Status

- Each technique contributes 0..30 points.
- Total is normalized to 0..100 with a linear scale.
- Status is derived from total score:
    - 70+ => HIGHLY OBFUSCATED
    - 45..69 => OBFUSCATED
    - 1..44 => POSSIBLY OBFUSCATED
    - 0 => NO STRONG OBFUSCATION INDICATORS

## 7. Practical Notes

- High entropy by itself does not guarantee packing; it is a strong heuristic.
- Import obfuscation can be used in legitimate software; import_count gating reduces noise.
- XOR decoding is noisy; IOC extraction provides stronger evidence.
- Opaque predicate detection is heuristic; ratios help reduce compiler noise.

If you want a Mermaid diagram of this pipeline or a slide-ready summary, I can prepare that next.
