# ObfusHunter - Project Overview

This document describes the project structure, how the tool works, how to run it, and the detailed analysis logic. It is intended for slide preparation and team sharing.

## 1. Project Scope

The tool focuses only on Windows malware that uses five static obfuscation techniques:

1. String Encryption (XOR)
2. Import Obfuscation (dynamic API resolution)
3. PE Packing
4. Dead Code Insertion
5. API Hashing

The analyzer is static only. It does not execute samples and does not handle .NET/MSIL assemblies.

## 2. Application Structure

Root layout (key folders only):

- analysis/
    - engine.py: analysis pipeline and report builder
    - pe.py: PE parsing, sections, imports, entropy
    - disasm.py: Capstone disassembly summary
    - techniques/
        - pe_packing.py
        - string_xor.py
        - import_obfuscation.py
        - dead_code.py
        - api_hashing.py
- web/
    - routes.py: Flask endpoints
- templates/
    - index.html: web UI
- static/
    - css/app.css
    - js/app.js
- storage/
    - report_store.py: save/load JSON reports
- utils/
    - files.py: file validation helpers
- app.py: Flask app entry
- config.py: global config (paths, limits)
- run.sh / run.bat: start scripts

## 3. How the Tool Works (High-Level)

1. User uploads a PE sample via web UI.
2. Flask saves it to data/uploads/ and calls analysis/engine.py::analyze_file().
3. The engine runs a PE parse, disassembly summary, and five technique checks.
4. Results are merged into a report JSON with score, indicators, and evidence.
5. The report is returned to the UI and stored under data/reports/.

## 4. How to Run

Linux/macOS:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
./run.sh
```

Windows:

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
run.bat
```

Open http://localhost:5000

## 5. Analysis Pipeline (Detailed)

### 5.1 Entry Point: analysis/engine.py

- analyze_file(file_path):
    - Computes SHA-256 and file size.
    - Calls analyze_pe() to parse PE headers and sections.
    - If not PE or .NET/MSIL, returns early with a status.
    - Calls summarize_disassembly() for instruction-based signals.
    - Runs each technique module and produces a score per technique.
    - Applies gating rules (e.g., packed files reduce XOR/dead-code noise).
    - Builds indicators list for UI.
    - Returns a normalized score (0-100) and full evidence payload.

### 5.2 PE Parsing: analysis/pe.py

- analyze_pe(file_path) reads PE metadata:
    - Architecture, entry point, image base.
    - Section list with entropy, raw size, flags (R/W/X).
    - Import table (normal and delay import).
    - Marks .NET/MSIL as unsupported.

- summarize_import_obfuscation():
    - Extracts dynamic-resolution APIs such as LoadLibrary/GetProcAddress.

### 5.3 Disassembly Summary: analysis/disasm.py

- Uses Capstone on executable sections only.
- Produces a compact summary:
    - rotate_count (API hashing signals)
    - memory_xor_immediate_count (XOR string decode)
    - stack_string_xor_count (stack string decode)
    - basic_opaque_predicate_count (dead code)
    - cfg_sink_vertex_count and ratio (dead code)
- Stores evidence samples for UI.

## 6. Logic of Each Technique (Important)

### 6.1 String Encryption (XOR) - analysis/techniques/string_xor.py

- Scans .data/.rdata (and other non-executable sections) for XOR-decoded strings.
- Tests all single-byte XOR keys (1..255).
- Scores decoded runs by "text_score" to filter noise.
- Extracts IOC-like strings (URL, IP, domain, registry path).
- Returns:
    - xor_keys: list of likely keys
    - hits: examples with offsets and decoded text
    - meaningful_example_count: number of strong candidates
    - iocs: extracted IOC strings

### 6.2 Import Obfuscation - analysis/techniques/import_obfuscation.py

- Checks for dynamic API resolution patterns:
    - LoadLibraryA/W/Ex
    - GetProcAddress
    - LdrLoadDll / LdrGetProcedureAddress
- Applies gating by import_count:
    - Small import table -> stronger signal.
    - Large import table -> weaker or no score.
- Returns evidence of resolver imports.

### 6.3 PE Packing - analysis/techniques/pe_packing.py

- Detects packing via:
    - High entropy sections (> 7.2)
    - Known packer section names (UPX, etc.)
    - Writable + executable sections
- High confidence when multiple indicators exist.

### 6.4 Dead Code Insertion - analysis/techniques/dead_code.py

- Uses disassembly summary:
    - Opaque predicate count + density (ratio).
    - Sink blocks in CFG + ratio.
- Only scores when counts and ratios exceed thresholds to reduce compiler noise.

### 6.5 API Hashing - analysis/techniques/api_hashing.py

- Looks for:
    - Rotate instruction frequency (ROR/ROL)
    - PEB/TEB access (fs:/gs:)
    - Small import table without GetProcAddress
- Signals hash-based API resolution.

## 7. Scoring and Gating Rules

- Each technique returns score in 0..30.
- Total score is normalized to 0..100.
- Packed files trigger gating:
    - XOR and dead-code scores are reduced if packed stub is too small or noisy.

## 8. Report Output

The report JSON includes:

- file: name, size, sha256
- pe: PE metadata and section details
- disassembly: summary + evidence
- techniques: per-technique scores and evidence
- indicators: summarized reasons for UI display
- summary: overall score and status label

## 9. UI Behavior

- Web UI displays:
    - Overall score and status
    - Technique badges
    - Indicators with evidence (expandable)
    - Section table
    - Raw JSON report

## 10. Notes for Slides

Recommended slide outline:

1. Project goals and scope
2. Five techniques and why they matter
3. Architecture overview (diagram)
4. Analysis pipeline
5. Per-technique heuristics
6. Demo: packed vs. unpacked sample
7. Limitations and future work

If you want, I can add a Mermaid diagram or a condensed slide-ready version.
