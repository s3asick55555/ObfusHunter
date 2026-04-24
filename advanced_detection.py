import math
import sys
import os
import re
import pefile

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    for count in byte_counts:
        if count > 0:
            p_x = float(count) / len(data)
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def detect_base64(data):
    # Search for Base64-like strings (length >= 16)
    pattern = re.compile(rb'[A-Za-z0-9+/]{16,}(?:==|=)?')
    matches = pattern.findall(data)
    results = []
    for m in matches:
        if len(m) % 4 == 0:
            results.append(m)
    return results

def detect_padding(data):
    # Detect large blocks of null bytes or same byte (e.g., > 10KB)
    threshold = 10 * 1024
    null_padding = b'\x00' * threshold
    if null_padding in data:
        return True
    return False

def analyze_pe(file_path):
    print(f"--- Advanced Obfuscation Analysis: {os.path.basename(file_path)} ---")
    try:
        pe = pefile.PE(file_path)
        
        # 1. Section Entropy
        print("\n[Section Entropy]")
        for section in pe.sections:
            name = section.Name.decode().strip('\x00')
            entropy = calculate_entropy(section.get_data())
            print(f"  {name:8}: {entropy:.4f}")
            if entropy > 7.2:
                print(f"    [!] High entropy in {name} - likely encrypted/packed.")
        
        # 2. Import Analysis
        print("\n[Import Analysis]")
        import_count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                import_count += len(entry.imports)
            print(f"  Total Imports: {import_count}")
            if import_count < 10:
                print("    [!] Very few imports - typical for packed files.")
        else:
            print("    [!] No imports found - highly suspicious!")

        # 3. Base64 Detection
        with open(file_path, "rb") as f:
            raw_data = f.read()
        
        b64_matches = detect_base64(raw_data)
        if b64_matches:
            print(f"\n[Base64 Strings] Found {len(b64_matches)} potential Base64 strings.")
            for b in b64_matches[:5]: # Show first 5
                print(f"  {b[:50].decode(errors='ignore')}...")

        # 4. Padding Detection
        if detect_padding(raw_data):
            print("\n[Binary Padding]")
            print("  [!] Significant null padding detected. May be avoiding scanners.")

    except pefile.PEFormatError:
        print("Not a valid PE file.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 advanced_detection.py <file_path>")
    else:
        analyze_pe(sys.argv[1])
