import sys
from collections import Counter
import math

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    entropy = 0
    byte_counts = Counter(data)
    for count in byte_counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def count_printable_strings(data, min_length=4):
    """Count printable strings in data (Didier Stevens approach)"""
    strings = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(bytes(current))
            current = []
    if len(current) >= min_length:
        strings.append(bytes(current))
    return strings

def analyze_string_quality(data, sample_size=1024):
    """Analyze quality of strings in decoded data"""
    sample = data[:sample_size]
    strings = count_printable_strings(sample)
    
    if not strings:
        return 0, 0, 0
    
    total_chars = sum(len(s) for s in strings)
    avg_length = total_chars / len(strings) if strings else 0
    printable_ratio = total_chars / len(sample) if sample else 0
    
    return len(strings), avg_length, printable_ratio

def detect_repeated_bytes(data, window_size=256):
    """Find frequently repeated byte patterns (potential XOR keys)"""
    results = {}
    for key_len in [1, 2, 3, 4, 8]:
        patterns = Counter()
        for i in range(0, min(len(data), window_size), key_len):
            pattern = tuple(data[i:i+key_len])
            if len(pattern) == key_len:
                patterns[pattern] += 1
        
        # Get top patterns
        common = patterns.most_common(5)
        if common and common[0][1] >= 3:  # Pattern appears at least 3 times
            results[key_len] = common
    
    return results

def detect_suspicious_apis(data):
    """Detect suspicious Windows API calls and functions"""
    suspicious_apis = [
        b"VirtualAlloc", b"VirtualAllocEx", b"VirtualProtect", b"VirtualProtectEx",
        b"WriteProcessMemory", b"CreateRemoteThread", b"QueueUserAPC",
        b"SetWindowsHookEx", b"CreateProcess", b"ShellExecute",
        b"WinExec", b"LoadLibraryA", b"LoadLibraryW", b"GetProcAddress",
        b"GetModuleHandle", b"InjectionThread", b"CreateToolhelp32Snapshot"
    ]
    
    found = []
    for api in suspicious_apis:
        indices = []
        start = 0
        while True:
            idx = data.find(api, start)
            if idx == -1:
                break
            indices.append(idx)
            start = idx + 1
        
        if indices:
            found.append((api.decode(errors='ignore'), indices))
    
    return found

def detect_xor_loops(data, window_size=256):
    """Detect patterns consistent with XOR loop instructions"""
    # Look for common x86 XOR loop patterns:
    # - XOR instruction bytes: 0x31 (xor r/m32, r32), 0x34 (xor al, imm8), 0x35 (xor eax, imm32)
    # - Loop instruction: 0xE2 (loop)
    # - Jump instructions: 0x74-0x75 (jz/jnz), 0xEB (jmp)
    xor_opcodes = [0x31, 0x34, 0x35]
    loop_opcodes = [0xE2, 0xEB, 0x74, 0x75, 0x84, 0x85]  # loop, jmp, jz, jnz, test, cmp variants
    
    suspicious_regions = []
    sample = data[:window_size]
    
    for i in range(len(sample) - 2):
        if sample[i] in xor_opcodes:
            # Check if there's a loop/jump nearby
            found_loop = False
            for offset in range(1, min(10, len(sample) - i)):
                if sample[i + offset] in loop_opcodes:
                    found_loop = True
                    break
            
            if found_loop:
                region = sample[max(0, i-4):min(len(sample), i+8)]
                suspicious_regions.append((i, region.hex()))
    
    return suspicious_regions

def detect_xor(file_path):
    # Comprehensive target list (Known Plaintexts)
    targets = [
        b"http://", b"https://", b"GET ", b"POST ", b"Mozilla", 
        b"kernel32.dll", b"advapi32.dll", b"user32.dll",
        b"LoadLibrary", b"GetProcAddress", b"GetModuleHandle",
        b"CreateProcess", b"ShellExecute", b"VirtualAlloc", b"WriteProcessMemory",
        b"cmd.exe", b"powershell.exe", b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        b"This program cannot be run in DOS mode"
    ]

    print(f"--- Enhanced XOR Malware Detection: {file_path} ---\n")
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # === PHASE 1: QUICK INDICATORS ===
        print("[PHASE 1: Quick Malware Indicators]")
        
        # Check for suspicious APIs in plaintext
        suspicious = detect_suspicious_apis(data)
        if suspicious:
            print("[!] SUSPICIOUS API CALLS FOUND (plaintext):")
            for api, offsets in suspicious:
                print(f"    - {api} at offsets: {[hex(o) for o in offsets[:3]]}")
        
        # Check for XOR-like loop patterns
        xor_loops = detect_xor_loops(data)
        if xor_loops:
            print(f"[!] POTENTIAL XOR LOOPS DETECTED: {len(xor_loops)} occurrences")
            for offset, hex_pattern in xor_loops[:3]:
                print(f"    - Offset {hex(offset)}: {hex_pattern}")
        
        # Check for repeated byte patterns (potential keys)
        print("\n[Repeated Byte Pattern Analysis (Potential XOR Keys)]")
        repeated = detect_repeated_bytes(data)
        if repeated:
            for key_len, patterns in sorted(repeated.items()):
                for pattern, count in patterns[:2]:
                    key_str = bytes(pattern).hex()
                    print(f"[!] Key pattern (len {key_len}): 0x{key_str} - appears {count} times")
        
        # === PHASE 2: SINGLE-BYTE BRUTE FORCE ===
        print("\n[PHASE 2: Single-Byte XOR Brute Force]")
        chunk = data[:8192]
        good_keys = []
        
        for key in range(1, 256):
            decoded = bytes([b ^ key for b in chunk])
            strings, avg_len, printable_ratio = analyze_string_quality(decoded)
            
            # If we find known plaintext or good string quality, this is a candidate
            found = False
            for t in targets:
                if t in decoded:
                    good_keys.append((key, "known_plaintext", t.decode(errors='ignore')))
                    found = True
                    break
            
            # Also check for suspiciously good string quality (sign of decryption)
            if not found and strings > 5 and printable_ratio > 0.3:
                good_keys.append((key, "high_string_quality", f"{strings} strings, {printable_ratio:.2%} printable"))
            
            # Check for suspicious APIs after decryption
            if not found:
                apis = detect_suspicious_apis(decoded)
                if apis:
                    good_keys.append((key, "suspicious_api", f"{len(apis)} API calls detected"))
        
        if good_keys:
            print(f"[!] Found {len(good_keys)} suspicious single-byte keys:")
            for key, reason, detail in good_keys[:10]:
                print(f"    Key 0x{key:02x}: {reason} - {detail}")
        else:
            print("[✓] No suspicious single-byte keys found.")

        # === PHASE 3: MULTI-BYTE / REPEATING KEY DETECTION ===
        print("\n[PHASE 3: Multi-Byte XOR Key Detection]")
        multi_matches = []
        
        for t in targets:
            if len(t) < 4:
                continue
            
            for i in range(min(len(data) - len(t), 16384)):
                potential_key_seq = bytes([data[i+j] ^ t[j] for j in range(len(t))])
                
                for key_len in [2, 3, 4, 8]:
                    if len(t) >= key_len * 2:
                        candidate = potential_key_seq[:key_len]
                        
                        is_repeating = True
                        for j in range(len(t)):
                            if potential_key_seq[j] != candidate[j % key_len]:
                                is_repeating = False
                                break
                        
                        if is_repeating and len(set(candidate)) > 1:
                            key_hex = candidate.hex()
                            multi_matches.append((t.decode(errors='ignore'), hex(i), key_hex, key_len))
                            break
                
                if multi_matches:
                    break
        
        if multi_matches:
            print(f"[!] Found {len(multi_matches)} multi-byte XOR patterns:")
            for plaintext, offset, key, key_len in multi_matches[:10]:
                print(f"    Found '{plaintext}' at {offset}")
                print(f"      Key (len {key_len}): 0x{key} (repeating)")
        else:
            print("[✓] No multi-byte XOR patterns found.")
        
        # === PHASE 4: ENTROPY ANALYSIS ===
        print("\n[PHASE 4: Entropy & Encryption Analysis]")
        total_entropy = calculate_entropy(data)
        print(f"Overall entropy: {total_entropy:.4f}")
        if total_entropy > 7.2:
            print("[!] ALERT: Very high entropy - file is likely encrypted or packed")
        elif total_entropy > 6.8:
            print("[?] WARNING: High entropy - possible encryption")
        
        # Check entropy of potential regions
        regions = [
            ("First 4KB", data[:4096]),
            ("Middle 4KB", data[len(data)//2:len(data)//2 + 4096] if len(data) > 4096 else b""),
        ]
        for name, region in regions:
            if region:
                ent = calculate_entropy(region)
                if ent > 7.0:
                    print(f"  [{name}] Entropy: {ent:.4f} - Likely encrypted")

        # === SUMMARY ===
        print("\n[SUMMARY]")
        risk_level = 0
        if good_keys:
            risk_level += 2
        if xor_loops:
            risk_level += 2
        if suspicious:
            risk_level += 1
        if repeated:
            risk_level += 1
        if total_entropy > 7.0:
            risk_level += 1
        
        if risk_level >= 4:
            print("[!!!] HIGH RISK: Strong indicators of malware with XOR encoding")
        elif risk_level >= 2:
            print("[!!] MEDIUM RISK: Multiple indicators of XOR encoding/obfuscation")
        elif risk_level >= 1:
            print("[!] LOW RISK: Possible encryption/obfuscation detected")
        else:
            print("[✓] No significant XOR/encryption indicators found")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 xor_detect.py <file_path>")
    else:
        detect_xor(sys.argv[1])
