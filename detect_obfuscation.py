import math
import sys
import os

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_file(file_path):
    print(f"--- Analyzing: {os.path.basename(file_path)} ---")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            
        # 1. Check Overall Entropy
        total_entropy = calculate_entropy(data)
        print(f"Total Entropy: {total_entropy:.4f}")
        if total_entropy > 7.0:
            print("[!] ALERT: Very high overall entropy. Likely packed or encrypted.")
        elif total_entropy > 6.0:
            print("[?] WARNING: High entropy detected.")

        # 2. Basic PE Header Check (Static Signature)
        if data.startswith(b'MZ'):
            print("Format: Windows PE Executable")
            # Simple check for common obfuscated section names (if readable)
            suspicious_sections = [b'UPX0', b'UPX1', b'aspack', b'pdata']
            for section in suspicious_sections:
                if section in data:
                    print(f"[!] ALERT: Found signature of common packer/obfuscator: {section.decode()}")

    except Exception as e:
        print(f"Error reading file: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detect_obfuscation.py <file_path>")
    else:
        analyze_file(sys.argv[1])
