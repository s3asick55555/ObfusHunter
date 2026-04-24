
#!/usr/bin/env python3
"""
XORStrings Python Implementation
Detects XOR, ROL, and SHIFT encoded strings in binary files.
Based on Didier Stevens' XORStrings.c tool.
"""

import sys
import os
from dataclasses import dataclass
from typing import List, Optional
from collections import defaultdict
import xortool

# Operation codes
OPR_XOR = 0
OPR_ROL = 1
OPR_SHIFT = 2

OPERATIONS = ["XOR", "ROL", "SHIFT"]


@dataclass
class StringAnalysisResult:
    """Result of analyzing strings in decoded data"""
    operation: int
    key: int
    count_strings: int
    count_characters: int
    max_string_length: int
    max_string_index: int = -1
    decoded_data: Optional[bytearray] = None


def XOR(pcBuffer: bytearray, cXOR: bytearray):
    """XOR buffer with repeating key"""
    lSize = len(pcBuffer)
    kSize = len(cXOR)
    for i in range(lSize):
        pcBuffer[i] ^= cXOR[i % kSize]
    return pcBuffer


def ROL(pcBuffer: bytearray, cROL = 1):
    """Rotate left each byte"""
    if cROL >= 8:
        return pcBuffer
    lSize = len(pcBuffer)
    for i in range(lSize):
        pcBuffer[i] = ((pcBuffer[i] << cROL) | (pcBuffer[i] >> (8-cROL))) & 0xff
    return pcBuffer


def SHIFTL(pcBuffer: bytearray, cSHIFTL = 1):
    """Shift left across bytes (with carry)"""
    if cSHIFTL >= 8:
        return pcBuffer
    lSize = len(pcBuffer)
    first_bit = pcBuffer[0] >> (8 - cSHIFTL)
    for i in range(lSize - 1):
        pcBuffer[i] = ((pcBuffer[i] << cSHIFTL) | (pcBuffer[i + 1] >> (8 - cSHIFTL))) & 0xff
    pcBuffer[lSize - 1] = ((pcBuffer[lSize - 1] << cSHIFTL) | first_bit) & 0xff
    return pcBuffer


def SHIFTR(pcBuffer: bytearray, cSHIFTR = 1):
    """Shift right across bytes (with carry)"""
    if cSHIFTR >= 8:
        return pcBuffer
    lSize = len(pcBuffer)
    last_bit = pcBuffer[lSize - 1] & ((1 << cSHIFTR) - 1)
    for i in range(lSize - 1, 0, -1):
        pcBuffer[i] = ((pcBuffer[i] >> cSHIFTR) | (pcBuffer[i - 1] << (8 - cSHIFTR))) & 0xff
    pcBuffer[0] = ((pcBuffer[0] >> cSHIFTR) | (last_bit << (8 - cSHIFTR))) & 0xff
    return pcBuffer


def is_printable(byte_val: int) -> bool:
    """Check if byte is printable ASCII"""
    return 0x20 <= byte_val <= 0x7E


def analyze_strings(data: bytearray, min_length: int = 5, terminator: int = 0) -> StringAnalysisResult:
    """Analyze strings in buffer: count, character count, max length"""
    count_strings = 0
    count_characters = 0
    max_string_length = 0
    max_string_index = -1
    
    i = 0
    string_start = -1
    
    while i < len(data):
        if data[i] != terminator and is_printable(data[i]):
            if string_start == -1:
                string_start = i
        else:
            if string_start != -1 and i - string_start >= min_length:
                count_strings += 1
                string_length = i - string_start
                count_characters += string_length
                if string_length > max_string_length:
                    max_string_length = string_length
                    max_string_index = string_start
            string_start = -1
        i += 1
    
    # Check last string
    if string_start != -1 and len(data) - string_start >= min_length:
        count_strings += 1
        string_length = len(data) - string_start
        count_characters += string_length
        if string_length > max_string_length:
            max_string_length = string_length
            max_string_index = string_start
    
    return StringAnalysisResult(
        operation=-1,
        key=-1,
        count_strings=count_strings,
        count_characters=count_characters,
        max_string_length=max_string_length,
        max_string_index=max_string_index
    )


def extract_strings(data: bytearray, min_length: int = 5, terminator: int = 0) -> List[str]:
    """Extract all strings from buffer"""
    strings = []
    i = 0
    string_start = -1
    
    while i < len(data):
        if data[i] != terminator and is_printable(data[i]):
            if string_start == -1:
                string_start = i
        else:
            if string_start != -1 and i - string_start >= min_length:
                strings.append(data[string_start:i].decode('ascii', errors='ignore'))
            string_start = -1
        i += 1
    
    if string_start != -1 and len(data) - string_start >= min_length:
        strings.append(data[string_start:].decode('ascii', errors='ignore'))
    
    return strings


def do_strings_analysis(buffer: bytearray, min_length: int = 5, terminator: int = 0) -> List[StringAnalysisResult]:
    """Analyze XOR, ROL, and SHIFT transformations"""
    results = []
    original = bytearray(buffer)
    
    # Test XOR with all 256 keys
    for key in range(256):
        buffer = bytearray(original)
        buffer = XOR(buffer, bytearray([key]))
        result = analyze_strings(buffer, min_length, terminator)
        result.operation = OPR_XOR
        result.key = key
        result.decoded_data = buffer if result.count_strings > 0 else None
        results.append(result)
    
    # Test ROL (1-7 rotations)
    buffer = bytearray(original)
    for rot in range(1, 8):
        buffer = ROL(buffer, 1)
        result = analyze_strings(buffer, min_length, terminator)
        result.operation = OPR_ROL
        result.key = rot
        result.decoded_data = bytearray(buffer) if result.count_strings > 0 else None
        results.append(result)
    
    # Test SHIFT (1-7 shifts)
    buffer = bytearray(original)
    for shift in range(1, 8):
        buffer = SHIFTL(buffer, 1)
        result = analyze_strings(buffer, min_length, terminator)
        result.operation = OPR_SHIFT
        result.key = shift
        result.decoded_data = bytearray(buffer) if result.count_strings > 0 else None
        results.append(result)
    
    return results


def save_decoded_file(data: bytearray, filename: str, operation: int, key: int):
    """Save decoded file with operation and key in filename"""
    op_str = OPERATIONS[operation] if operation < len(OPERATIONS) else "UNK"
    output_file = f"{filename}.{op_str}.{key:02X}"
    
    try:
        with open(output_file, 'wb') as f:
            f.write(data)
        print(f"[*] Saved: {output_file}")
        return True
    except Exception as e:
        print(f"[!] Error saving {output_file}: {e}")
        return False


def format_hex_key(operation: int, key: int) -> str:
    """Format key as hex string"""
    if operation == OPR_XOR:
        return f"0x{key:02x}"
    else:
        return f"{key}"


def print_results(results: List[StringAnalysisResult], sort_by_max: bool = False, 
                 dump_longest: bool = False, csv_output: bool = False, 
                 buffer: bytearray = None, filename: str = None, save_files: bool = False):
    """Print analysis results"""
    # Filter results with strings found
    results_with_strings = [r for r in results if r.count_strings > 0]
    
    if not results_with_strings:
        print("[*] No strings found in any transformation")
        return
    
    # Sort results
    if sort_by_max:
        results_with_strings.sort(key=lambda r: r.max_string_length, reverse=True)
    else:
        results_with_strings.sort(key=lambda r: r.count_strings, reverse=True)
    
    # Print header
    if csv_output:
        print("Operation,Key,Count,Avg_Length,Max_Length")
    else:
        print(f"{'Opr':5} {'Key':6} {'Count':6} {'Avg':6} {'Max':6}  Longest String")
        print("-" * 80)
    
    # Print results
    original = bytearray(buffer) if buffer else None
    for result in results_with_strings[:100]:  # Show top 100
        op_str = OPERATIONS[result.operation]
        key_str = format_hex_key(result.operation, result.key)
        avg_len = result.count_characters / result.count_strings if result.count_strings > 0 else 0
        
        if csv_output:
            longest = ""
            if dump_longest and result.decoded_data and result.max_string_index >= 0:
                start = result.max_string_index
                end = start + result.max_string_length
                longest = result.decoded_data[start:end].decode('ascii', errors='ignore')
            print(f"{op_str},{key_str},{result.count_strings},{avg_len:.1f},{result.max_string_length},{longest}")
        else:
            print(f"{op_str:5} {key_str:6} {result.count_strings:6} {avg_len:6.1f} {result.max_string_length:6}", end="")
            
            if dump_longest and result.decoded_data and result.max_string_index >= 0:
                start = result.max_string_index
                end = start + result.max_string_length
                longest = result.decoded_data[start:end].decode('ascii', errors='ignore')
                print(f"  {longest[:60]}")
            else:
                print()
            
            if save_files and result.decoded_data and filename:
                save_decoded_file(result.decoded_data, filename, result.operation, result.key)


def print_strings(data: bytearray, operation: int, key: int, min_length: int = 5, 
                 terminator: int = 0, save_decoded: bool = False, filename: str = None):
    """Apply transformation and print strings"""
    buffer = bytearray(data)
    
    # Apply transformation
    if operation == OPR_XOR:
        buffer = XOR(buffer, bytearray([key]))
    elif operation == OPR_ROL:
        for _ in range(key):
            buffer = ROL(buffer, 1)
    elif operation == OPR_SHIFT:
        for _ in range(key):
            buffer = SHIFTL(buffer, 1)
    
    # Extract and print strings
    strings = extract_strings(buffer, min_length, terminator)
    for s in strings:
        print(s)
    
    # Save if requested
    if save_decoded and filename:
        save_decoded_file(buffer, filename, operation, key)


def main():
    """Main function with argument parsing"""
    if len(sys.argv) < 2:
        print("Usage: python3 xor_detect_v2.py [options] <file>")
        print("\nOptions:")
        print("  -s            Save decoded files")
        print("  -d            Dump longest string")
        print("  -m            Sort by max string length (default: by count)")
        print("  -l <length>   Minimum string length (default: 5)")
        print("  -t <term>     String terminator as decimal or 0x hex (default: 0)")
        print("  -c            CSV output")
        print("  -o <op>       Operation: XOR, ROL, or SHIFT (use with -k)")
        print("  -k <key>      Key value (use with -o)")
        print("\nExamples:")
        print("  python3 xor_detect_v2.py malware.bin")
        print("  python3 xor_detect_v2.py -d -m malware.bin")
        print("  python3 xor_detect_v2.py -o XOR -k 0x42 malware.bin")
        sys.exit(1)
    
    # Parse arguments
    save_files = False
    dump_longest = False
    sort_by_max = False
    csv_output = False
    min_length = 5
    terminator = 0
    operation = None
    key = None
    filename = None
    
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        if arg == '-s':
            save_files = True
        elif arg == '-d':
            dump_longest = True
        elif arg == '-m':
            sort_by_max = True
        elif arg == '-c':
            csv_output = True
        elif arg == '-l' and i + 1 < len(sys.argv):
            min_length = int(sys.argv[i + 1])
            i += 1
        elif arg == '-t' and i + 1 < len(sys.argv):
            term_arg = sys.argv[i + 1]
            if term_arg.startswith('0x') or term_arg.startswith('0X'):
                terminator = int(term_arg, 16)
            else:
                terminator = int(term_arg)
            i += 1
        elif arg == '-o' and i + 1 < len(sys.argv):
            op_arg = sys.argv[i + 1].upper()
            if op_arg == "XOR":
                operation = OPR_XOR
            elif op_arg == "ROL":
                operation = OPR_ROL
            elif op_arg == "SHIFT":
                operation = OPR_SHIFT
            i += 1
        elif arg == '-k' and i + 1 < len(sys.argv):
            key_arg = sys.argv[i + 1]
            if key_arg.startswith('0x') or key_arg.startswith('0X'):
                key = int(key_arg, 16)
            else:
                key = int(key_arg)
            i += 1
        elif not arg.startswith('-'):
            filename = arg
        
        i += 1
    
    if not filename or not os.path.exists(filename):
        print(f"[!] File not found: {filename}")
        sys.exit(1)
    
    # Read file
    try:
        with open(filename, 'rb') as f:
            data = bytearray(f.read())
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)
    
    print(f"[*] Analyzing: {filename} ({len(data)} bytes)")
    print()
    
    # Validate options
    if (operation is None and key is not None) or (operation is not None and key is None):
        print("[!] Error: -o and -k must be used together")
        sys.exit(1)
    
    # Execute analysis
    if operation is not None and key is not None:
        # Print specific transformation
        print(f"[*] Applying {OPERATIONS[operation]} with key {format_hex_key(operation, key)}")
        print()
        print_strings(data, operation, key, min_length, terminator, save_files, filename)
    else:
        # Full analysis
        print(f"[*] Analyzing all XOR, ROL, and SHIFT transformations...")
        print(f"[*] Min string length: {min_length}, Terminator: 0x{terminator:02x}")
        print()
        
        results = do_strings_analysis(bytearray(data), min_length, terminator)
        print_results(results, sort_by_max, dump_longest, csv_output, data, filename, save_files)


if __name__ == "__main__":
    main()

    