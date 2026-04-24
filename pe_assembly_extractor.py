#!/usr/bin/env python3
"""
PE Assembly Extractor & Section Analyzer
Extracts assembly code and section properties from PE executables
"""

import sys
import os
import pefile
import capstone
from capstone import x86
import math
from collections import Counter

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if not data:
        return 0
    entropy = 0
    byte_counts = Counter(data)
    for count in byte_counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def get_section_properties(pe):
    """Extract and display properties for all sections"""
    print("\n" + "="*80)
    print("SECTION PROPERTIES")
    print("="*80)
    
    sections_info = []
    
    for section in pe.sections:
        name = section.Name.decode().strip('\x00')
        
        # Get section data
        section_data = section.get_data()
        entropy = calculate_entropy(section_data)
        
        properties = {
            'name': name,
            'virtual_size': section.Misc_VirtualSize,
            'virtual_address': hex(section.VirtualAddress),
            'raw_size': section.SizeOfRawData,
            'raw_pointer': hex(section.PointerToRawData),
            'characteristics': section.Characteristics,
            'entropy': entropy,
            'actual_size': len(section_data),
        }
        
        sections_info.append(properties)
        
        # Print section header
        print(f"\n[{name}]")
        print(f"  Virtual Address:    {properties['virtual_address']}")
        print(f"  Virtual Size:       {properties['virtual_size']:,} bytes")
        print(f"  Raw Address:        {properties['raw_pointer']}")
        print(f"  Raw Size:           {properties['raw_size']:,} bytes")
        print(f"  Actual Size:        {properties['actual_size']:,} bytes")
        print(f"  Entropy:            {entropy:.4f}")
        
        # Decode characteristics
        characteristics = []
        if section.Characteristics & 0x20000000:
            characteristics.append("EXECUTE")
        if section.Characteristics & 0x40000000:
            characteristics.append("READ")
        if section.Characteristics & 0x80000000:
            characteristics.append("WRITE")
        if section.Characteristics & 0x02000000:
            characteristics.append("INITIALIZED_DATA")
        if section.Characteristics & 0x04000000:
            characteristics.append("UNINITIALIZED_DATA")
        
        if characteristics:
            print(f"  Characteristics:    {', '.join(characteristics)}")
        
        # Entropy interpretation
        if entropy > 7.2:
            print(f"  [!] High entropy - likely encrypted/packed")
        elif entropy > 6.5:
            print(f"  [?] Moderate entropy - may be compressed")
    
    return sections_info

def disassemble_section(pe, section, arch='x86', mode='32bit'):
    """Disassemble code in a given section"""
    try:
        section_data = section.get_data()
        
        # Set capstone mode based on PE architecture
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            cs_mode = capstone.CS_MODE_32
            arch_name = "x86 (32-bit)"
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            cs_mode = capstone.CS_MODE_64
            arch_name = "x86-64 (64-bit)"
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']:
            cs_mode = capstone.CS_MODE_ARM
            arch_name = "ARM"
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']:
            cs_mode = capstone.CS_MODE_ARM
            arch_name = "ARM64"
        else:
            return None, None
        
        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        md.detail = True
        
        instructions = list(md.disasm(section_data, section.VirtualAddress))
        return instructions, arch_name
        
    except Exception as e:
        return None, str(e)

def filter_interesting_instructions(instructions, keywords=None):
    """Filter instructions for analysis (calls, jumps, suspicious operations)"""
    if keywords is None:
        keywords = ['call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'xor', 'mov']
    
    filtered = []
    for instr in instructions:
        mnemonic = instr.mnemonic.lower()
        if any(kw in mnemonic for kw in keywords):
            filtered.append(instr)
    
    return filtered

def extract_strings_from_section(section_data, min_length=4):
    """Extract readable strings from binary section"""
    strings = []
    current = []
    
    for byte in section_data:
        if 32 <= byte <= 126:  # Printable ASCII
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append({
                    'offset': len(strings),
                    'value': bytes(current).decode(errors='ignore'),
                    'length': len(current)
                })
            current = []
    
    if len(current) >= min_length:
        strings.append({
            'offset': len(strings),
            'value': bytes(current).decode(errors='ignore'),
            'length': len(current)
        })
    
    return strings

def analyze_pe_file(file_path, dump_assembly=True, max_instructions=1000, 
                   section_filter=None, keyword_filter=None, force_all_sections=False):
    """Main analysis function"""
    print(f"{'='*80}")
    print(f"PE Assembly Extractor & Section Analyzer")
    print(f"{'='*80}")
    print(f"File: {file_path}")
    print(f"{'='*80}\n")
    
    try:
        pe = pefile.PE(file_path)
        
        # Display PE Header Info
        print("[PE HEADER INFORMATION]")
        print(f"  Architecture:       ", end="")
        if pe.FILE_HEADER.Machine == 0x14c:
            print("x86 (32-bit)")
        elif pe.FILE_HEADER.Machine == 0x8664:
            print("x86-64 (64-bit)")
        elif pe.FILE_HEADER.Machine == 0x1c0:
            print("ARM")
        else:
            print(f"0x{pe.FILE_HEADER.Machine:04x}")
        
        print(f"  Subsystem:          {pe.OPTIONAL_HEADER.Subsystem}")
        print(f"  Entry Point:        {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"  Image Base:         {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        
        # Extract section properties
        sections = get_section_properties(pe)
        
        # Extract assembly and properties for each section
        if dump_assembly:
            print("\n" + "="*80)
            print("ASSEMBLY CODE EXTRACTION")
            print("="*80)
            
            for section in pe.sections:
                section_name = section.Name.decode().strip('\x00')
                
                # Skip non-executable sections unless section_filter or force_all_sections is set
                if not force_all_sections and section_filter is None:
                    is_executable = bool(section.Characteristics & 0x20000000)
                    if not is_executable:
                        continue
                elif section_filter and section_filter not in section_name:
                    continue
                
                print(f"\n[{section_name}] Disassembly")
                print(f"  Base Address: {hex(section.VirtualAddress)}")
                print(f"  Size: {len(section.get_data()):,} bytes\n")
                
                instructions, arch_name = disassemble_section(pe, section)
                
                if instructions is None:
                    print(f"  [!] Cannot disassemble: {arch_name}\n")
                    continue
                
                # Filter instructions if keyword filter provided
                display_instructions = instructions
                if keyword_filter:
                    display_instructions = filter_interesting_instructions(instructions, keyword_filter)
                    print(f"  Found {len(display_instructions)} interesting instructions (filtered from {len(instructions)})\n")
                else:
                    print(f"  Total instructions: {len(instructions)}\n")
                
                # Display instructions
                for instr in display_instructions:                    
                    # Highlight suspicious instructions
                    highlight = ""
                    if any(x in instr.mnemonic.lower() for x in ['call', 'jmp', 'je','jge','jl','jle', 'ja', 'jb']):
                        highlight = " [JUMP/CALL]"
                        print(f"  {hex(instr.address):10s} {instr.mnemonic:6s} {instr.op_str:30s}{highlight}")
                    elif 'xor' in instr.mnemonic.lower():
                        reg = instr.op_str.split(", ")
                        if reg[0] == reg[1]:
                            highlight = ""
                        else:
                            possible_key = reg[1]
                            if not possible_key.startswith("0x"):
                                highlight = f" [XOR with data at {reg[1]}]"
                            else:
                                key = int(possible_key[2:],16)
                                highlight = f" [XOR with possible key {key}]"
                                
                    
                            print(f"  {hex(instr.address):10s} {instr.mnemonic:6s} {instr.op_str:30s}{highlight}")
        
        # Extract strings from each section
        print("\n" + "="*80)
        print("EXTRACTED STRINGS")
        print("="*80)
        
        for section in pe.sections:
            section_name = section.Name.decode().strip('\x00')
            section_data = section.get_data()
            
            strings = extract_strings_from_section(section_data)
            
            if strings:
                print(f"\n[{section_name}] Found {len(strings)} strings")
                for i, s in enumerate(strings[:20]):  # Show first 20
                    print(f"  {s['value']}")
                
                if len(strings) > 20:
                    print(f"  ... and {len(strings) - 20} more strings")
        
        return True
        
    except pefile.PEFormatError:
        print("[!] Error: Not a valid PE file")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pe_assembly_extractor.py <PE_file> [options]")
        print("\nOptions:")
        print("  --no-asm              Skip assembly disassembly (show sections only)")
        print("  --all-sections        Disassemble all sections (not just executable)")
        print("  --limit <n>           Limit assembly output to <n> instructions (default: 500)")
        print("  --section <name>      Only disassemble this section")
        print("  --keywords <list>     Filter for keywords: 'call,jmp,xor' (default: call,jmp,xor,je,jne,mov)")
        print("\nExamples:")
        print("  python3 pe_assembly_extractor.py malware.exe")
        print("  python3 pe_assembly_extractor.py sample.exe --section .text --limit 200")
        print("  python3 pe_assembly_extractor.py app.exe --no-asm")
        print("  python3 pe_assembly_extractor.py test.exe --all-sections")
        sys.exit(1)
    
    file_path = sys.argv[1]
    dump_asm = True
    max_instr = 500
    section_filter = None
    keyword_filter = None
    force_all = False
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--no-asm":
            dump_asm = False
        elif sys.argv[i] == "--all-sections":
            force_all = True
        elif sys.argv[i] == "--limit" and i + 1 < len(sys.argv):
            max_instr = int(sys.argv[i + 1])
            i += 1
        elif sys.argv[i] == "--section" and i + 1 < len(sys.argv):
            section_filter = sys.argv[i + 1]
            i += 1
        elif sys.argv[i] == "--keywords" and i + 1 < len(sys.argv):
            keyword_filter = sys.argv[i + 1].split(',')
            i += 1
        i += 1
    
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)
    
    analyze_pe_file(file_path, dump_assembly=dump_asm, max_instructions=max_instr,
                   section_filter=section_filter, keyword_filter=keyword_filter,
                   force_all_sections=force_all)

if __name__ == "__main__":
    main()
