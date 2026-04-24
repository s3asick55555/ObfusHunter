import sys
import pefile
from capstone import *

def analyze_control_flow(file_path):
    print(f"--- Control Flow Obfuscation Analysis: {file_path} ---")
    try:
        pe = pefile.PE(file_path)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        # Find the section containing the entry point
        code_section = None
        for section in pe.sections:
            if section.VirtualAddress <= entry_point < section.VirtualAddress + section.Misc_VirtualSize:
                code_section = section
                break
        
        if not code_section:
            print("Could not find code section.")
            return

        code_data = code_section.get_data()
        code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

        # Initialize Capstone (Assuming x86 or x64)
        if pe.FILE_HEADER.Machine == 0x014c: # x86
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif pe.FILE_HEADER.Machine == 0x8664: # x64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            print("Unsupported architecture.")
            return

        indirect_transfers = 0
        jumps = 0
        total_insns = 0
        nops = 0

        # Analyze first 10,000 instructions for performance
        for i in md.disasm(code_data[:20000], code_addr):
            total_insns += 1
            
            # 1. Detect NOPs (Junk code indicator)
            if i.mnemonic == 'nop':
                nops += 1

            # 2. Detect Indirect Jumps/Calls
            if i.mnemonic in ['call', 'jmp']:
                jumps += 1
                # Check if operand is a register (indirect)
                if i.op_str in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 
                                'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                                'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
                    indirect_transfers += 1
                elif i.op_str.startswith('[') and '0x' not in i.op_str:
                    # Likely indirect memory access like [eax]
                    indirect_transfers += 1

        if total_insns > 0:
            print(f"\n[Statistics (First 20KB of code)]")
            print(f"  Total Instructions: {total_insns}")
            print(f"  NOP Instructions: {nops} ({nops/total_insns:.2%})")
            print(f"  Indirect Jumps/Calls: {indirect_transfers} ({indirect_transfers/jumps:.2%} of jumps)" if jumps > 0 else "  No jumps found")
            
            if nops / total_insns > 0.1:
                print("  [!] High NOP density - possible junk code insertion.")
            if jumps > 0 and indirect_transfers / jumps > 0.3:
                print("  [!] High ratio of indirect transfers - possible control flow flattening or indirect call obfuscation.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cf_detect.py <file_path>")
    else:
        analyze_control_flow(sys.argv[1])
