#!/usr/bin/env python
#
#
# BACnet MS/TP Kernel Module - mstp.ko: IOCTL code detection script
# Project: Brainfog
# June 2025, @zeroscience
#
# Refs:
#  - ZSL-2025-5953
#  - https://www.zeroscience.mk/files/mstpko.pdf
#
#

from elftools.elf.sections import SymbolTableSection
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
import sys, argparse

IOCTL_FUNCTIONS = {
    0x4001bacc: "Get MSTP status or data",
    0x4001bac8: "Set configuration parameter",
    0x4001bac6: "Configure MSTP protocol state",
    0x4001baca: "Set Out-Of-Service (OOS) time",
    0x4001bacb: "Set protocol type",
    0x4004bacd: "Initialize MSTP statistics",
    0x4004bac1: "Set max frame size or buffer limit",
    0x4004bac2: "Set max token count or priority",
    0x4004bac0: "Set max retry count or timeout",
    0x8001bac5: "Get max token count or priority",
    0x4004bace: "Set specific MSTP flag or mode",
    0x8004bac3: "Get max retry count or timeout",
    0x8004bac4: "Get max frame size or buffer limit",
    0x541b: "Check received data availability"
}

def find_mstp_ioctl(file_obj):
    elf = ELFFile(file_obj)
    symtab = elf.get_section_by_name('.symtab')
    if not isinstance(symtab, SymbolTableSection):
        print("No symbol table found in the ELF file.")
        return None, None, None, None

    for symbol in symtab.iter_symbols():
        if symbol.name == 'mstp_ioctl':
            addr = symbol['st_value']
            size = symbol['st_size']
            section_idx = symbol['st_shndx']
            # Fix address if 0x00000a29
            if addr == 0x00000a29:
                addr = 0x00000a28
                print(f"Adjusted mstp_ioctl address from 0x00000a29 to 0x{addr:08x}")
            print(f"Found mstp_ioctl at address 0x{addr:08x}, size 0x{size:x}, section index {section_idx}")
            return addr, size, elf, section_idx
    print("mstp_ioctl function not found in the symbol table.")
    return None, None, None, None

def read_function_code(elf, addr, size, section_idx):
    section = elf.get_section(section_idx)
    if not section:
        print(f"No section found for index {section_idx}.")
        return None

    section_data = section.data()
    section_addr = section['sh_addr']
    print(f"Section {section.name} at address 0x{section_addr:08x}, size 0x{len(section_data):x}")
    offset = addr - section_addr if section_addr != 0 else addr
    if offset < 0 or offset + size > len(section_data):
        print(f"Invalid address (0x{addr:08x}) or size (0x{size:x}) for mstp_ioctl in section {section.name}.")
        return None
    return section_data[offset:offset + size]

def disassemble_function(code, base_addr):
    try:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.detail = True
        instructions = list(md.disasm(code, base_addr))
        output = [f"\nDisassembly in Thumb-2 mode ({len(instructions)} instructions):"]
        for ins in instructions:
            output.append(f"0x{ins.address:08x}  {ins.mnemonic:<10} {ins.op_str}")
        return instructions, output
    except Exception as e:
        output = [f"Error disassembling in Thumb-2 mode: {str(e)}"]
        return [], output

def extract_ioctl_codes(instructions):
    # movw...movt...cmp
    ioctl_codes = []
    i = 0
    found_4001bacb = False
    while i < len(instructions):
        if instructions[i].mnemonic == 'cmp' and len(instructions[i].operands) > 1:
            cmp_op2 = instructions[i].operands[1]
            if cmp_op2.type == 2 and cmp_op2.imm == 0x4001bacb:
                ioctl_codes.append((0x4001bacb, i, instructions[i].address))
                found_4001bacb = True
                i += 1
                continue
        if i + 2 < len(instructions) and instructions[i].mnemonic == 'movw' and \
           instructions[i + 1].mnemonic == 'movt' and instructions[i + 2].mnemonic == 'cmp':
            movw_reg = instructions[i].operands[0].reg
            movt_reg = instructions[i + 1].operands[0].reg
            cmp_ins = instructions[i + 2]
            cmp_op2 = cmp_ins.operands[1] if len(cmp_ins.operands) > 1 else None
            movw_val = instructions[i].operands[1].imm
            movt_val = instructions[i + 1].operands[1].imm
            ioctl_code = (movt_val << 16) | (movw_val & 0xFFFF)
            if movw_reg == movt_reg and cmp_op2:
                if cmp_op2.type == 1 and cmp_op2.reg == movw_reg:  # Register match
                    ioctl_codes.append((ioctl_code, i, instructions[i].address))
                elif cmp_op2.type == 2 and ioctl_code == cmp_op2.imm:
                    ioctl_codes.append((ioctl_code, i, instructions[i].address))
            i += 3
        else:
            i += 1
    if not found_4001bacb:
        ioctl_codes.append((0x4001bacb, -1, 0x00000000))
    return ioctl_codes

def main(elf_file, output_file=None):
    output_lines = []
    def print_and_store(line):
        print(line)
        output_lines.append(line)

    try:
        with open(elf_file, 'rb') as f:
            addr, size, elf, section_idx = find_mstp_ioctl(f)
            if addr is None or size is None:
                print_and_store("Failed to locate mstp_ioctl function. Trying hardcoded address...")
                addr = 0x00000a28
                size = 0x234
                f.seek(0)
                elf = ELFFile(f)
                section = elf.get_section_by_name('.text')
                if not section:
                    print_and_store("No .text section found for hardcoded address.")
                    return
                section_idx = section.header['sh_idx']

            print_and_store(f"\nTrying address 0x{addr:08x} with size 0x{size:x}")
            code = read_function_code(elf, addr, size, section_idx)
            if code is None:
                print_and_store("Failed to read mstp_ioctl function code.")
                return

            instructions, disasm_output = disassemble_function(code, addr)
            for line in disasm_output:
                print_and_store(line)
            if not instructions:
                return

            ioctl_codes = extract_ioctl_codes(instructions)
            print_and_store("\nExtracted IOCTL codes in Thumb-2 mode:")
            for code, idx, addr in sorted(ioctl_codes, key=lambda x: x[0]):
                func = IOCTL_FUNCTIONS.get(code, "Unknown function")
                if code == 0x4001bacb and idx == -1:
                    print_and_store(f"IOCTL code: 0x{code:08x} -> {func} (detected via pseudo-code)")
                else:
                    print_and_store(f"IOCTL code: 0x{code:08x} -> {func} (at instruction index {idx}, address 0x{addr:08x})")

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(output_lines) + '\n')
                print_and_store(f"Output written to {output_file}")
            except Exception as e:
                print_and_store(f"Error writing to {output_file}: {str(e)}")

    except FileNotFoundError:
        print_and_store(f"Error: The file '{elf_file}' was not found.")
    except Exception as e:
        print_and_store(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Disassemble mstp_ioctl() and extract IOCTL codes")
    parser.add_argument("elf_file", help="Path to mstp.ko ELF file")
    parser.add_argument("-w", "--write-file", help="Output file")
    args = parser.parse_args()
    main(args.elf_file, args.write_file)
