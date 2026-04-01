#!/usr/bin/env python3
"""ARM64 instruction decoder. 4 bytes in, one instruction out.
test: python3 decoder.py 0xd65f03c0 → "RET"
test: python3 decoder.py 0xd503201f → "NOP" """
import struct, sys
from loader import NSO

def decode(inst):
    if inst == 0x00000000:                    return "---"
    if inst == 0xd503201f:                    return "NOP"   # this is the encoding for the NOP
    if inst == 0xd65f03c0:                    return "RET"   # this is the encoding for the RET instruction in ARM64

    top6 = (inst >> 26)
    top8 = (inst >> 24)

    # branches
    if top6 == 0x05:                          return "B"        # B (unconditional branch)
    if top6 == 0x25:                          return "BL"       # BL (branch with link / function call)
    if top8 == 0x54:                          return "B.cond"
    if (top8 & 0x7E) == 0x34:                return "CBZ/CBNZ" # CBZ/CBNZ (compare and branch if zero)
    if ((inst >> 25) & 0x7F) == 0x6B:        return "BR/BLR"   # bits [31:25] = 1101011 → BR/BLR/RET family (branch register)

    # data processing
    if ((inst >> 23) & 0x3F) == 0x22:        return "ADD/SUB imm"  # bits [28:23] = 100010 → ADD/SUB immediate
    if ((inst >> 24) & 0x1F) == 0x0B:        return "DP reg"       # bits [28:24] = 01011 → data processing register
    if ((inst >> 24) & 0x1F) == 0x0A:        return "Logic reg"    # bits [28:24] = 01010 → logical register (MOV/ORR/AND)
    if ((inst >> 23) & 0x3F) == 0x25:        return "MOV wide"     # bits [28:23] = 100101 → MOV wide (MOVZ/MOVK/MOVN)
    if ((inst >> 24) & 0x1F) == 0x10:        return "ADR"          # bits [28:24] = 10000 → ADR/ADRP (address calc)

    # load/store
    if ((inst >> 24) & 0x3F) == 0x39:        return "LDR/STR"  # bits [29:24] = 111001 → LDR/STR unsigned offset
    if ((inst >> 25) & 0x3F) == 0x14:        return "STP/LDP"  # bits [30:25] = 010100 → LDP/STP family

    # system
    if (inst >> 21) == 0x6A0:                return "SVC"      # supervisor call — syscall to the Switch kernel

    return "???"

def disasm(text, start=0, count=50):
    """decode a chunk of .text bytes into a list of (addr, raw_int, name) tuples.
    iterates in 4-byte increments since each ARM64 instruction is exactly 4 bytes.
    struct.unpack("<I", ...) converts 4 little-endian bytes into a 32-bit unsigned int."""
    results = []
    for i in range(start, min(start + count * 4, len(text)), 4): # iterate over the text in 4-byte steps 
        inst = struct.unpack("<I", text[i:i+4])[0] # convert 4 bytes to int — "<I" = little-endian unsigned int
        results.append((i, inst, decode(inst)))     # (offset, raw instruction, decoded name)
    return results # returns a list of tuples containing the offset, raw instruction, and decoded name for each instruction in the specified range


if __name__ == "__main__":                                                                                                                                                                            
      nso = NSO(sys.argv[1])                                                           
      count = int(sys.argv[2]) if len(sys.argv) > 2 else 50                                                                                                                                             
      hand = "--hand" in sys.argv        
                                                                                                                                                                                                        
      if hand:                                                                                                                                                                                          
          for addr, inst, name in disasm(nso.text, 0, count):                                  
              print(f"  {addr:08x}:  {inst:08x}  {name}")                                                                                                                                               
      else:                                                                            
          from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM                                                                                                                                           
          md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
          md.skipdata = True                                                                                                                                                                            
          for inst in list(md.disasm(nso.text, 0))[:count]:                            
              print(f"  {inst.address:08x}:  {inst.bytes.hex()}  {inst.mnemonic} {inst.op_str}")