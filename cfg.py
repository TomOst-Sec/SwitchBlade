#!/usr/bin/env python3
"""M4: function discovery, control flow graphs, cross-references."""
import sys
from loader import NSO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def disassemble(text):
    """disassemble entire .text section → list of capstone instruction objects"""
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True
    return list(md.disasm(text, 0))


def find_functions(instructions):
    """scan for stp x29, x30 prologues → list of function start addresses"""
    func_starts = []
    for i, inst in enumerate(instructions):
        if inst.mnemonic == 'stp' and inst.op_str.startswith('x29, x30'):
            if i > 0 and instructions[i-1].mnemonic == 'sub':
                func_starts.append(instructions[i-1].address)
            else:
                func_starts.append(inst.address)
    return func_starts


def find_function_bounds(instructions, func_starts):
    bounds = []
    for i in range(len(func_starts)):
        start = func_starts[i]
        end = func_starts[i+1] if i+1 < len(func_starts) else instructions[-1].address + instructions[-1].size
        bounds.append((start, end))
    return bounds


def build_cfg(instructions, start, end):
    func_instructions= [inst for inst in instructions if start <= inst.address < end] 
    cfg = {} 
    for i, inst in enumerate(func_instructions):  
        nxt =func_instructions[i+1].address if i+1 < len(func_instructions) else None  
        m = inst.mnemonic 
        if m == 'ret':                          cfg[inst.address] = [] 
        elif m == 'b':                          cfg[inst.address] = [int(inst.op_str.lstrip('#'), 16)] 
        elif m == 'bl':                         cfg[inst.address] = [nxt] if nxt else [] 
        elif m.startswith('b.') or m in ('cbz','cbnz','tbz','tbnz'): 
            target = int(inst.op_str.split(', ')[-1].lstrip('#'), 16) 
            cfg[inst.address] = [target] + ([nxt] if nxt else []) 
    return cfg


def find_xrefs(instructions):
    """collect all BL targets (call xrefs) and ADRP+ADD pairs (data xrefs) → list of (from, to, type)"""
    xrefs = []
    for i, inst in enumerate(instructions):
        if inst.mnemonic == 'bl':
            target = int(inst.op_str.lstrip('#'), 16)
            xrefs.append((inst.address, target, 'call'))
        elif inst.mnemonic == 'adrp' and i + 1 < len(instructions):
            # adrp xN, #0xPAGE → extract register and page address
            parts = inst.op_str.split(', ')
            reg = parts[0]
            page = int(parts[1].lstrip('#'), 16)
            # check if next instruction is add on the same register
            nxt = instructions[i + 1]
            if nxt.mnemonic == 'add' and nxt.op_str.startswith(f'{reg}, {reg}, '):
                offset = int(nxt.op_str.split(', ')[-1].lstrip('#'), 16)
                xrefs.append((inst.address, page + offset, 'data'))
    return xrefs



if __name__ == "__main__":
    nso = NSO(sys.argv[1])
    instructions = disassemble(nso.text)
    func_starts = find_functions(instructions)
    bounds = find_function_bounds(instructions, func_starts)
    print(f"found {len(func_starts)} functions")
    for start, end in bounds[:10]:
        print(f"function at 0x{start:x} - 0x{end:x} (size {end-start} bytes)")
    # test CFG on first function
    start, end = bounds[0]
    cfg = build_cfg(instructions, start, end)
    print(f"CFG for function at 0x{start:x}:")
    for addr, next_addrs in cfg.items():
        targets = ', '.join(f"0x{a:x}" for a in next_addrs)
        print(f"  0x{addr:x} -> {targets}")

    # test xrefs
    xrefs = find_xrefs(instructions)
    calls = [x for x in xrefs if x[2] == 'call']
    data  = [x for x in xrefs if x[2] == 'data']
    print(f"\nxrefs: {len(calls)} calls, {len(data)} data refs")
    for src, dst, kind in xrefs[:20]:
        print(f"  0x{src:x} -> 0x{dst:x}  ({kind})")


    

