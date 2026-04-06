#!/usr/bin/env python3
"""M8: vulnerability pattern scanner. finds suspicious patterns across all Switch binaries.
usage: python3 scanner.py <file.nso>    — scan one binary
       python3 scanner.py <dir/>        — scan all 74 binaries"""
import sys, os, glob, bisect
from loader import NSO
from analyzer import get_service_name, target_value, scan_syscalls
from cfg import disassemble, find_functions, find_function_bounds
from syscalls import HORIZON_SYSCALLS

INFO, LOW, MED, HIGH, CRIT = 1, 2, 3, 4, 5
SEV = {1: 'INFO', 2: 'LOW ', 3: 'MED ', 4: 'HIGH', 5: 'CRIT'}

DANGEROUS_SVCS = {
    0x48: "MapPhysicalMemoryUnsafe", 0x49: "UnmapPhysicalMemoryUnsafe",
    0x4E: "ReadWriteRegister", 0x60: "DebugActiveProcess",
    0x6A: "ReadDebugProcessMemory", 0x6B: "WriteDebugProcessMemory",
    0x73: "SetProcessMemoryPermission", 0x74: "MapProcessMemory",
    0x77: "MapProcessCodeMemory", 0x7F: "CallSecureMonitor",
}


# ── rules ─────────────────────────────────────────────────────────
# each rule: (insns, start, end) → [(addr, severity, description)]

def rule_dangerous_svc(insns, s, e):
    """security-sensitive syscalls — elevated privilege surface"""
    hits = []
    for i in insns:
        if i.mnemonic == 'svc':
            num = int(i.op_str.lstrip('#'), 16)
            if num in DANGEROUS_SVCS:
                hits.append((i.address, CRIT, f"dangerous: {DANGEROUS_SVCS[num]}"))
    return hits


def rule_unchecked_svc(insns, s, e):
    """SVC return value (x0) not tested — missing error handling"""
    hits = []
    for idx, i in enumerate(insns):
        if i.mnemonic != 'svc': continue
        window = insns[idx+1:idx+4]
        if not window: continue
        checked = any(
            (w.mnemonic in ('cbz','cbnz','tbz','tbnz') and w.op_str.startswith('x0')) or
            (w.mnemonic in ('cmp','tst') and w.op_str.startswith('x0'))
            for w in window
        )
        if not checked:
            num = int(i.op_str.lstrip('#'), 16)
            name = HORIZON_SYSCALLS.get(num, f'svc_{num:#x}')
            hits.append((i.address, MED, f"unchecked: {name} return"))
    return hits


def rule_large_stack(insns, s, e):
    """large stack buffer — potential overflow target"""
    for i in insns:
        if i.mnemonic == 'sub' and i.op_str.startswith('sp, sp, #'):
            try:
                size = int(i.op_str.split('#')[1].strip(), 0)
                if size >= 0x200:
                    sev = HIGH if size >= 0x1000 else MED if size >= 0x400 else LOW
                    return [(i.address, sev, f"stack buffer: {size:#x} ({size}) bytes")]
            except (ValueError, IndexError): pass
    return []


def rule_int_overflow(insns, s, e):
    """multiply without overflow check before use — integer overflow risk"""
    hits = []
    for idx, i in enumerate(insns):
        if i.mnemonic not in ('mul', 'madd', 'umull', 'smull'): continue
        dst = i.op_str.split(',')[0].strip()
        has_check, has_use = False, False
        for w in insns[idx+1:idx+8]:
            if w.mnemonic in ('umulh', 'smulh'):                         has_check = True; break
            if w.mnemonic in ('cmp','tst') and dst in w.op_str:          has_check = True; break
            if w.mnemonic in ('cbz','cbnz') and w.op_str.startswith(dst): has_check = True; break
            if w.mnemonic in ('bl', 'svc'):                              has_use = True; break
            if w.mnemonic in ('str', 'stp') and dst in w.op_str:        has_use = True; break
        if has_use and not has_check:
            hits.append((i.address, HIGH, f"unchecked mul: {dst}"))
    return hits


def rule_ipc_handler(insns, s, e):
    """IPC dispatch function — primary attack surface"""
    for i in insns:
        if i.mnemonic == 'svc':
            num = int(i.op_str.lstrip('#'), 16)
            if num in (0x43, 0x44):
                return [(i.address, INFO, f"IPC handler: {HORIZON_SYSCALLS.get(num, '?')}")]
    return []


def rule_complexity(insns, s, e):
    """high complexity function — audit target"""
    branches = sum(1 for i in insns if i.mnemonic in ('b','bl','br','blr') or
                   i.mnemonic.startswith('b.') or i.mnemonic in ('cbz','cbnz','tbz','tbnz'))
    size = e - s
    if branches > 80 and size > 0x2000:
        return [(s, LOW, f"complex: {branches} branches, {size:#x} bytes")]
    return []


RULES = [rule_dangerous_svc, rule_unchecked_svc, rule_large_stack,
         rule_int_overflow, rule_ipc_handler, rule_complexity]


# ── scanner core ──────────────────────────────────────────────────

def scan_function(insns, start, end):
    """run all rules on one function's instructions → [(addr, severity, desc)]"""
    if not insns: return []
    hits = []
    for rule in RULES:
        hits.extend(rule(insns, start, end))
    return hits


def scan_binary(nso):
    """scan entire binary → [(func_addr, [(addr, sev, desc)])]"""
    instructions = disassemble(nso.text)
    starts = find_functions(instructions)
    bounds = find_function_bounds(instructions, starts)
    addrs = [i.address for i in instructions]
    results = []
    for s, e in bounds:
        lo = bisect.bisect_left(addrs, s)
        hi = bisect.bisect_left(addrs, e)
        hits = scan_function(instructions[lo:hi], s, e)
        if hits: results.append((s, hits))
    return results


# ── CLI ───────────────────────────────────────────────────────────

def _print_scan(name, results, tv):
    total = sum(len(h) for _, h in results)
    if not total: return 0
    print(f"\n{'─'*60}")
    print(f"  {name}  (target: {tv}/10)  {total} findings")
    for _, hits in results:
        for addr, sev, desc in sorted(hits, key=lambda x: -x[1]):
            print(f"  [{SEV[sev]}]  0x{addr:08x}  {desc}")
    return total


if __name__ == "__main__":
    path = sys.argv[1]
    if os.path.isdir(path):
        stats = []
        for f in sorted(glob.glob(os.path.join(path, "*.nso"))):
            nso = NSO(f)
            name = get_service_name(nso) or os.path.basename(f).replace(".nso", "")
            results = scan_binary(nso)
            syscalls = scan_syscalls(nso)
            tv = target_value(name, syscalls)
            n = _print_scan(name, results, tv)
            crits = sum(1 for _, h in results for _, s, _ in h if s == CRIT)
            stats.append((name, n, crits))
        total = sum(n for _, n, _ in stats)
        crits = sum(c for _, _, c in stats)
        print(f"\n{'='*60}")
        print(f"  {total} findings, {crits} critical")
        for name, n, c in sorted(stats, key=lambda x: -x[2]):
            if n: print(f"  {'!!' if c else '  '} {n:3d} findings  {name}")
    else:
        nso = NSO(path)
        name = get_service_name(nso) or os.path.basename(path).replace(".nso", "")
        results = scan_binary(nso)
        syscalls = scan_syscalls(nso)
        tv = target_value(name, syscalls)
        n = _print_scan(name, results, tv)
        print(f"\n{n} findings total")
