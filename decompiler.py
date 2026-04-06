#!/usr/bin/env python3
"""M9: ARM64 → C pseudocode decompiler. translates machine code to readable C.
usage: python3 decompiler.py <file.nso>              — decompile first 5 functions
       python3 decompiler.py <file.nso> 0x1234       — decompile function at address"""
import sys
from loader import NSO
from cfg import disassemble, find_functions, find_function_bounds
from syscalls import HORIZON_SYSCALLS

CONDS = {'eq':'==', 'ne':'!=', 'lt':'<', 'le':'<=', 'gt':'>', 'ge':'>=',
         'hi':'> (u)', 'ls':'<= (u)', 'cs':'>= (u)', 'cc':'< (u)',
         'mi':'< 0', 'pl':'>= 0'}


def _ops(op_str):
    """split operand string respecting brackets: 'x0, [x1, #8]' → ['x0', '[x1, #8]']"""
    parts, cur, depth = [], '', 0
    for c in op_str:
        if c == '[': depth += 1
        elif c == ']': depth -= 1
        if c == ',' and depth == 0: parts.append(cur.strip()); cur = ''
        else: cur += c
    if cur.strip(): parts.append(cur.strip())
    return parts


def _imm(s):
    """parse immediate: '#0x1a' → 26, '#-0x10' → -16"""
    s = s.lstrip('#').strip()
    try: return -int(s[1:], 0) if s.startswith('-') else int(s, 0)
    except ValueError: return s


def _fmt(v):
    if isinstance(v, int): return f'{v:#x}' if abs(v) > 255 else str(v)
    return str(v)


def _typ(mnem, reg):
    """C type from mnemonic + register"""
    m = mnem.lower()
    if 'sb' in m: return 'int8_t'
    if 'sh' in m: return 'int16_t'
    if 'sw' in m: return 'int32_t'
    if m.endswith('b'): return 'uint8_t'
    if m.endswith('h'): return 'uint16_t'
    if reg.startswith('w'): return 'uint32_t'
    return 'uint64_t'


def _mem(base, off, typ='uint64_t'):
    """C memory access expression"""
    if base in ('sp', 'x29'): return f'local_{abs(off):x}'
    if off == 0: return f'*({typ} *){base}'
    sign = '+' if off > 0 else '-'
    return f'*({typ} *)({base} {sign} {_fmt(abs(off))})'


def _parse_mem(s):
    """'[x19, #8]' → ('x19', 8)"""
    s = s.strip('[]! ')
    parts = [p.strip() for p in s.split(',')]
    base = parts[0]
    if len(parts) > 1 and parts[1].strip().startswith('#'):
        off = _imm(parts[1])
        return base, off if isinstance(off, int) else 0
    return base, 0


def decompile_insn(insn, state):
    """translate one ARM64 instruction → (C_line | None, state)"""
    m, ops = insn.mnemonic, _ops(insn.op_str)

    # ── noise ──
    if m == 'nop': return None, state
    if m == 'stp' and len(ops) >= 2 and ops[0] == 'x29' and ops[1] == 'x30': return None, state
    if m == 'ldp' and len(ops) >= 2 and ops[0] == 'x29' and ops[1] == 'x30': return None, state

    # ── return ──
    if m == 'ret': return 'return x0;', state

    # ── syscall ──
    if m == 'svc':
        num = int(ops[0].lstrip('#'), 16)
        name = HORIZON_SYSCALLS.get(num, f'svc_{num:#x}')
        return f'x0 = {name}();', state

    # ── calls ──
    if m == 'bl':
        t = _imm(ops[0])
        return (f'x0 = sub_{t:x}();' if isinstance(t, int) else f'x0 = {ops[0]}();'), state
    if m == 'blr': return f'x0 = (*{ops[0]})();', state

    # ── unconditional branch ──
    if m == 'b':
        t = _imm(ops[0])
        return (f'goto loc_{t:x};' if isinstance(t, int) else f'goto {ops[0]};'), state
    if m == 'br': return f'goto *{ops[0]};', state

    # ── conditional branches ──
    if m.startswith('b.'):
        cond = m[2:]
        t = _imm(ops[0])
        lbl = f'loc_{t:x}' if isinstance(t, int) else str(t)
        c = CONDS.get(cond, cond)
        if state['cmp']:
            a, b = state['cmp']
            return f'if ({a} {c} {b}) goto {lbl};', state
        return f'if ({cond}) goto {lbl};', state

    if m == 'cbz':
        t = _imm(ops[1]); lbl = f'loc_{t:x}' if isinstance(t, int) else str(t)
        return f'if ({ops[0]} == 0) goto {lbl};', state
    if m == 'cbnz':
        t = _imm(ops[1]); lbl = f'loc_{t:x}' if isinstance(t, int) else str(t)
        return f'if ({ops[0]} != 0) goto {lbl};', state
    if m == 'tbz' and len(ops) >= 3:
        bit, t = _imm(ops[1]), _imm(ops[2]); lbl = f'loc_{t:x}' if isinstance(t, int) else str(t)
        return f'if (!({ops[0]} & (1 << {bit}))) goto {lbl};', state
    if m == 'tbnz' and len(ops) >= 3:
        bit, t = _imm(ops[1]), _imm(ops[2]); lbl = f'loc_{t:x}' if isinstance(t, int) else str(t)
        return f'if ({ops[0]} & (1 << {bit})) goto {lbl};', state

    # ── compare → state update ──
    if m == 'cmp' and len(ops) >= 2:
        b = _imm(ops[1]) if ops[1].startswith('#') else ops[1]
        state['cmp'] = (ops[0], _fmt(b) if isinstance(b, int) else b)
        return None, state
    if m == 'tst' and len(ops) >= 2:
        b = _imm(ops[1]) if ops[1].startswith('#') else ops[1]
        state['cmp'] = (f'{ops[0]} & {_fmt(b) if isinstance(b, int) else b}', '0')
        return None, state

    # ── mov ──
    if m == 'mov' and len(ops) >= 2:
        src = ops[1]
        if src in ('xzr', 'wzr'): return f'{ops[0]} = 0;', state
        if src.startswith('#'): return f'{ops[0]} = {_fmt(_imm(src))};', state
        return f'{ops[0]} = {src};', state
    if m in ('movz', 'movk', 'movn') and len(ops) >= 2:
        v = _imm(ops[1])
        if m == 'movn': return f'{ops[0]} = ~{_fmt(v)};', state
        if m == 'movk' and len(ops) > 2:
            shift = ops[2].split('#')[-1].strip()
            return f'{ops[0]} |= ({_fmt(v)} << {shift});', state
        return f'{ops[0]} = {_fmt(v)};', state

    # ── arithmetic ──
    if m in ('add', 'adds') and len(ops) >= 3:
        if ops[1] in state['adrp']:
            off = _imm(ops[2]) if ops[2].startswith('#') else None
            if isinstance(off, int):
                addr = state['adrp'].pop(ops[1]) + off
                return f'{ops[0]} = {_fmt(addr)};  /* data ref */', state
        b = ops[2].lstrip('#')
        extra = f' {ops[3]}' if len(ops) > 3 else ''
        return f'{ops[0]} = {ops[1]} + {b}{extra};', state

    if m in ('sub', 'subs') and len(ops) >= 3:
        if ops[0] == 'sp' and ops[1] == 'sp':
            sz = _imm(ops[2])
            if isinstance(sz, int): return f'sp -= {_fmt(sz)};  /* alloc {sz} bytes */', state
        b = ops[2].lstrip('#')
        return f'{ops[0]} = {ops[1]} - {b};', state

    if m == 'mul' and len(ops) == 3:   return f'{ops[0]} = {ops[1]} * {ops[2]};', state
    if m == 'madd' and len(ops) == 4:  return f'{ops[0]} = {ops[1]} * {ops[2]} + {ops[3]};', state
    if m == 'msub' and len(ops) == 4:  return f'{ops[0]} = {ops[3]} - {ops[1]} * {ops[2]};', state
    if m in ('sdiv','udiv') and len(ops) == 3: return f'{ops[0]} = {ops[1]} / {ops[2]};', state
    if m == 'neg' and len(ops) >= 2:   return f'{ops[0]} = -{ops[1]};', state

    # ── logical ──
    if m == 'and' and len(ops) >= 3:  return f'{ops[0]} = {ops[1]} & {ops[2].lstrip("#")};', state
    if m == 'orr' and len(ops) >= 3:
        if ops[1] in ('xzr','wzr'): return f'{ops[0]} = {ops[2]};', state
        return f'{ops[0]} = {ops[1]} | {ops[2].lstrip("#")};', state
    if m == 'eor' and len(ops) >= 3:  return f'{ops[0]} = {ops[1]} ^ {ops[2].lstrip("#")};', state
    if m == 'mvn' and len(ops) >= 2:  return f'{ops[0]} = ~{ops[1]};', state
    if m == 'orn' and len(ops) >= 3:  return f'{ops[0]} = {ops[1]} | ~{ops[2]};', state
    if m == 'bic' and len(ops) >= 3:  return f'{ops[0]} = {ops[1]} & ~{ops[2]};', state

    # ── shifts ──
    if m in ('lsl','lslv') and len(ops) == 3: return f'{ops[0]} = {ops[1]} << {ops[2].lstrip("#")};', state
    if m in ('lsr','lsrv') and len(ops) == 3: return f'{ops[0]} = {ops[1]} >> {ops[2].lstrip("#")};', state
    if m in ('asr','asrv') and len(ops) == 3:
        return f'{ops[0]} = (int64_t){ops[1]} >> {ops[2].lstrip("#")};', state

    # ── load ──
    if (m.startswith('ldr') or m.startswith('ldur')) and len(ops) >= 2 and ops[1].startswith('['):
        base, off = _parse_mem(ops[1])
        return f'{ops[0]} = {_mem(base, off, _typ(m, ops[0]))};', state
    if m.startswith('ldr') and len(ops) == 2:
        return f'{ops[0]} = {ops[1]};  /* literal */', state

    # ── store ──
    if (m.startswith('str') or m.startswith('stur')) and len(ops) >= 2 and ops[1].startswith('['):
        base, off = _parse_mem(ops[1])
        return f'{_mem(base, off, _typ(m, ops[0]))} = {ops[0]};', state

    # ── load pair ──
    if m == 'ldp' and len(ops) >= 3 and ops[2].startswith('['):
        base, off = _parse_mem(ops[2])
        t = _typ(m, ops[0]); w = 8 if ops[0].startswith('x') else 4
        return f'{ops[0]} = {_mem(base, off, t)}; {ops[1]} = {_mem(base, off+w, t)};', state

    # ── store pair ──
    if m == 'stp' and len(ops) >= 3 and ops[2].startswith('['):
        base, off = _parse_mem(ops[2])
        t = _typ(m, ops[0]); w = 8 if ops[0].startswith('x') else 4
        return f'{_mem(base, off, t)} = {ops[0]}; {_mem(base, off+w, t)} = {ops[1]};', state

    # ── address generation ──
    if m == 'adrp' and len(ops) >= 2:
        page = _imm(ops[1])
        if isinstance(page, int): state['adrp'][ops[0]] = page
        return f'{ops[0]} = {_fmt(page)};  /* page */', state
    if m == 'adr' and len(ops) >= 2:
        return f'{ops[0]} = {_fmt(_imm(ops[1]))};', state

    # ── conditional select ──
    if m == 'csel' and len(ops) >= 4:
        c = CONDS.get(ops[3], ops[3])
        if state['cmp']:
            a, b = state['cmp']
            return f'{ops[0]} = ({a} {c} {b}) ? {ops[1]} : {ops[2]};', state
        return f'{ops[0]} = ({ops[3]}) ? {ops[1]} : {ops[2]};', state
    if m == 'cset' and len(ops) >= 2:
        c = CONDS.get(ops[1], ops[1])
        if state['cmp']:
            a, b = state['cmp']
            return f'{ops[0]} = ({a} {c} {b});', state
        return f'{ops[0]} = ({ops[1]});', state
    if m == 'csinc' and len(ops) >= 4:
        c = CONDS.get(ops[3], ops[3])
        if state['cmp']:
            a, b = state['cmp']
            return f'{ops[0]} = ({a} {c} {b}) ? {ops[1]} : {ops[2]} + 1;', state
        return f'{ops[0]} = ({ops[3]}) ? {ops[1]} : {ops[2]} + 1;', state

    # ── extensions ──
    if m in ('sxtw','sxth','sxtb') and len(ops) >= 2:
        return f'{ops[0]} = (int64_t){ops[1]};', state
    if m in ('uxtw','uxth','uxtb') and len(ops) >= 2:
        return f'{ops[0]} = (uint64_t){ops[1]};', state

    # ── misc ──
    if m == 'mrs': return f'{ops[0]} = __mrs({ops[1]});', state
    if m == 'msr': return f'__msr({ops[0]}, {ops[1]});', state
    if m == 'clz': return f'{ops[0]} = __clz({ops[1]});', state
    if m == 'rev': return f'{ops[0]} = __bswap({ops[1]});', state

    # ── fallback ──
    return f'/* {m} {insn.op_str} */', state


def decompile(instructions, start, end):
    """decompile a function → list of C pseudocode strings"""
    insns = [i for i in instructions if start <= i.address < end]
    if not insns: return []

    # branch targets within function → become labels
    targets = set()
    for i in insns:
        m, ops = i.mnemonic, _ops(i.op_str)
        if m == 'b' or m.startswith('b.'):
            t = _imm(ops[0])
            if isinstance(t, int) and start <= t < end: targets.add(t)
        elif m in ('cbz','cbnz') and len(ops) >= 2:
            t = _imm(ops[1])
            if isinstance(t, int) and start <= t < end: targets.add(t)
        elif m in ('tbz','tbnz') and len(ops) >= 3:
            t = _imm(ops[2])
            if isinstance(t, int) and start <= t < end: targets.add(t)

    lines = [f'/* sub_{start:x} — {len(insns)} insns, {end-start} bytes */']
    state = {'cmp': None, 'adrp': {}}
    for i in insns:
        if i.address in targets:
            lines.append(f'loc_{i.address:x}:')
        line, state = decompile_insn(i, state)
        if line is not None:
            lines.append(f'    {line}')
    return lines


if __name__ == "__main__":
    nso = NSO(sys.argv[1])
    instructions = disassemble(nso.text)
    starts = find_functions(instructions)
    bounds = find_function_bounds(instructions, starts)

    if len(sys.argv) > 2:
        addr = int(sys.argv[2], 16)
        end = dict(bounds).get(addr)
        if end is None:
            print(f"function 0x{addr:x} not found"); sys.exit(1)
        for line in decompile(instructions, addr, end):
            print(line)
    else:
        for s, e in bounds[:5]:
            print(f"\n{'─'*60}")
            for line in decompile(instructions, s, e):
                print(line)
