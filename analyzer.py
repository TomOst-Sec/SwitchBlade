#!/usr/bin/env python3
"""M3: syscall scanner. finds every SVC in every Switch binary.
usage: python3 analyzer.py <file.nso>           — scan one binary
       python3 analyzer.py <dir/>               — scan all 74 binaries"""
import sys, os, glob
from loader import NSO
from syscalls import HORIZON_SYSCALLS
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def get_service_name(nso):
    """pull service name from .rodata — Nintendo embeds .nss filenames in every binary."""
    current = b''
    for b in nso.rodata:
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= 4:
                try:
                   s = current.decode()
                except:
                   current=b''
                   continue
                       
                if '.nss' in s and 'nnSdk' not in s:
                    # strip build paths: D:\home\jenkins\...\ssl.nss → ssl
                    s = s.split('\\')[-1].split('/')[-1]
                    return s.replace('.nss', '').rstrip('MOD0').rstrip()
            current = b''
    return None

def scan_syscalls(nso):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True
    results = []
    if not hasattr(nso, "text") or not nso.text:
        print("⚠️ Warning: Empty or missing .text section")
        return results
    for inst in md.disasm(nso.text, 0):
        if inst.mnemonic == "svc":
            num = int(inst.op_str.lstrip('#'), 16)
            name = HORIZON_SYSCALLS.get(num, f"unknown_0x{num:02x}")
            results.append((inst.address, num, name))
    return results

def target_value(name, syscalls):
    """rate 1-10 how valuable cracking this binary would be."""
    n = name.lower()
    svc_nums = {s[1] for s in syscalls}

    # 10 — unpatchable or total system compromise
    if 'boot2' in n or 'boot' in n:                          return 10  # bootloader bug = unpatchable, game over forever
    # 9 — remote code execution without user interaction
    if n in ('ssl', 'bsdsocket', 'wlan'):                    return 9   # network-facing, processes untrusted remote data
    # 8 — wireless/physical proximity attacks
    if n in ('bluetooth', 'nfc', 'ldn'):                      return 8   # no internet needed, proximity attack
    # 7 — browser / web engine (historically #1 exploit vector on every console)
    if 'web' in n:                                            return 7   # webkit = massive parser attack surface
    # 6 — DRM / entitlements (piracy = biggest bounty motivation)
    if n in ('es', 'ns'):                                     return 6   # crack DRM = free games
    # 5 — identity / auth (account takeover)
    if n in ('account', 'auth'):                              return 5
    # 4 — parser targets (fuzzing goldmine, memory corruption likely)
    if n in ('jpegdec', 'audio', 'capsrv', 'hid'):           return 4   # complex format parsing
    # 3 — GPU / display (kernel surface, hardware access)
    if n in ('nvservices', 'nvnflinger', 'vi'):               return 3
    # 2 — system services with dangerous syscalls
    if svc_nums & {0x48, 0x4E, 0x6A, 0x6B}:                  return 2   # MapUnsafe, ReadWriteRegister, ReadDebugMem, WriteDebugMem
    # 1 — everything else
    return 1



def print_report(name, syscalls):
    print(f"\n{name}: {len(syscalls)} syscalls")
    for addr, num, svc_name in syscalls:
        print(f"  {addr:08x}: SVC #0x{num:02x}  {svc_name}")



def print_summary(all_results):
    print(f"\n{'='*60}")
    print(f"SUMMARY: {len(all_results)} binaries scanned")
    print(f"{'='*60}")
    rated = [(name, syscalls, target_value(name, syscalls)) for name, syscalls in all_results]
    for name, syscalls, tv in sorted(rated, key=lambda x: (-x[2], -len(x[1]))):
        bar = "█" * tv + "░" * (10 - tv)
        print(f"  [{bar}] {tv:2d}/10  {len(syscalls):3d} svcs  {name}")




if __name__ == "__main__":
    path = sys.argv[1]
    if os.path.isdir(path):
        all_results = []
        for f in sorted(glob.glob(os.path.join(path, "*.nso"))):
            nso = NSO(f)
            syscalls = scan_syscalls(nso)
            name = get_service_name(nso) or os.path.basename(f)
            print_report(name, syscalls)
            all_results.append((name, syscalls))
        print_summary(all_results)
    else:
        nso = NSO(path)
        syscalls = scan_syscalls(nso)
        name = get_service_name(nso) or os.path.basename(path)
        print_report(name, syscalls)

