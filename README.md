<p align="center">
  <img src="logo.png" width="420" alt="SwitchBlade" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/%F0%9F%8E%AE_target-Nintendo%20Switch-e60012?style=for-the-badge&logoColor=white" />
  <img src="https://img.shields.io/badge/%F0%9F%94%A7_arch-AArch64-4361ee?style=for-the-badge" />
  <img src="https://img.shields.io/badge/%F0%9F%93%A6_firmware-20.1.5-10b981?style=for-the-badge" />
  <img src="https://img.shields.io/badge/%F0%9F%92%80_binaries-74%20services-f59e0b?style=for-the-badge" />
  <img src="https://img.shields.io/badge/%F0%9F%90%8D_python-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white" />
</p>

<h1 align="center">🗡️ SWITCHBLADE</h1>

<p align="center">
  <strong>A Nintendo Switch firmware reverse engineering platform built from scratch.</strong>
  <br />
  <em>🔓 74 ARM64 system binaries &bull; 📦 261MB of Nintendo's OS &bull; 🔍 Every secret is in the code.</em>
</p>

<p align="center">
  <a href="#-architecture">🏗️ Architecture</a> &bull;
  <a href="#-quick-start">🚀 Quick Start</a> &bull;
  <a href="#-modules">📦 Modules</a> &bull;
  <a href="#-high-value-targets">🎯 Targets</a> &bull;
  <a href="#-roadmap">🗺️ Roadmap</a> &bull;
  <a href="#-philosophy">💡 Philosophy</a>
</p>

---

## 🔍 What is this?

A **purpose-built reverse engineering platform** for one target: the Nintendo Switch firmware.

It's not a plugin for Ghidra. It's not a wrapper around Capstone. Every component — the NSO parser, the AArch64 decoder, the syscall labeler, the firmware diff engine — is built from scratch to find vulnerabilities in Nintendo's code.

```
🔒 encrypted .nca firmware
       |
       v  🔑 (hactool + prod.keys)
🔓 decrypted .nso binaries
       |
       v  🗡️ (switchblade)
💀 disassembled + analyzed + vulnerability-scanned
```

## ⚔️ Why not just use Ghidra?

| | 🦖 Ghidra | 🗡️ Switchblade |
|---|---|---|
| 📂 Load an NSO | Manual setup, no Switch context | One command, auto-detected |
| 🏷️ Syscall labels | Generic SVC numbers | Named Horizon OS calls (`svcSendSyncRequest`, `svcConnectToNamedPort`...) |
| 🔗 IPC tracing | Nothing | Maps inter-service communication across all 74 binaries |
| 🔄 Firmware diffing | Load two files manually, diff by hand | One command: show what Nintendo patched |
| 🗂️ Browse services | Open 74 files one at a time | Service browser — click ssl, nfc, bluetooth, explore |
| 🤖 Vuln scanning | Manual analysis | AI-powered pattern detection across entire firmware |
| ⏱️ Setup time | Download 500MB, configure, learn the UI | `python3 switchblade.py ssl.nso` |

---

## 🏗️ Architecture

```
📄 .nso file ──▶ LOADER ──▶ raw bytes ──▶ DECODER ──▶ instructions ──▶ ANALYZER ──▶ functions ──▶ API ──▶ UI
                                                            |
                                                            ▼
                                                      🤖 VULN SCANNER
                                                      🔄 DIFF ENGINE

 6 components. each one is a standalone python file.
 each one works by itself. each one you can test from the command line.
 no frameworks. no dependencies. simple enough to hold in your head.
```

```
🗡️ switchblade/
  📄 loader.py       ◀── M1: parse NSO header, extract .text/.rodata/.data
  📄 decoder.py      ◀── M2: 4 bytes ──▶ ARM64 instruction
  📄 analyzer.py     ◀── M3: find syscalls, label with Horizon OS names, rank targets
  📄 cfg.py          ◀── M4: function discovery, CFG, cross-references
  📄 api.py          ◀── M5: FastAPI serving JSON
  📄 diff.py         ◀── M7: diff two firmware versions
  📄 scanner.py      ◀── M8: pattern + AI vuln scanner
  📄 decompiler.py   ◀── M9: ARM64 ──▶ C pseudocode
  📁 ui/
    📄 index.html    ◀── M6: three-panel layout
    📄 app.js        ◀── M6: fetch API, render disasm + CFG
```

---

## 🚀 Quick Start

### Parse a Switch binary

```bash
python3 loader.py /path/to/ssl.nso
```

```
b'NSO0'  version=0  flags=56
  compressed: text=0 rodata=0 data=0
.text:      2459492 bytes  mem=0x0
.rodata:     757936 bytes  mem=0x259000
.data:       118168 bytes  mem=0x313000
============================================================
  00000000  03 00 00 14 18 90 25 00 4c 90 25 00 1f 00 00 f1  ......%.L.%.....
  00000010  01 04 00 54 f3 03 01 2a 60 19 00 f0 00 80 36 91  ...T...*`.....6.
  00000020  e2 59 00 b0 42 40 08 91 42 00 00 cb 01 00 80 52  .Y..B@..B......R
  00000030  d0 41 09 94 60 fe ff 10 41 19 00 b0 21 20 03 91  .A..`...A...! ..
```

> 🔬 That's real Nintendo ARM64 machine code from the Switch's SSL/TLS service.

### Analyze functions and control flow

```bash
python3 cfg.py /path/to/ssl.nso
```

```
found 7118 functions
function at 0x100 - 0x150 (size 80 bytes)
function at 0x150 - 0x4e0 (size 912 bytes)
...
CFG for function at 0x100:
  0x110 -> 0x114
  0x118 -> 0x134, 0x11c
  0x130 -> 0x4ab0
  0x140 ->

xrefs: 45043 calls, 5885 data refs
```

### Scan syscalls across all binaries

```bash
python3 analyzer.py /path/to/nso_directory/
```

### Launch the web UI

Requires extracted `.nso` files (use [hactool](https://github.com/SciresM/hactool) + prod.keys to extract from firmware `.nca` files).

```bash
pip install fastapi uvicorn capstone
```

```bash
NSO_DIR="/path/to/your/extracted/nsos" uvicorn api:app --reload
```

Then open `http://localhost:8000` in your browser. First load takes a few minutes — it disassembles all 74 binaries (~261MB). Once you see `loaded 74 services` in the terminal, the UI is ready.

### 📚 Use as a library

```python
from loader import NSO

nso = NSO("ssl.nso")
nso.text      # 💻 raw ARM64 code bytes (2.4MB)
nso.rodata    # 📝 string constants, lookup tables
nso.data      # 📊 global variables
nso.hexdump("text", 0, 128)  # 🔍 hex dump any section
```

---

## 🎯 High-Value Targets

> 74 system services extracted from Nintendo Switch firmware 20.1.5. Sorted by attack value.

### 🔴 Tier 1 — Network + Crypto (Remote Attack Surface)

| Service | Size | What It Does | Why It Matters |
|---------|------|-------------|----------------|
| 🔐 **ssl** | 3.3MB | TLS/SSL cryptographic stack | Every encrypted connection. MitM on all Switches. |
| 🌐 **bsdsocket** | 1.6MB | BSD socket network stack | Buffer overflow = remote code execution |
| 📡 **bluetooth** | 1.4MB | Bluetooth stack | Wireless proximity attack. No internet needed. |
| 📱 **nfc** | 1MB | NFC / Amiibo handler | Malformed NFC tag = exploit via physical access |
| 📶 **wlan** | 2.1MB | WiFi driver | Processes untrusted wireless frames |

### 🟠 Tier 2 — System Security

| Service | Size | What It Does | Why It Matters |
|---------|------|-------------|----------------|
| 🛒 **es** | 1MB | eShop / entitlement system | Game DRM. Crack this = free games. |
| 💀 **boot2.ProdBoot** | 184KB | Second-stage bootloader | **The holy grail.** Bug here = potentially unpatchable. |
| 👤 **account** | 2.3MB | Nintendo account system | Auth tokens, identity |
| ⚙️ **ns** | 3.9MB | Nintendo services core | App management, permissions |

### 🟡 Tier 3 — Parser Targets (Fuzzing Goldmine)

| Service | Size | What It Does |
|---------|------|-------------|
| 🖼️ **jpegdec** | 340KB | JPEG decoder. Malformed image = memory corruption. |
| 🎮 **hid** | 2.2MB | Controller input. Malformed USB/BT input = crash. |
| 🔊 **audio** | 1.6MB | Audio processing. Complex format parsing. |
| 📸 **capsrv** | 676KB | Screenshot service. Image parser bugs. |

### 🟢 Tier 4 — Largest Attack Surface

| Service | Size | What It Does |
|---------|------|-------------|
| 🏠 **qlaunch** | 18.9MB | Home menu. Biggest binary. |
| 🌍 **LibAppletWeb** | 12.3MB | Web browser. Historically #1 console exploit vector. |
| 🛍️ **LibAppletShop** | 12.3MB | eShop. Same web engine. |
| ❌ **error** | 11.8MB | Error display. Surprisingly large. |

---

## 📦 Modules

| | Module | File | Status | What It Does |
|---|--------|------|--------|-------------|
| 📂 | **M1: Loader** | `loader.py` | ✅ Done | Parse NSO header, extract .text/.rodata/.data sections |
| 🔬 | **M2: Decoder** | `decoder.py` | ✅ Done | 4 bytes -> ARM64 assembly instruction (hand-built + Capstone) |
| 📡 | **M3: Syscalls** | `analyzer.py` | ✅ Done | Find all SVC instructions, label with Horizon OS names, rank targets 1-10 |
| 🧠 | **M4: Analyzer** | `cfg.py` | ✅ Done | Discover functions, build control flow graphs, xrefs |
| 🌐 | **M5: API** | `api.py` | ✅ Done | FastAPI serving all 74 services as JSON |
| 🎨 | **M6: UI** | `ui/index.html` | ✅ Done | Web-based service browser, disasm view, CFG renderer |
| 🔄 | **M7: Diff** | `diff.py` | ⬜ Todo | Compare firmware versions, find patched functions |
| 🤖 | **M8: Scanner** | `scanner.py` | ⬜ Todo | AI-powered vulnerability pattern detection |
| 📝 | **M9: Decompiler** | `decompiler.py` | ⬜ Todo | ARM64 -> C pseudocode |

---

## 🗺️ Roadmap

```
✅ M1  LOADER         "i can open any Switch binary and see its guts"
✅ M2  DECODER        "i can read ARM64 machine code as assembly"
✅ M3  SYSCALLS       "i know every kernel call in every binary"
✅ M4  ANALYZER       "i can find every function and trace its control flow"
✅ M5  API + BROWSER  "i can explore all 74 services in my browser"
✅ M6  UI + GRAPH     "i can see function graphs and navigate visually"
⬜ M7  DIFF ENGINE    "i can see what Nintendo patched between versions"
⬜ M8  VULN SCANNER   "AI flags suspicious functions across all binaries"
⬜ M9  DECOMPILER     "i can read ARM64 as C code"
⬜ M10 SHIP           "the tool is packaged and ready"
```

---

## 💀 The Vulnerability Research Pipeline

```
  🔓 STEP 1: EXTRACT
  .nca (encrypted) ──▶ hactool + prod.keys ──▶ .nso (ARM64 binaries)

  🔬 STEP 2: ANALYZE
  .nso ──▶ switchblade ──▶ functions, syscalls, CFG, xrefs

  🎯 STEP 3: HUNT
  strategy: follow untrusted input through the code

  🌐 network packets  ──▶ ssl, bsdsocket
  📡 wireless frames  ──▶ bluetooth, wlan
  📱 NFC tags         ──▶ nfc
  🎮 USB devices      ──▶ hid
  🌍 web content      ──▶ LibAppletWeb
  🖼️ images           ──▶ jpegdec, capsrv

  🔄 STEP 4: DIFF
  firmware 20.1.5 vs 20.2.0 ──▶ what did Nintendo patch?
  patches reveal what was broken. broken = exploitable on older versions.

  📋 STEP 5: REPORT
  find bug ──▶ write report ──▶ responsible disclosure 
```

---

## 🔎 Vulnerability Patterns to Hunt

| | Pattern | What to Look For | Impact |
|---|---------|-----------------|--------|
| 💥 | **Unchecked memcpy** | Size from user input without bounds check | Buffer overflow -> code execution |
| 🔢 | **Integer overflow** | `size * count` wrapping to small value | Heap overflow |
| 📝 | **Format string** | User data passed to printf-like functions | Arbitrary read/write |
| 👻 | **Use-after-free** | Object freed then accessed via stale pointer | Code execution |
| 🔓 | **Missing IPC validation** | Command handler trusts sizes from IPC message | Privilege escalation |
| 🎭 | **Type confusion** | Casting based on attacker-controlled field | Fake vtable -> code execution |
| 1️⃣ | **Off-by-one** | `<=` instead of `<` in bounds check | Corrupt adjacent data |

---

## 💡 Philosophy

This project follows a simple doctrine:

- 🎯 **Build what you need.** This isn't a general-purpose RE framework. It's a weapon aimed at one target.
- 🚀 **Ship fast, iterate later.** A working prototype beats a perfect plan.
- 🧘 **Simplicity over features.** Every file is standalone. Every function fits in your head.
- 🚫 **No frameworks when functions will do.** Pure Python. No magic.
- 🧠 **The hard part is the learning.** The decoder is hand-written, not Capstone. Understanding > convenience.
- 🔍 **Follow untrusted input.** Every vulnerability starts where the system touches data it doesn't control.

---

## 📊 Extracted Firmware Stats

```
🎮 Target:     Nintendo Switch Firmware 20.1.5
📦 Services:   74 ARM64 system binaries
💾 Total size: 261 MB of decompressed machine code
🔧 Arch:       AArch64 (ARMv8-A, 64-bit)
📄 Format:     NSO (Nintendo Switch Object)
🔑 Extracted:  hactool + prod.keys
```

---

## 📚 References

| | Resource | Description |
|---|----------|-------------|
| 📄 | [NSO Format Specification](https://switchbrew.org/wiki/NSO) | Header layout we parse in loader.py |
| 📡 | [Switch Syscalls](https://switchbrew.org/wiki/SVC) | Horizon OS kernel calls |
| 📖 | [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest/) | AArch64 instruction encoding |
| 🔑 | [hactool](https://github.com/SciresM/hactool) | NCA decryption tool |
| 🌐 | [Atmosphere-NX](https://github.com/Atmosphere-NX/Atmosphere) | Switch custom firmware (OS internals reference) |


---

## ⚠️ Disclaimer

This project is built strictly for **educational and security research purposes**. It is intended to help learn ARM64 reverse engineering, binary analysis, and vulnerability research methodology.

- This tool does not enable piracy, does not bypass DRM, and does not modify console firmware
- Any vulnerabilities discovered should be reported through **responsible disclosure** to Nintendo
- The author assumes no liability for misuse of this tool or any information derived from it
- You are solely responsible for ensuring your use complies with all applicable laws and regulations
