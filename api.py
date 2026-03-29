#!/usr/bin/env python3
"""M5: FastAPI serving all 74 Switch services as JSON."""
import os, glob
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from loader import NSO
from analyzer import scan_syscalls, get_service_name, target_value
from cfg import disassemble, find_functions, find_function_bounds, build_cfg, find_xrefs

NSO_DIR = os.environ.get("NSO_DIR", "nso/")

DB = {}  # service_name → precomputed analysis


@asynccontextmanager
async def lifespan(app):
    load_all()
    yield

app = FastAPI(lifespan=lifespan)


def load_all():
    for f in sorted(glob.glob(os.path.join(NSO_DIR, "*.nso"))):
        nso = NSO(f)
        name = get_service_name(nso) or os.path.basename(f).replace(".nso", "")
        instructions = disassemble(nso.text)
        func_starts = find_functions(instructions)
        bounds = find_function_bounds(instructions, func_starts)
        syscalls = scan_syscalls(nso)
        xrefs = find_xrefs(instructions)
        tv = target_value(name, syscalls)
        DB[name] = {
            "name": name,
            "size": len(nso.text) + len(nso.rodata) + len(nso.data),
            "target_value": tv,
            "instructions": instructions,
            "functions": bounds,
            "func_map": dict(bounds),
            "syscalls": syscalls,
            "xrefs": xrefs,
        }
    print(f"loaded {len(DB)} services")


def get_service(name):
    if name not in DB:
        raise HTTPException(404, f"service '{name}' not found")
    return DB[name]



@app.get("/")
def index():
    return FileResponse("ui/index.html")


@app.get("/api/services")
def list_services():
    return [
        {
            "name": s["name"],
            "size": s["size"],
            "syscall_count": len(s["syscalls"]),
            "function_count": len(s["functions"]),
            "target_value": s["target_value"],
        }
        for s in DB.values()
    ]


@app.get("/api/services/{name}")
def service_detail(name: str):
    s = get_service(name)
    return {
        "name": s["name"],
        "size": s["size"],
        "functions": len(s["functions"]),
        "syscalls": len(s["syscalls"]),
        "target_value": s["target_value"],
    }


@app.get("/api/services/{name}/functions")
def service_functions(name: str):
    s = get_service(name)
    return [{"addr": f"0x{start:x}", "end": f"0x{end:x}", "size": end - start} for start, end in s["functions"]]


@app.get("/api/services/{name}/functions/{addr}/cfg")
def function_cfg(name: str, addr: str):
    s = get_service(name)
    start = int(addr, 16)
    end = s["func_map"].get(start)
    if end is None:
        raise HTTPException(404, f"function 0x{start:x} not found")
    cfg = build_cfg(s["instructions"], start, end)
    return {f"0x{a:x}": [f"0x{t:x}" for t in targets] for a, targets in cfg.items()}


@app.get("/api/services/{name}/functions/{addr}/disasm")
def function_disasm(name: str, addr: str):
    s = get_service(name)
    start = int(addr, 16)
    end = s["func_map"].get(start)
    if end is None:
        raise HTTPException(404, f"function 0x{start:x} not found")
    return [
        {"addr": f"0x{i.address:x}", "hex": i.bytes.hex(), "mnemonic": i.mnemonic, "operands": i.op_str}
        for i in s["instructions"]
        if start <= i.address < end
    ]


@app.get("/api/services/{name}/syscalls")
def service_syscalls(name: str):
    s = get_service(name)
    return [
        {"addr": f"0x{a:x}", "num": num, "name": svc_name}
        for a, num, svc_name in s["syscalls"]
    ]


@app.get("/api/services/{name}/xrefs")
def service_xrefs(name: str):
    s = get_service(name)
    return [{"from": f"0x{src:x}", "to": f"0x{dst:x}", "type": kind} for src, dst, kind in s["xrefs"]]
