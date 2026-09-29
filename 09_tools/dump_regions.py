#!/usr/bin/env python3
"""Dump disassembly windows of interesting regions in unpacked dll2."""
import sys
from capstone import *

DLL = "/home/z/my-project/samples/carved/dll2/final_FULLIMAGE.bin"
IMAGE_BASE = 0x180000000

REGIONS = {
    "aimbot_status":   (0x180023300, 0x180023900),
    "matrix_xref":     (0x180026700, 0x180026a00),
    "ipc_dispatch_a":  (0x18002ab00, 0x18002ad00),
    "ipc_bullettrack": (0x18002ad00, 0x18002b500),
    "magic_bullet":    (0x18002b200, 0x18002b600),
    "remote_parse":    (0x18003dd00, 0x18003ee00),
    "defaults_a":      (0x18003f900, 0x180040200),
    "defaults_b":      (0x180040200, 0x180041200),
    "applied_msg":     (0x180034000, 0x180034300),
}

def read(va, size):
    data = open(DLL, "rb").read()
    off = va - IMAGE_BASE
    return data[off:off+size]

def main():
    which = sys.argv[1] if len(sys.argv) > 1 else None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    for name, (start, end) in REGIONS.items():
        if which and which != name:
            continue
        code = read(start, end-start)
        out = f"/home/z/my-project/logs/asm_{name}.txt"
        with open(out, "w") as f:
            f.write(f"; region {name} 0x{start:x}-0x{end:x}\n")
            for insn in md.disasm(code, start):
                f.write(f"0x{insn.address:012x}  {insn.mnemonic:8s} {insn.op_str}\n")
        print(f"[+] {name}: {end-start} bytes -> {out}")

if __name__ == "__main__":
    main()
