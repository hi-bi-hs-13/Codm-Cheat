#!/usr/bin/env python3
"""Parse .pdata RUNTIME_FUNCTION entries of the unpacked DLL2, map xref addresses to functions,
and dump disassembly of the interesting ones."""
import struct, sys
from capstone import *
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

DLL = "/home/z/my-project/samples/carved/dll2/final_FULLIMAGE.bin"
IMAGE_BASE = 0x180000000
PDATA_RVA, PDATA_SIZE = 0xdb000, 0x7aac

def load():
    data = open(DLL, "rb").read()
    funcs = []
    off = PDATA_RVA
    end = PDATA_RVA + PDATA_SIZE
    while off + 12 <= end:
        start_rva, end_rva, unw = struct.unpack("<III", data[off:off+12])
        if start_rva == 0 and end_rva == 0:
            break
        funcs.append((IMAGE_BASE + start_rva, IMAGE_BASE + end_rva))
        off += 12
    return data, funcs

def find_func(funcs, va):
    for s, e in funcs:
        if s <= va < e:
            return (s, e)
    return None

def main():
    data, funcs = load()
    print(f"[*] {len(funcs)} runtime functions")
    xrefs = [0x180023532, 0x180026842, 0x18002ac15, 0x18002ad49, 0x18002b2ed, 0x18002b34c,
             0x1800340e7, 0x18003dde6, 0x18003ecf1, 0x18003fac9, 0x18003faf3, 0x180040ec0, 0x180023614]
    for x in xrefs:
        f = find_func(funcs, x)
        print(f"  xref 0x{x:x} -> {'func 0x%x-0x%x (size %d)' % (f[0], f[1], f[1]-f[0]) if f else 'NO FUNCTION'}")

if __name__ == "__main__":
    main()
