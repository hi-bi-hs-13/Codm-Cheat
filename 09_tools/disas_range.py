#!/usr/bin/env python3
"""Disassemble an RVA range of the unpacked loader image with RIP-target literal resolution."""
import re
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = 0x140000000


def s_at(data, va, n=28):
    raw = data[va - BASE:va - BASE + n]
    t = raw.split(b"\x00")[0]
    try:
        return t.decode()
    except Exception:
        return repr(t[:16])


def main():
    img = sys.argv[1] if len(sys.argv) > 1 else "03_dumps_loader/unpacked_full_memory_image.bin"
    rva = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x6903C
    size = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x700
    data = open(img, "rb").read()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    code = data[rva:rva + size]
    for ins in md.disasm(code, BASE + rva):
        line = f"{hex(ins.address)} {ins.bytes.hex().ljust(22)} {ins.mnemonic} {ins.op_str}"
        if "rip" in ins.op_str:
            m = re.search(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)", ins.op_str)
            if m:
                disp = int(m.group(2), 0)
                tgt = ins.address + ins.size + disp if m.group(1) == "+" else ins.address + ins.size - disp
                if BASE <= tgt < BASE + len(data):
                    line += f'   ; -> [{hex(tgt)}] "{s_at(data, tgt)}"'
        print(line)
        if ins.address >= BASE + rva + size - 0x40:
            break


if __name__ == "__main__":
    main()
