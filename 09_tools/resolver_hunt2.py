import capstone, struct, os

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = os.path.join(HERE, "..", "04_dumps_dll_layer2", "final_FULLIMAGE.bin")
BASE = 0x180000000
img = open(DUMP, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def read_va(va, n):
    return img[va-BASE: va-BASE+n]

def cstr(va, n=80):
    d = read_va(va, n)
    z = d.find(b"\x00")
    return d[:z if z >= 0 else n].decode("latin1")

def disas(start, length, out, label):
    out.write(f"\n===== {label} (0x{start:X} +0x{length:X}) =====\n")
    for ins in md.disasm(img[start-BASE:start-BASE+length], start):
        out.write(f"  0x{ins.address:X}  {ins.mnemonic:<8s} {ins.op_str}\n")

OUT = os.path.join(HERE, "..", "01_reports", "RESOLVER_DISASM2.txt")
with open(OUT, "w", encoding="utf-8") as f:
    # exact strings
    f.write("=== STRINGS ===\n")
    for va in (0x1800AE6F8, 0x1800AE710, 0x1800AE738, 0x1800AE7B8):
        f.write(f"  0x{va:X}: {cstr(va)!r}\n")
    # the zero/failure path of resolve_typeinfo 0x18002c330
    disas(0x18002C780, 0x300, f, "resolve_typeinfo ZERO-OFFSET path")
    # validator body
    disas(0x18002BB30, 0x120, f, "validator 0x18002bb30 (mode selector)")
    # memread helper used everywhere
    disas(0x18002A6A0, 0x60, f, "memread 0x18002a6a0")
print("written", OUT)
print()
for va in (0x1800AE6F8, 0x1800AE710, 0x1800AE738, 0x1800AE7B8):
    print(f"0x{va:X}: {cstr(va)!r}")
