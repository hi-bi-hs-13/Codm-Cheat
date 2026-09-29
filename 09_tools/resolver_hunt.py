#!/usr/bin/env python3
"""resolver_hunt.py — find & disassemble the ext.dll LOCAL typeinfo resolver.

Target: how does the DLL resolve TypeInfo/classes when the server sends 0x0
for every typeinfo offset? Entry points from prior analysis (ESP logic report):
  - validator 0x18002bb30, resolver 0x18002c438
  - strings: "ok via direct TypeInfo", "ok via legacy TypeInfo holder",
    "ok via generic TypeInfo"
Input: 04_dumps_dll_layer2/final_FULLIMAGE.bin (unpacked DLL, base 0x180000000)
"""
import capstone, pefile, struct, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = os.path.join(HERE, "..", "04_dumps_dll_layer2", "final_FULLIMAGE.bin")
BASE = 0x180000000

pe = pefile.PE(DUMP, fast_load=True)
img = bytearray(open(DUMP, "rb").read())
print(f"image size 0x{len(img):X}  base 0x{BASE:X}  sections:")
secs = []
for s in pe.sections:
    name = s.Name.rstrip(b"\x00").decode(errors="replace")
    va, vsz, raw, rawsz = s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData
    secs.append((name, va, vsz, raw, rawsz))
    print(f"  {name:8s} VA=0x{BASE+va:08X} vsize=0x{vsz:X} raw@0x{raw:X} rawsz=0x{rawsz:X}")

def va2off(va):
    # this dump is a linear memory image: file offset == RVA
    rva = va - BASE
    return rva if 0 <= rva < len(img) else None

def va_of_off(off):
    return BASE + off

def read_va(va, n):
    off = va2off(va)
    return bytes(img[off:off+n]) if off is not None and off + n <= len(img) else None

# ---- 1. find the decision strings in .rdata ----
NEEDLES = [b"ok via direct TypeInfo", b"ok via legacy TypeInfo holder",
           b"ok via generic TypeInfo", b"TypeInfo", b"typeinfo"]
hits = {}
low = bytes(img).lower()
for needle in [b"ok via direct typeinfo", b"ok via legacy typeinfo holder", b"ok via generic typeinfo"]:
    start = 0
    while True:
        i = low.find(needle, start)
        if i < 0: break
        hits.setdefault(needle.decode(), []).append(i)
        start = i + 1
print("\n--- string hits (file offsets) ---")
for k, v in hits.items():
    for off in v[:6]:
        print(f"  off 0x{off:X}")

# ---- 2. find LEA rip-relative references to those strings in .text ----
def va_of_off(off):
    return BASE + off  # linear memory image

print("\n--- code refs (lea reg,[rip+disp]) to these strings ---")
tva, tvsz = 0x1000, 0xAB027  # .text RVA/vsize (raw==rva in this image)
text_bytes = bytes(img[tva:tva+tvsz])
targets = {}
for k, offs in hits.items():
    for off in offs:
        va = va_of_off(off)
        if va: targets[va] = k

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False
refs = []
i = 0
n = len(text_bytes)
# scan for LEA opcodes 48 8D xx (ModRM mod=00 rm=101 => rip-relative)
while i < n - 7:
    if text_bytes[i] == 0x48 and text_bytes[i+1] == 0x8D and (text_bytes[i+2] & 0xC7) == 0x05:
        disp = struct.unpack("<i", text_bytes[i+3:i+7])[0]
        rip = BASE + tva + i + 7
        tgt = rip + disp
        if tgt in targets:
            refs.append((rip, tgt))
    i += 1
print(f"  found {len(refs)} references")
for rip, tgt in refs[:12]:
    print(f"    code 0x{rip:X} -> string 0x{tgt:X} ('{targets[tgt][:28]}...')")

# ---- 3. disassemble around each ref site (function start unknown: walk back) ----
OUT = os.path.join(HERE, "..", "01_reports", "RESOLVER_DISASM.txt")
with open(OUT, "w", encoding="utf-8") as f:
    def disas(center, label, back=0x120, fwd=0x200):
        off = va2off(center) - back
        data = bytes(img[off:off+back+fwd])
        f.write(f"\n===== {label} around 0x{center:X} =====\n")
        for ins in md.disasm(data, center - back):
            marker = ""
            if any(abs(ins.address - r[0]) < 8 for r in refs):
                marker = "   <== REF"
            f.write(f"  0x{ins.address:X}  {ins.mnemonic:<8s} {ins.op_str}{marker}\n")
    for rip, tgt in refs[:4]:
        disas(rip, f"ref site -> '{targets[tgt][:30]}'")
    # the two known functions
    disas(0x18002c438, "resolver 0x18002c438", back=0x0, fwd=0x400)
    disas(0x18002bb30, "validator 0x18002bb30", back=0x0, fwd=0x200)
print(f"\ndisassembly written to {OUT}")
