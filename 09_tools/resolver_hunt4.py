import capstone, struct, os

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = os.path.join(HERE, "..", "04_dumps_dll_layer2", "final_FULLIMAGE.bin")
BASE = 0x180000000
img = open(DUMP, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False

tva, tvsz = 0x1000, 0xAB027
text = img[tva:tva+tvsz]

# scan every rip-relative reference into the globals window
def scan(window_lo, window_hi, label):
    print(f"=== rip-rel refs to {label} ===")
    found = []
    i = 0
    n = len(text)
    while i < n - 7:
        if text[i] in (0x48, 0x4C, 0x8B, 0x89) :
            # try 7-byte lea/mov rip-rel (REX 48/4C + op + modrm mod00 rm101)
            for oplen in (7,):
                op = text[i:i+oplen]
                if op[1] in (0x8D, 0x8B, 0x89, 0x3B, 0x39, 0x85, 0x83) or (op[0] in (0x48,0x4C) and op[1] in (0x8D,0x8B,0x89,0x39,0x3B)):
                    modrm = op[2]
                    if (modrm & 0xC7) == 0x05:
                        disp = struct.unpack("<i", op[3:7])[0]
                        tgt = BASE + tva + i + oplen + disp
                        if window_lo <= tgt <= window_hi:
                            found.append((BASE + tva + i, tgt, op[1]))
        i += 1
    for addr, tgt, opc in found:
        kind = {0x8D:"lea", 0x8B:"mov r<-[m]", 0x89:"mov m<-[r]", 0x39:"cmp m,r", 0x3B:"cmp r,m", 0x85:"test", 0x83:"grp"}.get(opc, hex(opc))
        print(f"  0x{addr:X}  {kind:10s} -> 0x{tgt:X}")
    return found

# typeinfo[0] (engine) and typeinfo[14] (firecomp) and the whole window
f0 = scan(0x1800D2458, 0x1800D2470, "typeinfo_engine global 0x1800D2460 (+/-8)")
f1 = scan(0x1800D2630, 0x1800D2648, "typeinfo[13/14] globals")
# dump context around every site found (30 instr back, 15 fwd)
def context(addr, back=0x60, fwd=0x40, out=None):
    start = addr - back
    out.write(f"\n----- context @ 0x{addr:X} -----\n")
    for ins in md.disasm(img[start-BASE:start-BASE+back+fwd], start):
        mark = "  <<<<" if ins.address == addr else ""
        out.write(f"  0x{ins.address:X}  {ins.mnemonic:<7s} {ins.op_str}{mark}\n")

OUT = os.path.join(HERE, "..", "01_reports", "RESOLVER_DISASM3.txt")
with open(OUT, "w", encoding="utf-8") as f:
    seen = set()
    for lst in (f0, f1):
        for addr, tgt, opc in lst:
            key = addr & ~0xF
            if key in seen: continue
            seen.add(key)
            context(addr, out=f)
print("\ncontexts written:", OUT)
