import capstone, struct, os

HERE = os.path.dirname(os.path.abspath(__file__))
DUMP = os.path.join(HERE, "..", "04_dumps_dll_layer2", "final_FULLIMAGE.bin")
BASE = 0x180000000
img = open(DUMP, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def cstr(va, n=90):
    d = img[va-BASE: va-BASE+n]
    z = d.find(b"\x00")
    return d[:z if z >= 0 else n].decode("latin1")

print("=== extra strings ===")
for va in (0x1800AE5E0, 0x1800AE5F0, 0x1800AE6D8, 0x1800AE530,
           0x1800AE548, 0x1800AE570, 0x1800AE598, 0x1800AE5C0):
    print(f"  0x{va:X}: {cstr(va)!r}")

# ---- find writes to the typeinfo globals in the parser region ----
# parser starts at 0x18003f8f0 (ESP report). Globals 0x1800d2460..0x1800d2638.
# We disassemble a generous range and print every instruction whose op_str
# contains a rip-relative target in the globals window, plus surrounding
# test/cmp instructions.
print("\n=== parser: instructions touching typeinfo globals 0x1800d2460..0x1800d2640 ===")
start, length = 0x18003F8F0, 0x1200
for ins in md.disasm(img[start-BASE:start-BASE+length], start):
    txt = f"{ins.mnemonic} {ins.op_str}"
    if "rip +" in txt or "rip -" in txt:
        # compute target
        try:
            disp = int(ins.op_str.split("rip")[1].strip().rstrip("]").replace("+ ", "").replace("- ", "-"), 16)
        except Exception:
            continue
        tgt = ins.address + ins.size + disp
        if 0x1800D2460 <= tgt <= 0x1800D2640:
            print(f"  0x{ins.address:X}  {txt}    ; -> 0x{tgt:X}")
    elif ins.mnemonic in ("test", "cmp") and ("rbx" in ins.op_str or "rsi" in ins.op_str):
        pass  # noise filter
