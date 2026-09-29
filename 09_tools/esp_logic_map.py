#!/usr/bin/env python3
"""Map the unpacked cheat DLL (dll2) — find xrefs to ESP/BulletTrack/Aimbot/TypeInfo strings.

Strategy:
1. Parse PE section table of final_FULLIMAGE.bin (unpacked, sections restored in-place)
2. Scan .text for RIP-relative LEA/MOV references into the string zone in .rdata
3. Report which code addresses reference which strings → function boundaries
"""
import pefile, sys, re
from capstone import *
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

DLL = "/home/z/my-project/samples/carved/dll2/final_FULLIMAGE.bin"
IMAGE_BASE = 0x180000000

# target string VAs from logs/dll2_rdata_strings.txt (subset the user cares about)
TARGETS = {
    0x1800affa8: "aimPct=",
    0x1800b0000: "camera-ads",
    0x1800b0010: "camera-preaim+3p",
    0x1800b0028: "camera-preaim",
    0x1800b0080: "aiming=",
    0x1800b00b0: "hitGroup=",
    0x1800b0130: "track-v3.9.8 mode=shotspread-preaim-3p",
    0x1800b0174: "Matrix",
    0x1800b02d0: "EnableSkeleton",
    0x1800b02e0: "DisableSkeleton",
    0x1800b02f0: "EnableOutlineESP",
    0x1800b0318: "DisableOutlineESP",
    0x1800b0340: "EnableRadar",
    0x1800b0350: "DisableRadar",
    0x1800b0390: "EnableBulletTrack",
    0x1800b03b0: "BulletTrack enabled (CurrentFireComponent, shared AIM target/FOV)",
    0x1800b03f8: "DisableBulletTrack",
    0x1800b0410: "BulletTrack disabled (restore queued)",
    0x1800b0438: "SetBulletTrackTargetMode",
    0x1800b0458: "BulletTrack target mode = ",
    0x1800b0478: "SetBulletTrackActivationModel",
    0x1800b0498: "SetBulletTrackTriggerMode",
    0x1800b04b8: "SetBulletTrackKeyHeld",
    0x1800b04d0: "SetBulletTrackTargetPawn",
    0x1800b05c8: "EnableMagicBullet",
    0x1800b05e0: "DisableMagicBullet",
    0x1800b0608: "SetMagicBulletType",
    0x1800b09a0: "typeinfo_loadout_helper",
    0x1800b09b8: "typeinfo_item2inventory",
    0x1800b09d0: "typeinfo_character_model",
    0x1800b09f0: "typeinfo_item_resource",
    0x1800b0a08: "typeinfo_weapon",
    0x1800b0a18: "typeinfo_role_base_generic",
    0x1800b0a38: "typeinfo_role_pack_generic",
    0x1800b0a58: "typeinfo_item2inventory_generic",
    0x1800b0a78: "typeinfo_character_model_generic",
    0x1800b0aa0: "typeinfo_item_resource_generic",
    0x1800b0ac0: "typeinfo_weapon_generic",
    0x1800b0ad8: "typeinfo_role_generic",
    0x1800b0af0: "typeinfo_role_base_character",
    0x1800b0b10: "typeinfo_role",
    0x1800b0b20: "typeinfo_weapon_fire_component_instant",
    0x1800b0b48: "typeinfo_engine",
    0x1800b0b58: "typeinfo-v1|",
    0x1800b0b68: "typeinfo-v1",
    0x1800b0b88: "offsets_signature",
    0x1800b0f48: "[+] REMOTE TYPEINFO OFFSETS APPLIED",
    0x1800b0f70: "[*] REMOTE TYPEINFO OFFSETS UNAVAILABLE/INVALID; USING COMPILED DEFAULTS",
    0x1800ae878: "WeaponConfConfig.GenericTypeInfo",
    0x1800ae930: "RoleConfConfig.GenericTypeInfo",
    0x1800ae9e8: "RoleBaseCharacterConfig.GenericTypeInfo",
    0x1800b00f0: "fireMode=",
    0x1800b0100: "fireComp=0x",
    0x1800b0110: "weapon=0x",
    0x1800b0120: "targetPawn=0x",
}

def main():
    data = open(DLL, "rb").read()
    # Reconstruct a PE-parseable header: the FULLIMAGE is a memory image; find NT headers at 0
    pe = pefile.PE(data=data, fast_load=True)  # works because headers at offset 0
    print("[*] Sections:")
    sections = {}
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="replace")
        rva = s.VirtualAddress
        vsize = s.Misc_VirtualSize
        raw_off = s.PointerToRawData
        sections[name] = (rva, vsize, raw_off, s.SizeOfRawData)
        print(f"    {name:10s} RVA=0x{rva:08x} vsize=0x{vsize:x} raw=0x{raw_off:x} rawsz=0x{s.SizeOfRawData:x}")

    if ".text" not in sections:
        print("no .text?"); return
    # Memory image: file offset == RVA (headers zeroed PointerToRawData)
    t_rva, t_vsize, _, _ = sections[".text"]
    text = data[t_rva:t_rva+t_vsize]
    text_va = IMAGE_BASE + t_rva
    print(f"[*] .text bytes: {len(text)} from VA 0x{text_va:x}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # Scan for rip-relative memory operands
    hits = []  # (insn_va, target_va, mnemonic, op_str)
    for insn in md.disasm(text, text_va):
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = insn.address + insn.size + op.mem.disp
                # allow pointing anywhere within the string (past start for e.g. offsets)
                for tva, label in TARGETS.items():
                    if tva == tgt:
                        hits.append((insn.address, tgt, insn.mnemonic, insn.op_str))
                        break
    print(f"\n[*] .text scan: {len(hits)} xrefs to target strings\n")
    for va, tgt, mn, ops in hits:
        print(f"  0x{va:012x}  {mn:6s} {ops:40s}  ->  {TARGETS[tgt]!r} @0x{tgt:x}")

if __name__ == "__main__":
    main()
