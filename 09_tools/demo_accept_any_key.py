#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demo: accept-any-key patch tested on REAL bytes with a random key scenario.

What it does (no real execution of the cheat, pure Unicorn emulation):
  1. Maps the unpacked loader image (original AND patched) at 0x140000000.
  2. Simulates what the server returns for a RANDOM key: code="INVALID_KEY"
     (built as a real MSVC std::string with SSO, like the real JSON parser does).
  3. Emulates the REAL check sequence at 0x14006e1eb:
        lea rdx,[LOGIN_SUCCESS] ; lea rcx,[rsp+0x360] ; call strcmp#0x140077510
        test al,al ; je fail(0x14006f242)
     The nested strcmp runs the REAL bytes (length-mismatch fast path,
     no encrypted regions touched).
  4. Shows: ORIGINAL lands in fail (0x14006f242), PATCHED falls through
     to the next check (0x14006e207) => any key accepted.

Usage:
  python demo_accept_any_key.py [RANDOM_KEY]
  (the key itself is not embedded — any string demonstrates rejection-turned-acceptance)
"""
import os, struct, sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
ORIG = os.path.join(HERE, "..", "03_dumps_loader", "unpacked_full_memory_image.bin")
PATCHED = os.path.join(HERE, "out", "patched_FULLIMAGE_accept_any_key.bin")
BASE = 0x140000000
STACK = 0x7FF000000000
STACK_SZ = 0x400000


def make_string_blob(s: bytes) -> bytes:
    """MSVC std::string SSO layout (size < 16): inline buf + size + capacity."""
    assert len(s) < 16
    b = bytearray(0x20)
    b[0:len(s)] = s
    struct.pack_into("<Q", b, 0x10, len(s))   # size
    struct.pack_into("<Q", b, 0x18, 15)       # capacity (<16 => SSO)
    return bytes(b)


def run(image_path: str, server_code: bytes) -> int:
    data = open(image_path, "rb").read()
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(BASE, (len(data) + 0xFFF) & ~0xFFF, 7)
    # chunked write (22MB in one go can fail on some builds)
    for o in range(0, len(data), 0x100000):
        mu.mem_write(BASE + o, data[o:o + 0x100000])
    mu.mem_map(STACK, STACK_SZ, 7)
    rsp = STACK + STACK_SZ - 0x2000
    # fake server "code" field as std::string at [rsp+0x360]
    mu.mem_write(rsp + 0x360, make_string_blob(server_code))
    mu.mem_write(rsp + 0x258, make_string_blob(server_code))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RBP, 0)
    # stop exactly at either branch target: fall-through (patched) or fail (original)
    stops = {0x14006E207, 0x14006F242}

    def _hook(mu_, address, size, _ud):
        if address in stops:
            mu_.emu_stop()

    mu.hook_add(UC_HOOK_CODE, _hook, begin=0x14006E1EB, end=0x14006F250)
    try:
        mu.emu_start(0x14006E1EB, 0x14006F250, 2000, 0)
    except Exception:
        pass
    return mu.reg_read(UC_X86_REG_RIP)


def main():
    key = sys.argv[1] if len(sys.argv) > 1 else "A1B2-C3D4-RANDOM-KEY"
    print(f"random key under test : {key}")
    print("server would answer : code=\"INVALID_KEY\"  (any non-success code)")
    print()
    rip_orig = run(ORIG, b"INVALID_KEY")
    print(f"ORIGINAL image : check-1 ends at RIP={hex(rip_orig)}", end=" ")
    print("=> FAIL path (0x14006f242), key rejected" if rip_orig == 0x14006F242 else "=> unexpected")
    rip_patch = run(PATCHED, b"INVALID_KEY")
    print(f"PATCHED image  : check-1 ends at RIP={hex(rip_patch)}", end=" ")
    print("=> FALLS THROUGH (0x14006e207), key accepted" if rip_patch == 0x14006E207 else "=> unexpected")
    print()
    if rip_orig == 0x14006F242 and rip_patch == 0x14006E207:
        print("RESULT: patch converts REJECT into ACCEPT on real bytes. OK to record.")
    else:
        print("RESULT: unexpected RIPs — do not record, investigate first.")
        sys.exit(1)


if __name__ == "__main__":
    main()
