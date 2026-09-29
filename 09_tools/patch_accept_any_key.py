#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Accept-Any-Key patch for CODM Loader (BestCheatIR).
Target: unpacked memory image (03_dumps_loader/unpacked_full_memory_image.bin,
        22,732,800 bytes, base 0x140000000, image offset = VA - 0x140000000).

Patch points (verified by disassembly, session 4):
  P1  VA 0x14006e201 (img off 0x6e201): 0F 84 3B 10 00 00  (JE fail) -> 6x NOP
      context: strcmp(code, "LOGIN_SUCCESS")#1 ; test al,al ; JE 0x14006f242
  P2  VA 0x14006e21d (img off 0x6e21d): 0F 84 1F 10 00 00  (JE fail) -> 6x NOP
      context: strcmp(...)#2 ; test al,al ; JE 0x14006f242
  P3  VA 0x14006e287 (img off 0x6e287): 0F 85 31 03 00 00  (JNE sig-ok) -> JMP sig-ok
      context: call 0x14006a360 (signature verify -> AL) ; test al,al ; JNE 0x14006e5be
      patch bytes: E9 32 03 00 00 90  (JMP rel32 0x332 + NOP)

Effect: any server response (even INVALID_KEY, even garbage JSON that parses)
flows to the LICENSE VERIFIED path. Offline (curl fail) still aborts earlier
at "curl_easy_perform failed"/"INVALID RESPONSE" — those live in still-encrypted
regions and are NOT patched here; use a fake HTTP server returning any JSON
with a "code" field, or patch after full unpack.

WARNING 1: do NOT apply to test.bin (packed) — bytes are encrypted there.
Apply at runtime after VMP unpacks .text (85% stage), or to the memory dump.
WARNING 2: VMP integrity hashes the file (NtCreateSection SEC_COMMIT +
byte-loop at 0x14146226c over headers). Patching test.bin on disk triggers
"File corrupted! ... Virus or cracked" (exit 0xDEADC0DE). Patch memory only,
after the Map/Unmap check, or disable that check first.
WARNING 3 (user-confirmed): cracked client gets NO remote typeinfo offsets
(server sends them only with LOGIN_SUCCESS) and falls back to compiled
defaults ("USING COMPILED DEFAULTS") — likely stale for current game build,
so the cheat is NOT actually usable. Proof-of-bypass only.
"""
import sys, os

PATCHES = [
    (0x6e201, bytes.fromhex("0f843b100000"), bytes.fromhex("909090909090")),
    (0x6e21d, bytes.fromhex("0f841f100000"), bytes.fromhex("909090909090")),
    (0x6e287, bytes.fromhex("0f8531030000"), bytes.fromhex("e93203000090")),
    # P4 (2026-09-21, live): response-HMAC compare in verify routine
    # (0x1400693d5 memcmp computed-vs-response-signature; jne -> r15b=0 fail).
    # NOP the jne so r15b=1 (match) is always taken. Context bytes:
    #   0x1400693dc 85c0 (test eax,eax) | 0x1400693de 7505 (jne +5) |
    #   0x1400693e0 41b701 (mov r15b,1) — returned as verify result.
    (0x693de, bytes.fromhex("7505"), bytes.fromhex("9090")),
    # P5 (2026-09-21, live): THE real gate — call 0x140068d80 (signature
    # verify; fetches response "signature" first thing) at 0x14006dc08,
    # tested at 0x14006dc0d, jne-success at 0x14006dc0f. Force JMP so the
    # whole "Invalid server signature" (0x14006dc70 block) is skipped.
    (0x6dc0f, bytes.fromhex("0f8506050000"), bytes.fromhex("e90705000090")),
]

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(here, "..", "03_dumps_loader", "unpacked_full_memory_image.bin")
    dst = os.path.join(here, "out", "patched_FULLIMAGE_accept_any_key.bin")
    data = bytearray(open(src, "rb").read())
    for off, expect, patch in PATCHES:
        actual = bytes(data[off:off + len(expect)])
        if actual != expect:
            print(f"FAIL at img off {hex(off)}: expected {expect.hex()}, found {actual.hex()}")
            print("Image differs from analyzed dump — aborting, no file written.")
            sys.exit(1)
    for off, expect, patch in PATCHES:
        data[off:off + len(patch)] = patch
        print(f"patched img off {hex(off)} (VA {hex(0x140000000 + off)}): {expect.hex()} -> {patch.hex()}")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    open(dst, "wb").write(data)
    print(f"WROTE {dst} ({len(data):,} bytes)")

if __name__ == "__main__":
    main()
