#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
memtap.py — passive IPC-record tap for the CODM loader.
The DLL streams FrameStart -> Matrix -> player x N -> FrameEnd records
(0xBB0 bytes each) to the loader over 127.0.0.1:4042; the loader keeps the
latest frame in heap memory. This tool finds that buffer with plain
ReadProcessMemory (no injection, no debugger — VMP-safe) and dumps/parses it.

Usage (Administrator):
  python memtap.py [--loop SEC] [--exe test.exe]
Live test: server menu 1 -> cheat -> emulator bot-match -> run memtap here.
Output: memtap_<ts>.bin (raw frame) + summary printed (matrix + players).
"""
import ctypes
import json
import os
import struct
import sys
import time

K32 = ctypes.WinDLL("kernel32", use_last_error=True)
K32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
K32.OpenProcess.restype = ctypes.c_void_p
K32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
K32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_size_t]
K32.VirtualQueryEx.restype = ctypes.c_size_t

PROCESS_QR_VM = 0x0400 | 0x0010  # QUERY_INFORMATION | VM_READ
MEM_COMMIT, MEM_PRIVATE = 0x1000, 0x20000
REC = 0xBB0


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong)]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_wchar * 260)]


def find_pids(exe):
    K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    K32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    K32.Process32FirstW.argtypes = [ctypes.c_void_p,
                                    ctypes.POINTER(PROCESSENTRY32)]
    K32.Process32NextW.argtypes = [ctypes.c_void_p,
                                   ctypes.POINTER(PROCESSENTRY32)]
    out = []
    ss = K32.CreateToolhelp32Snapshot(0x2, 0)
    if ss == ctypes.c_void_p(-1).value:
        return out
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    ok = K32.Process32FirstW(ss, ctypes.byref(pe))
    while ok:
        if pe.szExeFile.lower() == exe.lower():
            out.append(pe.th32ProcessID)
        ok = K32.Process32NextW(ss, ctypes.byref(pe))
    K32.CloseHandle(ss)
    return out


def rpm(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    done = ctypes.c_size_t(0)
    if not K32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n,
                                 ctypes.byref(done)):
        return b""
    return buf.raw[:done.value]


def scan_frames(h, cap=8):
    """Return [(hit_addr, chunk_bytes)] for EVERY heap chunk with FrameStart.

    Returns the already-read chunk itself (never an empty re-read window).
    """
    out = []
    mbi = MEMORY_BASIC_INFORMATION64()
    addr = 0
    while addr < 0x7FFFFFFFFFFF and len(out) < cap:
        if K32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                              ctypes.sizeof(mbi)) == 0:
            break
        size = mbi.RegionSize
        if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                and 0x10000 <= size <= 0x4000000):
            base = mbi.BaseAddress
            step = 0x100000
            off = 0
            while off < size and len(out) < cap:
                n = min(step, size - off)
                chunk = rpm(h, base + off, n)
                if not chunk:
                    break
                i = chunk.find(b"FrameStart")
                if i >= 0:
                    # window around the hit, clamped to what we actually read
                    s = max(0, i - 0x8000)
                    e = min(len(chunk), i + 0x18000)
                    out.append((base + off + i, chunk[s:e]))
                    off += i + 0x18000
                    continue
                off += n
        addr = (mbi.BaseAddress or 0) + size
        if size == 0:
            break
    return out


def matrix_sane(m):
    import math
    if not m or len(m) != 16:
        return False
    if any(math.isnan(x) or math.isinf(x) or abs(x) > 1e6 for x in m):
        return False
    n0 = sum(x * x for x in m[0:3]) ** 0.5
    return 0.5 < n0 < 2.0  # rotation row ~unit length


def find_matrix(buf):
    """Search every 'Matrix' marker for a sane 16-float view matrix.

    Layout varies (marker + header?): try several candidate offsets and
    validate rotation-row norm instead of trusting a fixed offset."""
    import math
    cands = set()
    pos = 0
    while True:
        i = buf.find(b"Matrix", pos)
        if i < 0:
            break
        # +0xFC confirmed live (Matrix marker sits at rec+0x460,
        # 16 floats at rec+0x55C); keep generic fallbacks too.
        for off in (0xFC, 7, 8, 16, 64, 72):
            cands.add(i + off)
        pos = i + 6
    for c in sorted(cands):
        if c + 64 > len(buf):
            continue
        try:
            v = struct.unpack_from("<16f", buf, c)
        except Exception:
            continue
        if any(math.isnan(x) or math.isinf(x) or abs(x) > 1e6 for x in v):
            continue
        n0 = sum(x * x for x in v[0:3]) ** 0.5
        if 0.5 < n0 < 2.0:
            return [round(x, 4) for x in v], hex(c)
    return None, None


def parse_frame(buf, base):
    """Split raw frame into records; extract matrix floats + player rows."""
    out = {"base": hex(base), "matrix": None, "matrix_at": None,
           "players": []}
    m, at = find_matrix(buf)
    out["matrix"], out["matrix_at"] = m, at
    # record layout (prior RE): 0xBB0 bytes, marker "player" at +0x460,
    # u64 id at +0x4A0, float dist at +0x514, name near +0x1C8-style blob.
    pos = 0
    while True:
        i = buf.find(b"player", pos)
        if i < 0:
            break
        rs = i - 0x460  # record start
        if rs < 0 or rs + REC > len(buf):
            pos = i + 6
            continue
        rec = buf[rs:rs + REC]
        try:
            pid_ = struct.unpack_from("<Q", rec, 0x4A0)[0]
        except Exception:
            pid_ = None
        try:
            dist = struct.unpack_from("<f", rec, 0x514)[0]
        except Exception:
            dist = None
        name = b""
        # +0x51A confirmed live ("[BOT]..."), then generic fallbacks.
        for off in (0x51A, 0x467, 0x100, 0x200, 0x300):
            s = rec[off:off + 32].split(b"\x00")[0]
            if len(s) >= 3 and all(32 <= c < 127 for c in s):
                name = s
                break
        out["players"].append({"id": pid_, "dist": dist,
                               "name": name.decode("utf-8", "replace")})
        pos = i + REC
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", type=float, default=0,
                    help="repeat every N seconds (live watch)")
    ap.add_argument("--warmup", type=float, default=0,
                    help="sleep N seconds BEFORE the first capture (tab into "
                         "the match now — captures only count while focused)")
    ap.add_argument("--exe", default="test.exe")
    args = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))

    def once():
        pids = find_pids(args.exe)
        if not pids:
            print(f"[!] {args.exe} not running")
            return False
        h = K32.OpenProcess(PROCESS_QR_VM, False, pids[-1])
        if not h:
            print(f"[!] OpenProcess failed err={ctypes.get_last_error()} "
                  "(run as Administrator)")
            return False
        frames = scan_frames(h)
        K32.CloseHandle(h)
        if not frames:
            print("[.] no FrameStart buffer yet (inject first / join a match)")
            return False
        best, bestbuf = None, b""
        for hit, buf in frames:
            info = parse_frame(buf, hit)
            score = (1 if info["matrix"] else 0, len(info["players"]))
            if best is None or score > (1 if best["matrix"] else 0,
                                        len(best["players"])):
                best, bestbuf = info, buf
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(here, f"memtap_{ts}.bin")
        with open(path, "wb") as f:
            f.write(bestbuf)
        with open(os.path.join(here, f"memtap_{ts}.json"), "w",
                  encoding="utf-8") as f:
            json.dump(best, f, ensure_ascii=False, indent=1)
        m = best["matrix"]
        print(f"[+] {len(frames)} frame bufs, best @ {best['base']} -> "
              f"{os.path.basename(path)} | "
              f"matrix={'OK@' + str(best['matrix_at']) if m else 'MISSING'} "
              f"players={len(best['players'])}")
        if m:
            print("    row0:", m[0:4], " row3:", m[12:16])
        for p in best["players"][:8]:
            print(f"    player id={p['id']} dist={p['dist']} name={p['name']}")
        return True

    if args.warmup > 0:
        print(f"[*] warmup {args.warmup}s — tab INTO the match now, stay focused")
        time.sleep(args.warmup)
    once()
    if args.loop > 0:
        print(f"[*] looping every {args.loop}s — Ctrl+C to stop")
        try:
            while True:
                time.sleep(args.loop)
                once()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    sys.exit(main())
