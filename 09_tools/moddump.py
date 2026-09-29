#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
moddump.py — dump a loaded module (e.g. decrypted ext.dll) from a live
process with plain ReadProcessMemory. No injection, VMP-safe.
Usage: python moddump.py --exe MuMuNxDevice.exe --mod ext.dll
Output: <mod>_mem_<ts>.dll next to this script.
"""
import argparse
import ctypes
import os
import time

K32 = ctypes.WinDLL("kernel32", use_last_error=True)
K32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
K32.OpenProcess.restype = ctypes.c_void_p
K32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
PROCESS_QR_VM = 0x0400 | 0x0010


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("GlblcntUsage", ctypes.c_ulong),
                ("ProccntUsage", ctypes.c_ulong),
                ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", ctypes.c_ulong),
                ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260)]


def find_module(pid, mod):
    K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    K32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    K32.Module32FirstW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    K32.Module32NextW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    ss = K32.CreateToolhelp32Snapshot(0x8, pid)  # TH32CS_SNAPMODULE
    if ss == ctypes.c_void_p(-1).value:
        return None, 0
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(me)
    ok = K32.Module32FirstW(ss, ctypes.byref(me))
    base, size = None, 0
    while ok:
        if me.szModule.lower() == mod.lower():
            base, size = me.modBaseAddr, me.modBaseSize
            break
        ok = K32.Module32NextW(ss, ctypes.byref(me))
    K32.CloseHandle(ss)
    return base, size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default="MuMuNxDevice.exe")
    ap.add_argument("--mod", default="ext.dll")
    ap.add_argument("--pid", type=int, default=0)
    args = ap.parse_args()

    pid = args.pid
    if not pid:
        K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        K32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong,
                                                 ctypes.c_ulong]

        class PE32(ctypes.Structure):
            _fields_ = [("dwSize", ctypes.c_ulong),
                        ("cntUsage", ctypes.c_ulong),
                        ("th32ProcessID", ctypes.c_ulong),
                        ("th32DefaultHeapID", ctypes.c_void_p),
                        ("th32ModuleID", ctypes.c_ulong),
                        ("cntThreads", ctypes.c_ulong),
                        ("th32ParentProcessID", ctypes.c_ulong),
                        ("pcPriClassBase", ctypes.c_long),
                        ("dwFlags", ctypes.c_ulong),
                        ("szExeFile", ctypes.c_wchar * 260)]

        ss = K32.CreateToolhelp32Snapshot(0x2, 0)
        pe = PE32()
        pe.dwSize = ctypes.sizeof(pe)
        K32.Process32FirstW.argtypes = [ctypes.c_void_p,
                                        ctypes.POINTER(PE32)]
        K32.Process32NextW.argtypes = [ctypes.c_void_p,
                                       ctypes.POINTER(PE32)]
        ok = K32.Process32FirstW(ss, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.lower() == args.exe.lower():
                pid = pe.th32ProcessID
                break
            ok = K32.Process32NextW(ss, ctypes.byref(pe))
        K32.CloseHandle(ss)
    if not pid:
        print(f"[!] {args.exe} not running")
        return 2
    base, size = find_module(pid, args.mod)
    if not base:
        print(f"[!] {args.mod} not loaded in pid {pid}")
        return 2
    print(f"[*] {args.mod} @ {hex(base)} size {hex(size)} (pid {pid})")
    h = K32.OpenProcess(PROCESS_QR_VM, False, pid)
    if not h:
        print(f"[!] OpenProcess err={ctypes.get_last_error()}")
        return 2
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(
        here, f"{os.path.splitext(args.mod)[0]}_mem_"
        f"{time.strftime('%Y%m%d_%H%M%S')}.dll")
    got = 0
    with open(out, "wb") as f:
        while got < size:
            n = min(0x100000, size - got)
            buf = ctypes.create_string_buffer(n)
            done = ctypes.c_size_t(0)
            if not K32.ReadProcessMemory(h, ctypes.c_void_p(base + got),
                                         buf, n, ctypes.byref(done)) \
                    or not done.value:
                print(f"[!] short read at {hex(base + got)}")
                break
            f.write(buf.raw[:done.value])
            got += done.value
    K32.CloseHandle(h)
    print(f"[+] wrote {out} ({got}/{size} bytes)")
    return 0 if got == size else 1


if __name__ == "__main__":
    raise SystemExit(main())
