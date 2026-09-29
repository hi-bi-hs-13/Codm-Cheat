#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
handle_enum.py — list named kernel handles (Section/Event/Mutant/ALPC/File)
of the cheat + emulator processes to identify their IPC channel.
Usage (Administrator): python handle_enum.py [pid1 pid2 ...]
Default PIDs: PBC loader + MuMuNxDevice auto-detected by exe name.
Shared Section/Event names present in BOTH processes = the channel.
"""
import ctypes
import sys

NTD = ctypes.WinDLL("ntdll", use_last_error=True)
K32 = ctypes.WinDLL("kernel32", use_last_error=True)

SystemHandleInformation = 16
ObjectTypeInformation, ObjectNameInformation = 2, 1
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
PROCESS_DUP_HANDLE = 0x0040
DUPLICATE_SAME_ACCESS = 0x2


class SYSTEM_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
    _fields_ = [("UniqueProcessId", ctypes.c_ushort),
                ("CreatorBackTraceIndex", ctypes.c_ushort),
                ("ObjectTypeIndex", ctypes.c_ubyte),
                ("HandleAttributes", ctypes.c_ubyte),
                ("HandleValue", ctypes.c_ushort),
                ("Object", ctypes.c_void_p),
                ("GrantedAccess", ctypes.c_ulong)]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort), ("MaximumLength", ctypes.c_ushort),
                ("Buffer", ctypes.c_void_p)]


class GENERIC_MAPPING(ctypes.Structure):
    _fields_ = [("GenericRead", ctypes.c_ulong),
                ("GenericWrite", ctypes.c_ulong),
                ("GenericExecute", ctypes.c_ulong),
                ("GenericAll", ctypes.c_ulong)]


class OBJECT_TYPE_INFORMATION(ctypes.Structure):
    _fields_ = [("TypeName", UNICODE_STRING),
                ("TotalNumberOfObjects", ctypes.c_ulong),
                ("TotalNumberOfHandles", ctypes.c_ulong),
                ("TotalPagedPoolUsage", ctypes.c_ulong),
                ("TotalNonPagedPoolUsage", ctypes.c_ulong),
                ("TotalNamePoolUsage", ctypes.c_ulong),
                ("TotalHandleTableUsage", ctypes.c_ulong),
                ("HighWaterNumberOfObjects", ctypes.c_ulong),
                ("HighWaterNumberOfHandles", ctypes.c_ulong),
                ("HighWaterPagedPoolUsage", ctypes.c_ulong),
                ("HighWaterNonPagedPoolUsage", ctypes.c_ulong),
                ("HighWaterNamePoolUsage", ctypes.c_ulong),
                ("HighWaterHandleTableUsage", ctypes.c_ulong),
                ("InvalidAttributes", ctypes.c_ulong),
                ("GenericMapping", GENERIC_MAPPING),
                ("ValidAccessMask", ctypes.c_ulong),
                ("SecurityRequired", ctypes.c_ubyte),
                ("MaintainHandleCount", ctypes.c_ubyte),
                ("TypeIndex", ctypes.c_ubyte),
                ("ReservedByte", ctypes.c_ubyte),
                ("PoolType", ctypes.c_ulong),
                ("DefaultPagedPoolCharge", ctypes.c_ulong),
                ("DefaultNonPagedPoolCharge", ctypes.c_ulong)]


NTD.NtQuerySystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                         ctypes.c_ulong,
                                         ctypes.POINTER(ctypes.c_ulong)]
NTD.NtQuerySystemInformation.restype = ctypes.c_long
NTD.NtQueryObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                              ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
NTD.NtQueryObject.restype = ctypes.c_long
K32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
K32.OpenProcess.restype = ctypes.c_void_p
K32.DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_void_p),
                                ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
K32.DuplicateHandle.restype = ctypes.c_bool


def read_ustr(ptr):
    us = UNICODE_STRING.from_address(ptr)
    if not us.Length or not us.Buffer:
        return ""
    try:
        return ctypes.wstring_at(us.Buffer, us.Length // 2)
    except Exception:
        return ""


def obj_type(h):
    buf = ctypes.create_string_buffer(0x1000)
    rl = ctypes.c_ulong(0)
    if NTD.NtQueryObject(h, ObjectTypeInformation, buf, 0x1000,
                         ctypes.byref(rl)) != 0:
        return "?"
    return read_ustr(ctypes.addressof(buf))


def obj_name(h):
    buf = ctypes.create_string_buffer(0x1000)
    rl = ctypes.c_ulong(0)
    if NTD.NtQueryObject(h, ObjectNameInformation, buf, 0x1000,
                         ctypes.byref(rl)) != 0:
        return ""
    return read_ustr(ctypes.addressof(buf))


def find_pids(exes):
    K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    K32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    K32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    K32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    class PE32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", ctypes.c_ulong),
                    ("cntThreads", ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong),
                    ("szExeFile", ctypes.c_wchar * 260)]

    out = {}
    ss = K32.CreateToolhelp32Snapshot(0x2, 0)
    pe = PE32()
    pe.dwSize = ctypes.sizeof(pe)
    ok = K32.Process32FirstW(ss, ctypes.byref(pe))
    while ok:
        for e in exes:
            if pe.szExeFile.lower() == e.lower():
                out[e] = pe.th32ProcessID
        ok = K32.Process32NextW(ss, ctypes.byref(pe))
    K32.CloseHandle(ss)
    return out


def handles_of(pid):
    size = 0x10000
    while True:
        buf = ctypes.create_string_buffer(size)
        rl = ctypes.c_ulong(0)
        st = NTD.NtQuerySystemInformation(SystemHandleInformation, buf, size,
                                          ctypes.byref(rl))
        if (st & 0xFFFFFFFF) == STATUS_INFO_LENGTH_MISMATCH:
            size = max(size * 2, rl.value if rl.value else size)
            continue
        if st != 0:
            print(f"[!] NtQuerySystemInformation err={hex(st & 0xFFFFFFFF)}")
            return []
        break
    n = ctypes.c_ulong.from_buffer_copy(buf, 0).value
    # x64 layout: ULONG count (4) + 4 pad, then array, stride 24
    entry_sz = 24
    items = []
    for i in range(n):
        e = SYSTEM_HANDLE_TABLE_ENTRY_INFO.from_buffer_copy(
            buf, 8 + i * entry_sz)
        items.append(e)
    return [e for e in items if e.UniqueProcessId == pid]


def main():
    if len(sys.argv) > 1:
        pids = [int(x) for x in sys.argv[1:]]
    else:
        found = find_pids(["PBC-1.0.57.exe", "MuMuNxDevice.exe"])
        print("targets:", found)
        pids = list(found.values())
    # NOTE: "File" deliberately excluded — name queries on pipes can hang,
    # and file-IPC was already ruled out (no hot files while ESP draws).
    INTEREST = ("Section", "Event", "Mutant", "ALPC Port", "Semaphore")
    by_name = {}
    for pid in pids:
        ph = K32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not ph:
            print(f"[!] OpenProcess({pid}) err={ctypes.get_last_error()} "
                  "(need Administrator)")
            continue
        seen = {}
        entries = handles_of(pid)
        print(f"[{pid}] {len(entries)} handles to scan...", flush=True)
        for n, e in enumerate(entries):
            if n and n % 2000 == 0:
                print(f"[{pid}] scanned {n}/{len(entries)} "
                      f"(named so far: {len(seen)})...", flush=True)
            dh = ctypes.c_void_p(0)
            if not K32.DuplicateHandle(ph, ctypes.c_void_p(e.HandleValue),
                                       K32.GetCurrentProcess(),
                                       ctypes.byref(dh), 0, False,
                                       DUPLICATE_SAME_ACCESS):
                continue
            try:
                t = obj_type(dh.value)
                if t in INTEREST:
                    nm = obj_name(dh.value)
                    if nm and nm not in seen:
                        seen[nm] = t
                        by_name.setdefault((t, nm), []).append(pid)
            finally:
                K32.CloseHandle(dh)
            if len(seen) > 2000:
                break
        K32.CloseHandle(ph)
        print(f"--- pid {pid}: {len(seen)} named interesting handles ---")
        for nm in sorted(seen):
            if "BaseNamedObjects" in nm or seen[nm] == "ALPC Port":
                print(f"  [{seen[nm]}] {nm}")
        print(f"  (... +{len(seen)} total, shared list below is what matters)")
    print("=== SHARED (in 2+ targets) ===")
    for (t, nm), ps in sorted(by_name.items()):
        if len(set(ps)) > 1:
            print(f"  [{t}] {nm} pids={sorted(set(ps))}")


if __name__ == "__main__":
    main()
