#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Runtime accept-any-key launcher for CODM Loader (BestCheatIR).
Usage:  run_patched.py <path-to-cheat-exe>     (also works via drag & drop: see run_patched.bat)
Requires: Windows 10/11 x64 + Administrator (cheat manifest demands it).

How it works:
  1. Starts the cheat SUSPENDED (nothing executes yet — VMP sees no debugger,
     no DebugPort is set, we are just a parent process).
  2. Reads the real image base from the remote PEB (ASLR-safe).
  3. Resumes the process and POLLS the 3 license-check sites until the
     pre-patch bytes appear — i.e. VMP has decrypted that .text region
     (this happens AFTER the early file-integrity check, so patching memory
     cannot trip the SEC_COMMIT file hash):
        site1 base+0x6e201 expect 0F843B100000 (JE fail, code check #1)
        site2 base+0x6e21d expect 0F841F100000 (JE fail, code check #2)
        site3 base+0x6e287 expect 0F8531030000 (JNE sig-ok branch)
  4. WriteProcessMemory the 3 patches (NOP/NOP/JMP), verify by read-back.
  5. Leaves the process running: type ANY key at "ENTER YOUR LICENSE KEY".
     Expected: LICENSE VERIFIED -> "Waiting for target process" (proof of
     bypass). Without a real LOGIN_SUCCESS the server sends no offsets, so
     the cheat sits on compiled defaults — NOT usable in game (confirmed).

Safety: run on an ISOLATED VM (snapshot first). Every license attempt uploads
your HWID to the vendor server, even rejected ones. Needs admin (the cheat
writes C:\\Windows\\System32\\keysex.txt). Clean that file + ext.dll afterwards.
"""
import ctypes, os, struct, sys, time

K32 = ctypes.WinDLL("kernel32", use_last_error=True)
NTD = ctypes.WinDLL("ntdll", use_last_error=True)

# 64-bit correctness: default ctypes restype is c_int (32-bit) which would
# truncate remote pointers. Declare the APIs we use explicitly.
K32.VirtualAllocEx.restype = ctypes.c_void_p
K32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               ctypes.c_ulong, ctypes.c_ulong]
K32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
K32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
K32.ResumeThread.argtypes = [ctypes.c_void_p]
K32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
K32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
K32.CreateProcessW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_bool, ctypes.c_ulong,
                               ctypes.c_void_p, ctypes.c_wchar_p,
                               ctypes.c_void_p, ctypes.c_void_p]
NTD.NtQueryInformationProcess.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]

CREATE_SUSPENDED = 0x4
CREATE_NEW_CONSOLE = 0x10
PROCESS_ALL = 0x1F0FFF
STILL_ACTIVE = 259


def _free_child_console(fh, pid):
    """Give the cheat's own console window a big scrollback buffer (9000
    lines) and make sure min/max/resize buttons exist. Best effort."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    GWL_STYLE, WS_MIN, WS_MAX, WS_SIZEBOX = -16, 0x20000, 0x10000, 0x40000
    # detach from OUR console first (required before AttachConsole)
    K32.FreeConsole()
    if not K32.AttachConsole(pid):
        raise RuntimeError("AttachConsole failed")
    try:
        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        K32.GetStdHandle.restype = ctypes.c_void_p
        K32.GetStdHandle.argtypes = [ctypes.c_ulong]
        K32.SetConsoleScreenBufferSize.argtypes = [ctypes.c_void_p, COORD]
        h = K32.GetStdHandle(0xFFFFFFF5)  # STD_OUTPUT_HANDLE
        # buffer must fit current window; 120x9000 is safe for defaults
        K32.SetConsoleScreenBufferSize(h, COORD(120, 9000))
        hwnd = user32.GetConsoleWindow()
        if hwnd:
            GWL = user32.GetWindowLongW(hwnd, -16)
            user32.SetWindowLongW(hwnd, -16, GWL | 0x20000 | 0x10000 | 0x40000)
            user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0,
                                0x0001 | 0x0002 | 0x0020 | 0x0040)
    finally:
        K32.FreeConsole()

SITES = [  # (rva, expected_pre, patch)
    (0x6E201, bytes.fromhex("0f843b100000"), bytes.fromhex("909090909090")),
    (0x6E21D, bytes.fromhex("0f841f100000"), bytes.fromhex("909090909090")),
    (0x6E287, bytes.fromhex("0f8531030000"), bytes.fromhex("e93203000090")),
    # P4: response-HMAC compare (0x1400693de jne->fail) => always match.
    (0x693DE, bytes.fromhex("7505"), bytes.fromhex("9090")),
    # P5: the real signature gate (0x140068d80 result) => always success.
    (0x6DC0F, bytes.fromhex("0f8506050000"), bytes.fromhex("e90705000090")),
]
POLL_TIMEOUT = 180.0
POLL_STEP = 0.15


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_ulong), ("lpReserved", ctypes.c_wchar_p),
                ("lpDesktop", ctypes.c_wchar_p), ("lpTitle", ctypes.c_wchar_p),
                ("dwX", ctypes.c_ulong), ("dwY", ctypes.c_ulong),
                ("dwXSize", ctypes.c_ulong), ("dwYSize", ctypes.c_ulong),
                ("dwXCountChars", ctypes.c_ulong), ("dwYCountChars", ctypes.c_ulong),
                ("dwFillAttribute", ctypes.c_ulong), ("dwFlags", ctypes.c_ulong),
                ("wShowWindow", ctypes.c_ushort), ("cbReserved2", ctypes.c_ushort),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", ctypes.c_void_p),
                ("hStdOutput", ctypes.c_void_p), ("hStdError", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
                ("dwProcessId", ctypes.c_ulong), ("dwThreadId", ctypes.c_ulong)]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_void_p), ("BasePriority", ctypes.c_void_p),
                ("UniqueProcessId", ctypes.c_void_p), ("InheritedFromUniqueProcessId", ctypes.c_void_p)]


def log(fh, msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    try:
        print(line, flush=True)  # absent under pythonw (hidden mode) — file log always works
    except Exception:  # noqa - hidden mode has no stdout
        pass
    fh.write(line + "\n"); fh.flush()


def rpm(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    done = ctypes.c_size_t(0)
    if not K32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(done)):
        return None
    return buf.raw[:done.value]


def wpm(h, addr, data):
    done = ctypes.c_size_t(0)
    return bool(K32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(done))
                and done.value == len(data))


def remote_image_base(h):
    pbi = PROCESS_BASIC_INFORMATION()
    retlen = ctypes.c_ulong(0)
    if NTD.NtQueryInformationProcess(h, 0, ctypes.byref(pbi),
                                     ctypes.sizeof(pbi), ctypes.byref(retlen)) != 0:
        return None
    raw = rpm(h, pbi.PebBaseAddress, 0x20)
    if not raw:
        return None
    return struct.unpack("<Q", raw[0x10:0x18])[0]  # PEB+0x10 ImageBaseAddress


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cheat", help="path to cheat exe")
    ap.add_argument("--jit", metavar="REQLOG",
                    help="JIT mode: patch only AFTER the cheat's request appears in the "
                         "fake-server request log (i.e. all VMP checks passed, verify "
                         "still waiting on the delayed response). Use with "
                         "fake_server.py --delay 20. Recommended (dodges the runtime "
                         "memory-integrity check that kills early patching).")
    ap.add_argument("--jit-timeout", type=float, default=300.0)
    ap.add_argument("--hidden", action="store_true",
                    help="hide the cheat's console window (SW_HIDE) instead of showing it. "
                         "Combine with --auto-key for a fully unattended run. "
                         "Monitoring via 09_bypass_session4\\run_patched_log.txt only.")
    ap.add_argument("--auto-key", default=None, metavar="KEY",
                    help="feed KEY+Enter to the cheat's license prompt automatically "
                         "through a stdin pipe (no typing needed).")
    args = ap.parse_args()
    target = os.path.abspath(args.cheat)
    if not os.path.exists(target):
        print(f"file not found: {target}")
        sys.exit(2)
    fh = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "run_patched_log.txt"), "a", encoding="utf-8")
    log(fh, f"target: {target}")
    si, pi = STARTUPINFO(), PROCESS_INFORMATION()
    si.cb = ctypes.sizeof(si)
    # NEW_CONSOLE: cheat gets its own window (like a plain double-click), so
    # launcher logs and cheat output never interleave, and no stray keypress
    # can leak into the license prompt.
    flags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE
    inherit = False
    stdin_write = None
    if args.auto_key is not None:
        # Pipe only stdin for --auto-key key injection.
        # stdout/stderr are NOT redirected to NUL — the cheat keeps its own
        # console window so the menu stays visible.
        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("nLength", ctypes.c_ulong),
                        ("lpSecurityDescriptor", ctypes.c_void_p),
                        ("bInheritHandle", ctypes.c_bool)]

        K32.CreatePipe.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.c_void_p, ctypes.c_ulong]
        K32.SetHandleInformation.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
        sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
        r_h, w_h = ctypes.c_void_p(), ctypes.c_void_p()
        if K32.CreatePipe(ctypes.byref(r_h), ctypes.byref(w_h), ctypes.byref(sa), 0x1000):
            K32.SetHandleInformation(w_h, 1, 0)  # write end: not inherited
            si.dwFlags = 0x100  # STARTF_USESTDHANDLES
            si.hStdInput = r_h.value
            # Leave stdout/stderr as default (cheat's own new console)
            K32.GetStdHandle.restype = ctypes.c_void_p
            K32.GetStdHandle.argtypes = [ctypes.c_ulong]
            si.hStdOutput = K32.GetStdHandle(0xFFFFFFF5)  # STD_OUTPUT_HANDLE
            si.hStdError  = K32.GetStdHandle(0xFFFFFFF4)  # STD_ERROR_HANDLE
            inherit = True
            stdin_write = w_h.value
            stdin_read_parent = r_h.value  # closed AFTER CreateProcess
        else:
            log(fh, "stdin pipe creation failed — continuing without --auto-key")
            args.auto_key = None
    # --hidden hides the *launcher* window (via VBS wscript.exe SW_HIDE),
    # never the cheat window. Cheat always gets CREATE_NEW_CONSOLE = visible.
    ok = K32.CreateProcessW(target, None, None, None, inherit, flags,
                            None, os.path.dirname(target) or None,
                            ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        log(fh, f"CreateProcess FAILED err={ctypes.get_last_error()} (run as Administrator?)")
        sys.exit(1)
    try:
        K32.CloseHandle(ctypes.c_void_p(stdin_read_parent))  # child has its own copy now
    except NameError:
        pass
    # NOTE: stdin_write stays open on purpose — the key is written after resume.
    log(fh, f"launched suspended pid={pi.dwProcessId}")
    base = remote_image_base(pi.hProcess)
    if not base:
        log(fh, "could not read remote PEB (terminating child)")
        K32.TerminateProcess(pi.hProcess, 1)
        sys.exit(1)
    log(fh, f"remote image base = {hex(base)} (ASLR-resolved)")
    # JIT baseline MUST be captured BEFORE ResumeThread: on a warm run the
    # cheat can fire its login request within the 2s auto-key sleep, and a
    # post-resume baseline would already include that line (no growth ever
    # detected -> no patches -> signature reject -> exit 1).
    jit_base_sz = None
    if args.jit:
        try:
            jit_base_sz = os.path.getsize(args.jit)
        except OSError:
            jit_base_sz = 0
    K32.ResumeThread(pi.hThread)
    if stdin_write is not None and args.auto_key is not None:
        import time as _t2
        _t2.sleep(2.0)  # let it reach the prompt; pipe buffers meanwhile
        blob = (args.auto_key + "\n").encode()
        done = ctypes.c_size_t(0)
        K32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                                  ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
        okw = K32.WriteFile(ctypes.c_void_p(stdin_write), blob, len(blob),
                            ctypes.byref(done), None)
        log(fh, f"auto-key injected: {done.value}/{len(blob)} bytes "
                f"({'OK' if okw and done.value == len(blob) else 'SHORT-WRITE err=%d' % ctypes.get_last_error()})")
        # keep stdin_write open (no EOF) in case the cheat reads stdin again later.
    if args.jit:
        base_sz = jit_base_sz
        log(fh, f"JIT mode: resumed; waiting for cheat request in {args.jit} "
                "(type the fake key at the prompt when it appears)...")
        t0 = time.time()
        ready = False
        while time.time() - t0 < args.jit_timeout:
            try:
                if os.path.getsize(args.jit) > base_sz:
                    ready = True
                    break
            except OSError:
                pass
            code = ctypes.c_ulong(0)
            K32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            if code.value != STILL_ACTIVE:
                log(fh, f"child exited with code {code.value} ({hex(code.value)}) "
                        "before any request — VMP verdict or user closed it.")
                sys.exit(3)
            time.sleep(POLL_STEP)
        if not ready:
            log(fh, f"JIT TIMEOUT {args.jit_timeout}s: no request seen. "
                    "Did you type a key? Is hosts pointing at the fake server? "
                    "Terminating child.")
            K32.TerminateProcess(pi.hProcess, 1)
            sys.exit(4)
        log(fh, "request seen (all VMP checks passed, verify is waiting on the "
                "delayed response) — patching NOW...")
    else:
        log(fh, "resumed; waiting for license code to decrypt in memory...")
        t0 = time.time()
        ready = False
        while time.time() - t0 < POLL_TIMEOUT:
            b0 = rpm(pi.hProcess, base + SITES[0][0], 6)
            if b0 == SITES[0][1]:
                ready = True
                break
            # early-abort detection: process already gone (integrity/debug verdict)
            code = ctypes.c_ulong(0)
            K32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            if code.value != STILL_ACTIVE:
                log(fh, f"child exited early with code {code.value} ({hex(code.value)}) "
                        "BEFORE decrypt — likely VMP verdict in this environment. "
                        "Use an isolated clean VM (no debugger, no hooks).")
                sys.exit(3)
            time.sleep(POLL_STEP)
        if not ready:
            log(fh, f"TIMEOUT {POLL_TIMEOUT}s: license bytes never decrypted. "
                    "VMP may have taken another path. Terminating child.")
            K32.TerminateProcess(pi.hProcess, 1)
            sys.exit(4)
    log(fh, f"decrypt detected; applying {len(SITES)} patches...")
    for rva, expect, patch in SITES:
        cur = rpm(pi.hProcess, base + rva, len(expect))
        if cur != expect:
            log(fh, f"site {hex(base + rva)}: unexpected bytes {cur.hex() if cur else None} "
                    "— version mismatch, aborting (child left suspended? no — terminating).")
            K32.TerminateProcess(pi.hProcess, 1)
            sys.exit(5)
        if not wpm(pi.hProcess, base + rva, patch):
            log(fh, f"site {hex(base + rva)}: WriteProcessMemory FAILED err={ctypes.get_last_error()}")
            K32.TerminateProcess(pi.hProcess, 1)
            sys.exit(6)
        back = rpm(pi.hProcess, base + rva, len(patch))
        log(fh, f"site {hex(base + rva)}: {expect.hex()} -> {back.hex()} "
                + ("OK" if back == patch else "VERIFY-FAIL"))
    log(fh, "ALL PATCHES APPLIED. Type ANY key at the cheat prompt.")
    log(fh, "Expected: LICENSE VERIFIED -> Waiting for target process. "
            "Video that screen. (No offsets => not game-usable, proof only.)")
    try:
        _free_child_console(fh, pi.dwProcessId)
    except Exception as e:  # noqa - best effort only, never fail the run
        log(fh, f"console fix skipped: {e}")
    K32.CloseHandle(pi.hThread)
    K32.CloseHandle(pi.hProcess)

    # keep alive indefinitely after license verification — just loop forever
    # so the cheat process stays running in background and does not exit.
    log(fh, "entering background watch mode: process will stay running...")
    captured = False
    while True:
        if not captured:
            # ext.dll is dropped at injection time (after license) — grab it
            # into the session folder on the first iteration where it exists.
            try:
                import shutil
                base = os.path.dirname(os.path.abspath(__file__))
                shutil.copy(r"C:\Windows\System32\ext.dll",
                            os.path.join(base, "ext_dropped.dll"))
                captured = True
                log(fh, "captured ext.dll -> ext_dropped.dll")
            except Exception:
                pass
        time.sleep(30)


if __name__ == "__main__":
    main()
