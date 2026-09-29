#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rpm_hook.py — prove the launcher<->DLL channel live.
Attaches (Frida) to the running PBC loader and logs every
OpenProcess / ReadProcessMemory / WriteProcessMemory:
target PID + address + size. Big periodic RPM reads from the
MuMuNxDevice PID = the frame-data channel (no TCP/pipe/file).

Usage (Administrator, while cheat+match running):
  venv\Scripts\python.exe 09_bypass_session4\rpm_hook.py <PBC-pid>
WARNING: VMP may notice the injection and kill the cheat. If the
cheat dies on attach, that itself is a signal (anti-debug present) —
fall back to ProcMon (safe, no injection; recipe in REAL_OFFSETS doc).
"""
import sys

import frida

JS = """
const openP = Module.getExportByName('kernel32.dll', 'OpenProcess');
const rpm = Module.getExportByName('kernel32.dll', 'ReadProcessMemory');
const wpm = Module.getExportByName('kernel32.dll', 'WriteProcessMemory');
Interceptor.attach(openP, {
  onEnter(args) { this.pid = args[2].toInt32(); },
  onLeave(ret) {
    if (!ret.isNull()) send({ev: 'OpenProcess', pid: this.pid,
                             h: ret.toString()});
  }
});
function hookRW(ptr, tag) {
  Interceptor.attach(ptr, {
    onEnter(args) {
      this.h = args[0].toString(); this.addr = args[1].toString();
      const sz = args[3].toInt32();
      this.big = sz >= 0x1000; this.size = sz;
    },
    onLeave(ret) {
      if (this.big && !ret.isNull())
        send({ev: tag, h: this.h, addr: this.addr, size: this.size});
    }
  });
}
hookRW(rpm, 'RPM'); hookRW(wpm, 'WPM');
"""


def main():
    if len(sys.argv) < 2:
        print("usage: rpm_hook.py <PBC-pid>")
        return 2
    pid = int(sys.argv[1])
    print(f"[*] attaching to PID {pid} ...", flush=True)
    try:
        s = frida.attach(pid)
    except Exception as e:
        print(f"[!] attach failed: {e}")
        print("    (VMP anti-debug likely — use ProcMon instead)")
        return 1
    s.on("message", lambda m, d: print(
        f"[{m['payload']['ev']}] " +
        " ".join(f"{k}={v}" for k, v in m["payload"].items()
                  if k != "ev"), flush=True) if m["type"] == "send" else None)
    s.create_script(JS).load()
    print("[*] hooked. Watching (Ctrl+C stops, cheat keeps running)...",
          flush=True)
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    s.detach()
    return 0


if __name__ == "__main__":
    sys.exit(main())
