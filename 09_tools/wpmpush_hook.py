#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wpmpush_hook.py — prove the push direction (DLL -> loader frames).
Attaches to MuMuNxDevice (ext.dll host), hooks OpenProcess (handle->PID
map) + WriteProcessMemory (target, size). Steady ESP frames show up as
periodic multi-KB writes into the PBC loader PID.
Usage (Administrator, match running):
  venv/Scripts/python.exe 09_bypass_session4/wpmpush_hook.py <MuMuNxDevice-pid> [seconds=60]
"""
import sys
import time
from collections import Counter

import frida

JS = """
const handles = {};
try {
  const op = Module.getExportByName('kernel32.dll', 'OpenProcess');
  Interceptor.attach(op, {
    onEnter(args) { this.pid = args[2].toInt32(); },
    onLeave(ret) {
      if (!ret.isNull()) handles[ret.toString()] = this.pid;
    }
  });
} catch (e) {}
const wpm = Module.getExportByName('kernel32.dll', 'WriteProcessMemory');
const sizes = {};
Interceptor.attach(wpm, {
  onEnter(args) {
    this.h = args[0].toString();
    this.size = args[3].toInt32();
  },
  onLeave(ret) {
    if (ret.toInt32() === 0) return;
    const pid = handles[this.h] || 0;
    send({ev: 'W', pid: pid, size: this.size});
  }
});
setInterval(() => send({ev: 'PING'}), 15000);
"""


def main():
    if len(sys.argv) < 2:
        print("usage: wpmpush_hook.py <MuMuNxDevice-pid> [seconds=60]")
        return 2
    pid = int(sys.argv[1])
    secs = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    by_pid, total = Counter(), [0]
    seen_ping = [False]

    def on_msg(m, d):
        if m["type"] != "send":
            return
        p = m["payload"]
        if p.get("ev") == "PING":
            seen_ping[0] = True
            return
        total[0] += 1
        by_pid[(p.get("pid"), p.get("size"))] += 1
        if total[0] % 200 == 0:
            print(f"[...] {total[0]} writes", flush=True)

    print(f"[*] attaching to PID {pid} ...", flush=True)
    try:
        s = frida.attach(pid)
    except Exception as e:
        print(f"[!] attach failed: {e}")
        return 1
    script = s.create_script(JS)
    script.on("message", on_msg)
    script.load()
    print(f"[*] hooked WPM. PLAY focused for {secs}s ...", flush=True)
    time.sleep(secs)
    s.detach()
    print(f"[+] {total[0]} WriteProcessMemory calls; agent alive={seen_ping[0]}")
    agg = Counter()
    for (p, sz), c in by_pid.most_common(40):
        print(f"    pid={p} size={sz}: {c}x")
        agg[sz] += c
    print("size histogram top:", agg.most_common(10))
    return 0


if __name__ == "__main__":
    sys.exit(main())
