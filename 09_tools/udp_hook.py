#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
udp_hook.py — capture live ESP frame datagrams (DLL -> loader).
Channel (proven by ProcMon): MuMuNxDevice sends UDP datagrams from
localhost:50092 to localhost:4042; PBC loader recvfrom()s them.
Sizes are record multiples: 2992 (1x0xBB0), 11968 (4x), 14960 (5x).
No focus needed at capture time: start hook, PLAY focused 1-2 min,
stop, send the dump file.

Usage (Administrator, cheat+match running):
  venv/Scripts/python.exe 09_bypass_session4/udp_hook.py <PBC-pid> [seconds]
Output: udp_hook_<ts>.bin (concatenated datagrams) + marker summary.
WARNING: VMP may notice Frida injection and kill the cheat. If it dies
on attach, use ProcMon lengths only (safe, no injection).
"""
import struct
import sys
import time

import frida

JS = """
const calls = {};
function cnt(api) {
  calls[api] = (calls[api] || 0) + 1;
  if (calls[api] % 2000 === 0) send({ev: 'STAT'});
}
function emitBytes(u8, tag) {
  if (u8 && u8.byteLength > 0) send({ev: 'DG', n: u8.byteLength, via: tag}, u8);
}
// overlapped (async) completions via IOCP
const pending = new Map();
function trackOv(ov, bufs, count, tag) {
  if (!ov.isNull()) pending.set(ov.toString(), {bufs, count, tag});
}
function hookFlat(name, tag) {
  try {
    const p = Module.getExportByName('ws2_32.dll', name);
    Interceptor.attach(p, {
      onEnter(args) { this.buf = args[1]; },
      onLeave(ret) {
        const n = ret.toInt32();
        if (n > 0 && n <= 65507) {
          try { emitBytes(this.buf.readByteArray(n), tag); } catch (e) {}
        }
      }
    });
  } catch (e) {}
}
function hookFlatCount(name, dll) {
  try {
    const p = Module.getExportByName(dll || 'ws2_32.dll', name);
    Interceptor.attach(p, {
      onEnter(args) { cnt(name); this.buf = args[1]; },
      onLeave(ret) {
        const n = ret.toInt32();
        if (name === 'recvfrom' || name === 'recv') {
          if (n > 0 && n <= 65507) {
            try { emitBytes(this.buf.readByteArray(n), name); } catch (e) {}
          }
        } else if (name === 'WSARecv' || name === 'WSARecvFrom') {
          // sync path with overlapped==NULL handled by dedicated hooks;
          // count only here
        }
      }
    });
  } catch (e) {}
}
hookFlatCount('recvfrom');
hookFlatCount('recv');
// WSARecv (no From) — sync + async-issue tracking
function hookWSA(name, tag) {
  try {
    const p = Module.getExportByName('ws2_32.dll', name);
    Interceptor.attach(p, {
      onEnter(args) {
        cnt(name);
        // WSARecv(s,bufs,count,outN,flags,ov,comp) | WSARecvFrom has from@5,ov@6
        const isFrom = (name === 'WSARecvFrom');
        this.bufs = args[1]; this.count = args[2].toInt32();
        this.outN = args[3]; this.ov = isFrom ? args[6] : args[5];
        trackOv(this.ov, this.bufs, this.count, tag);
      },
      onLeave(ret) {
        if (ret.toInt32() !== 0 || this.ov.isNull()) {
          // sync-immediate (ret 0, ov NULL) or failed
          if (ret.toInt32() === 0 && this.ov.isNull()) {
            let n = 0;
            try { n = this.outN.readU32(); } catch (e) { return; }
            dumpBufs(this.bufs, this.count, n, tag + '-sync');
          }
          return;
        }
        // async issued; completion via GQCS below
      }
    });
  } catch (e) {}
}
function dumpBufs(bufs, count, n, tag) {
  if (n <= 0 || n > 65507) return;
  try {
    const joined = Memory.alloc(n);
    let total = 0;
    for (let i = 0; i < count && total < n; i++) {
      const base = bufs.add(i * 16);
      const blen = base.readU32();
      const bptr = base.add(8).readPointer();
      const take = Math.min(blen, n - total);
      if (take <= 0) break;
      joined.add(total).writeByteArray(bptr.readByteArray(take));
      total += take;
    }
    if (total > 0) emitBytes(joined.readByteArray(total), tag);
  } catch (e) {}
}
hookWSA('WSARecv', 'wsarecv');
hookWSA('WSARecvFrom', 'wsarecvfrom');
// IOCP completion side
try {
  const gqcs = Module.getExportByName('kernel32.dll',
                                      'GetQueuedCompletionStatus');
  Interceptor.attach(gqcs, {
    onEnter(args) { this.ovPtr = args[3]; this.nPtr = args[1]; },
    onLeave(ret) {
      if (ret.toInt32() === 0) return;
      let ov = null, n = 0;
      try {
        ov = this.ovPtr.readPointer();
        if (ov.isNull()) return;
        n = this.nPtr.readU32();
      } catch (e) { return; }
      const rec = pending.get(ov.toString());
      if (!rec) return;
      dumpBufs(rec.bufs, rec.count, n, rec.tag + '-iocp');
    }
  });
} catch (e) {}
// report call counters periodically
setInterval(() => { try { send({ev: 'STAT', calls: calls}); } catch (e) {} },
            15000);
// sockets-as-files path: ReadFile/WriteFile on \Device\Afd handles.
// Record datagrams are exact multiples of 0xBB0 (2992).
const REC_SIZES = new Set([2992, 5984, 8976, 11968, 14960, 17952, 20944,
                           23936, 26928, 29920]);
let NtQueryObject = null;
try {
  NtQueryObject = new NativeFunction(
    Module.getExportByName('ntdll.dll', 'NtQueryObject'),
    'int', ['pointer', 'int', 'pointer', 'uint', 'pointer']);
} catch (e) {}
function objectName(h) {
  if (NtQueryObject === null) return '?';
  try {
    const buf = Memory.alloc(1024);
    const st = NtQueryObject(h, 1 /*ObjectNameInformation*/, buf, 1024,
                             ptr(0));
    if (st !== 0) return '?';
    const len = buf.readU16();
    if (len === 0) return '';  // unnamed: socket/Afd/section
    return buf.add(8).readUtf16String(len / 2);
  } catch (e) { return '?'; }
}
function hookFileRW(name, isRead, tag) {
  try {
    const p = Module.getExportByName('kernel32.dll', name);
    Interceptor.attach(p, {
      onEnter(args) {
        cnt(name);
        this.h = args[0]; this.buf = args[1];
        this.want = args[2].toInt32(); this.outN = args[3];
      },
      onLeave(ret) {
        if (ret.toInt32() === 0) return;
        let n = 0;
        try { n = this.outN.readU32(); } catch (e) { return; }
        if (!REC_SIZES.has(n)) return;
        const nm = objectName(this.h);
        if (nm !== '') return;  // real file -> ignore; '' = socket/Afd
        try { emitBytes(this.buf.readByteArray(n), tag); } catch (e) {}
      }
    });
  } catch (e) {}
}
hookFileRW('ReadFile', true, 'readfile');
hookFileRW('WriteFile', false, 'writefile');
// sanity: Sleep MUST fire in any GUI loop (proves agent is alive)
hookFlatCount('Sleep', 'kernel32.dll');
try { send({ev: 'LOADED'}); } catch (e) {}
// lowest level: AFD IOCTLs (catches direct DeviceIoControlFile paths)
const ioCodes = {};
try {
  const dio = Module.getExportByName('ntdll.dll',
                                     'NtDeviceIoControlFile');
  Interceptor.attach(dio, {
    onEnter(args) {
      this.h = args[0]; this.code = args[5].toInt32() >>> 0;
      this.outB = args[8]; this.outL = args[9].toInt32();
      this.ioSt = args[4];
      const k = 'ioctl_' + this.code.toString(16);
      ioCodes[k] = (ioCodes[k] || 0) + 1;
    },
    onLeave(ret) {
      if (ret.toInt32() !== 0) return;
      let n = 0;
      try { n = this.ioSt.add(8).readU32(); } catch (e) { return; }
      if (n <= 0 || n > 65507) return;
      const k = 'ioctl_' + this.code.toString(16) + '_bytes';
      ioCodes[k] = (ioCodes[k] || 0) + n;
      // dump only AFD-ish completions of record-multiple size
      if (REC_SIZES.has(n)) {
        try {
          const nm = objectName(this.h);
          emitBytes(this.outB.readByteArray(n),
                    'ioctl' + this.code.toString(16) + ':' + nm);
        } catch (e) {}
      }
    }
  });
  try { send({ev: 'IOCTL_OK'}); } catch (e) {}
  setInterval(() => {
    try { send({ev: 'STAT', calls: calls, io: ioCodes}); } catch (e) {}
  }, 15000);
} catch (e) {
  try { send({ev: 'IOCTL_FAIL', err: String(e)}); } catch (e2) {}
}
try {
  const wsa = Module.getExportByName('ws2_32.dll', 'WSARecvFrom');
  Interceptor.attach(wsa, {
    onEnter(args) {
      this.bufs = args[1]; this.count = args[2].toInt32();
      this.outN = args[3]; this.ov = args[6];
    },
    onLeave(ret) {
      // sync completion only (overlapped==NULL, ret==0)
      if (ret.toInt32() !== 0 || !this.ov.isNull()) return;
      let n = 0;
      try { n = this.outN.readU32(); } catch (e) { return; }
      if (n <= 0 || n > 65507) return;
      try {
        const joined = Memory.alloc(n);
        let total = 0;
        for (let i = 0; i < this.count && total < n; i++) {
          const base = this.bufs.add(i * 16);
          const blen = base.readU32();
          const bptr = base.add(8).readPointer();
          const take = Math.min(blen, n - total);
          if (take <= 0) break;
          joined.add(total).writeByteArray(bptr.readByteArray(take));
          total += take;
        }
        if (total > 0) emitBytes(joined.readByteArray(total), 'wsarecvfrom');
      } catch (e) {}
    }
  });
} catch (e) {}
"""


def main():
    if len(sys.argv) < 2:
        print("usage: udp_hook.py <PBC-pid> [seconds=90]")
        return 2
    pid, secs = int(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 90
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(here, f"udp_hook_{ts}.bin")
    f = open(path, "wb")
    count = [0]
    sizes = {}

    def on_msg(m, d):
        if m["type"] != "send":
            return
        if m["payload"].get("ev") in ("LOADED", "IOCTL_OK",
                                               "IOCTL_FAIL"):
            print(f"[+] {m['payload'].get('ev')}: "
                  f"{m['payload'].get('err', '')}", flush=True)
            return
        if m["payload"].get("ev") == "STAT":
            print(f"[stat] api calls: {m['payload'].get('calls')} "
                  f"io: {m['payload'].get('io')}",
                  flush=True)
            return
        if not d:
            return
        n = m["payload"]["n"]
        via = m["payload"].get("via", "?")
        count[0] += 1
        sizes[(via, n)] = sizes.get((via, n), 0) + 1
        f.write(struct.pack("<I", n))
        f.write(bytes(d))
        if count[0] % 50 == 0:
            print(f"[...] {count[0]} datagrams, sizes={sizes}", flush=True)

    print(f"[*] attaching to PID {pid} ...", flush=True)
    try:
        s = frida.attach(pid)
    except Exception as e:
        print(f"[!] attach failed: {e}")
        return 1
    script = s.create_script(JS)
    script.on("message", on_msg)
    script.load()
    print(f"[*] hooked recvfrom. PLAY focused for {secs}s ...", flush=True)
    try:
        time.sleep(secs)
    except KeyboardInterrupt:
        pass
    s.detach()
    f.close()
    print(f"[+] {count[0]} datagrams -> {path} sizes={sizes}")
    # quick marker scan of the dump
    blob = open(path, "rb").read()
    off, recs = 0, 0
    marks = {b"FrameStart": 0, b"Matrix": 0, b"player": 0, b"FrameEnd": 0}
    while off + 4 <= len(blob):
        (n,) = struct.unpack_from("<I", blob, off)
        dg = blob[off + 4:off + 4 + n]
        for m in marks:
            marks[m] += dg.count(m)
        recs += 1
        off += 4 + n
    print(f"[+] {recs} datagrams re-scanned, markers={marks}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
