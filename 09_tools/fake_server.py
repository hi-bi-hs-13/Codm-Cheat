#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fake license server for CODM Loader (BestCheatIR) — authorized-testing tool.
Intercepts https://api.bestcheatir.com/CODM via hosts redirect + local TLS cert.

Use TOGETHER with run_patched.py (the 3-jump patch skips code + signature
checks, so this server only needs well-formed JSON — no valid signatures).
Flow:  fake_server.py  ->  run_patched.py <cheat>  ->  type ANY key.

What it returns (always):
  code=LOGIN_SUCCESS, server_time=now, expires_at=2030-01-01,
  hwid/nonce reflected from YOUR request, signature="bypass-with-patch",
  16 typeinfo offsets = the client's own compiled defaults, extracted from
  the unpacked DLL dump (final_FULLIMAGE.bin globals 0x1800d2460...).
  Served both flat AND nested under "typeinfo-v1" (parser accepts either
  shape; extras are ignored). offsets_signature is a placeholder — with the
  patch active it is never verified; worst case the client uses the same
  defaults ("USING COMPILED DEFAULTS").

Usage (Administrator):
  python fake_server.py --cert server.pfx --pfx-password xxx --port 443
  (see FAKE_SERVER_GUIDE.md for hosts + cert steps)

Safety: isolated VM only. Every request is logged to requests_log.jsonl
(includes your HWID — that is exactly what the real server would receive).
"""
import argparse
import datetime
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time as _time
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REQLOG = os.path.join(HERE, "requests_log.jsonl")


def _say(msg):
    # pythonw-safe print (no console in hidden mode) — requests are also in REQLOG.
    try:
        print(msg, flush=True)
    except Exception:  # noqa - hidden mode has no stdout
        pass
    try:
        with open(os.path.join(HERE, "fake_server_stdout.log"), "a", encoding="utf-8") as f:
            f.write(str(msg) + "\n")
    except Exception:  # noqa - never fail serving
        pass

# --- offsets: REAL name->value mapping, captured live 2026-09-23 via
# --forward MITM (offsets_capture_20260923_060211.json). Only delta vs the
# unpacked-DLL compiled defaults is typeinfo_character_model = 0x0
# (server zeroes it). NOTE: the old zip() table below paired names with the
# wrong values — this explicit dict fixes that.
OFFSETS = {
    "typeinfo_loadout_helper": 0x0E8524F8,
    "typeinfo_item2inventory": 0x0E85DC68,
    "typeinfo_character_model": 0x0,
    "typeinfo_item_resource": 0x0E856940,
    "typeinfo_weapon": 0x0E854320,
    "typeinfo_role_base_generic": 0x0E85DD00,
    "typeinfo_item2inventory_generic": 0x0E855C78,
    "typeinfo_character_model_generic": 0x0E853E68,
    "typeinfo_item_resource_generic": 0x0E851CC0,
    "typeinfo_weapon_generic": 0x0E851930,
    "typeinfo_role_generic": 0x0E851C80,
    "typeinfo_role_base_character": 0x0E85E580,
    "typeinfo_role": 0x0E85E5A8,
    "typeinfo_role_pack_generic": 0x0E85E5B0,
    "typeinfo_weapon_fire_component_instant": 0x0E868C18,
    "typeinfo_engine": 0x0E852F08,
}

# --- AUTO-LOAD REAL OFFSETS (added 2026-09-26) ------------------------------
# In fake mode, serve the newest REAL offsets captured via --forward instead
# of this static table. Every forward run drops offsets_capture_<ts>.json;
# on startup we pick the newest one that is a genuine LOGIN_SUCCESS carrying
# typeinfo_* keys and merge its values over OFFSETS. Refresh workflow:
#   1. server.bat -> option 2 (forward), run the cheat with the real key
#   2. restart the server in fake mode — done (restart_fake_server.ps1)
OFFSETS_SIG = None


def _load_latest_capture():
    import glob as _glob
    best = None  # (tskey, filename, json)
    for path in _glob.glob(os.path.join(HERE, "offsets_capture_*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                j = json.load(f)
        except Exception:
            continue
        if j.get("code") != "LOGIN_SUCCESS" or not j.get("typeinfo_engine"):
            continue
        m = re.search(r"(\d{8}_\d{6})", os.path.basename(path))
        tskey = m.group(1) if m else ""
        if best is None or tskey > best[0]:
            best = (tskey, os.path.basename(path), j)
    return best


_c = _load_latest_capture()
if _c:
    _ts, _name, _j = _c
    _n = 0
    for _k, _v in _j.items():
        if not _k.startswith("typeinfo_"):
            continue
        try:
            OFFSETS[_k] = int(str(_v), 16) if isinstance(_v, str) else int(_v)
            _n += 1
        except Exception:
            pass
    OFFSETS_SIG = _j.get("offsets_signature")
    _say(f"REAL OFFSETS auto-loaded from {_name} "
         f"({_n} typeinfo keys, sig={str(OFFSETS_SIG)[:16]}...)")
else:
    _say("no usable offsets_capture_*.json — static default table in effect")


EXPIRES_TEXT = None

# --- MITM-forward mode: relay to the real vendor, capture the reply ---
FORWARD = False
VENDOR_DNS = "8.8.8.8"  # explicit DNS bypasses the hosts redirect
_vendor_ip_cache = {"ip": None, "ts": 0.0}
# --zero-offsets experiment (2026-09-26): serve 0x0 for every typeinfo key to
# test whether the DLL resolves all classes locally (character_model is always
# 0 from the real server and works, so zero values are accepted).
ZERO_OFFSETS = False


def vendor_ip(host):
    """Real IPv4 of host via explicit DNS (hosts file is bypassed)."""
    now = _time.time()
    if _vendor_ip_cache["ip"] and now - _vendor_ip_cache["ts"] < 600:
        return _vendor_ip_cache["ip"]
    try:
        out = subprocess.run(["nslookup", host, VENDOR_DNS],
                             capture_output=True, text=True,
                             timeout=10).stdout
        ips = re.findall(r"Address:\s*(\d+\.\d+\.\d+\.\d+)", out)
        ip = ips[-1]  # first Address: is the DNS server itself
        _vendor_ip_cache.update(ip=ip, ts=now)
        _say(f"vendor {host} -> {ip} (via {VENDOR_DNS})")
        return ip
    except Exception as e:
        _say(f"vendor DNS resolve failed: {e}")
        return None


class ForwardConn(http.client.HTTPSConnection):
    """HTTPS to the vendor: dial real_ip, SNI/Host stay the vendor name,
    real cert verified (proves we talk to the genuine server)."""

    def __init__(self, host, real_ip, **kw):
        self._real_ip = real_ip
        super().__init__(host, **kw)

    def connect(self):
        self.sock = socket.create_connection((self._real_ip, self.port),
                                             self.timeout)
        self.sock = self._context.wrap_socket(self.sock,
                                              server_hostname=self.host)


def forward_request(h, raw):
    """Relay cheat's request to the vendor verbatim; capture the reply.
    Returns (status, body_bytes, content_type)."""
    host = (h.headers.get("Host") or "api.bestcheatir.com").split(":")[0]
    ip = vendor_ip(host)
    if not ip:
        return 502, b'{"error":"vendor DNS failed"}', "application/json"
    skip = {"host", "content-length", "connection",
            "transfer-encoding", "expect"}
    fwd = {k: v for k, v in h.headers.items() if k.lower() not in skip}
    conn = ForwardConn(host, ip, timeout=25)
    try:
        conn.request(h.command, h.path, body=raw, headers=fwd)
        r = conn.getresponse()
        body = r.read()
        rctype = r.getheader("Content-Type", "application/octet-stream")
        status = r.status
    finally:
        conn.close()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        cap = os.path.join(HERE, f"offsets_capture_{ts}.json")
        with open(cap, "wb") as f:
            f.write(body)
        try:
            j = json.loads(body.decode("utf-8", "replace"))
            keys = list(j) if isinstance(j, dict) else j
        except Exception:
            keys = ["<non-JSON>"]
        _say(f"CAPTURED {len(body)} bytes -> {os.path.basename(cap)} "
             f"keys={keys if isinstance(keys, list) else type(keys)}")
    except Exception as e:
        _say(f"capture note: {e}")
    return status, body, rctype


def build_login_response(req):
    """Login reply shaped EXACTLY like the real vendor response (1044-byte
    LOGIN_SUCCESS capture): offsets ride INLINE in the login reply — the
    cheat never calls a separate offsets endpoint (proven via requests_log:
    only /CODM-PC/login.php is ever requested by LicenseClient).

    The earlier 6-field minimal reply made the DLL fall into its
    "REMOTE TYPEINFO OFFSETS UNAVAILABLE; USING COMPILED DEFAULTS" path,
    which correlates 1:1 with the disconnected-menu + silent host crash.
    Field order mirrors the capture (json.dumps preserves insertion order).
    Values: hwid/nonce echoed, signature="bypass-with-patch" (patch P3
    skips verification), typeinfo_* as HEX STRINGS exactly like the vendor,
    offsets_signature = the captured real value."""
    import time as _t
    # plausible-looking far-future date, format-valid, NOT round, and totally
    # unlike the real key's 2026-10-18 15:10:04 (so screenshots can't be
    # matched back to the real account). Change here if needed.
    expires = EXPIRES_TEXT if EXPIRES_TEXT is not None else "2027-01-27 11:36:52"
    server_time = _t.strftime("%Y-%m-%d %H:%M:%S")
    hwid = req.get("hwid", "")
    nonce = req.get("nonce", "")
    # signature formula CRACKED 2026-09-26 (brute_force_sig.py, verified on
    # 8 real captures): HMAC-SHA256(secret, "true|LOGIN_SUCCESS|"
    # "server_time|expires_at|hwid|nonce").hex — secret from CRACK_STATUS.md
    _secret = b"mQ8vT9zR4pK7xN2cY6sL0aH3dF1wE5uB9jG2nV7qZ4tC8rX6yP1kS5"
    _msg = "|".join(["true", "LOGIN_SUCCESS", server_time, expires, hwid, nonce])
    _sig = hmac.new(_secret, _msg.encode(), hashlib.sha256).hexdigest()
    body = {
        "success": True,
        "code": "LOGIN_SUCCESS",
        "message": "Login successful",
        "server_time": server_time,
        "expires_at": expires,
        "hwid": hwid,
        "nonce": nonce,
        "signature": _sig,
        "offset_schema": "typeinfo-v1",
    }
    for _k, _v in OFFSETS.items():
        body[_k] = ("0x0" if ZERO_OFFSETS else "0x%X" % _v)
    body["offsets_signature"] = OFFSETS_SIG or "bypass-with-patch"
    return body


def build_offsets_response(req):
    """Second-stage reply (offsets endpoint). Served flat AND nested."""
    body = {
        "code": "LOGIN_SUCCESS",
        "typeinfo-v1": dict(OFFSETS),
        "offsets_signature": OFFSETS_SIG or "bypass-with-patch",
    }
    body.update(OFFSETS)
    return body


def build_response(req, path=""):
    if "/CODM-PC/login.php" in path:
        return build_login_response(req)
    return build_offsets_response(req)


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    DELAY = 0

    def log_message(self, *a):
        pass

    def _answer(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")
        req = {}
        try:
            if "application/json" in ctype:
                req = json.loads(raw.decode("utf-8", "replace"))
            else:
                # real client sends URL-encoded FORM (observed live):
                # app_id=&app_version=&hwid=&key=&nonce=&signature=&timestamp=
                from urllib.parse import parse_qs
                req = {k: v[0] for k, v in
                       parse_qs(raw.decode("utf-8", "replace")).items()}
        except Exception:
            req = {"_raw": raw.decode("utf-8", "replace")[:500]}
        with open(REQLOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"path": self.path, "ua": self.headers.get("User-Agent"),
                                "req": req}) + "\n")
        if FORWARD:
            status, blob, ctype = forward_request(self, raw)
            tag = f"FORWARDED->{status}"
        else:
            resp = build_response(req if isinstance(req, dict) else {},
                                  self.path)
            blob = json.dumps(resp).encode()
            status, ctype, tag = 200, "application/json", "LOGIN_SUCCESS"
        if Handler.DELAY > 0:
            _say(f"holding response {Handler.DELAY}s (JIT patch window)...")
            _time.sleep(Handler.DELAY)
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
        except (ConnectionError, ssl.SSLError, OSError):
            pass  # client gave up (e.g. its own timeout fired first) — harmless
        _say(f"[{datetime.datetime.now():%H:%M:%S}] {self.command} {self.path} "
              f"key={str(req.get('key', '?'))[:20]}... -> {tag}")

    do_POST = _answer
    do_GET = _answer
    do_HEAD = _answer


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--cert", required=True, help="PEM certificate for api.bestcheatir.com (with SAN)")
    ap.add_argument("--key", required=True, help="PEM private key for --cert")
    ap.add_argument("--delay", type=float, default=0,
                    help="hold each response N seconds (JIT window: lets the patcher "
                         "apply memory patches after all VMP checks, before verify runs)")
    ap.add_argument("--expires-text", default=None,
                    help="custom string sent as expires_at (shows up verbatim in the "
                         "cheat's '[+] Expires At :' line, e.g. a tag). Default: "
                         "integer epoch 1893456000. NOTE: if the parser needs a "
                         "number, a string brings back INVALID RESPONSE — then drop it.")
    ap.add_argument("--forward", action="store_true",
                    help="MITM-forward mode: relay each request to the REAL vendor "
                         "(real key => real offsets), capture every reply verbatim "
                         "to offsets_capture_<ts>.json, return it untouched. "
                         "Needs: hosts redirect + our CA trusted + no cert pinning.")
    ap.add_argument("--vendor-dns", default="8.8.8.8",
                    help="DNS server used to resolve the vendor's real IP "
                         "(bypasses the hosts redirect).")
    ap.add_argument("--zero-offsets", action="store_true",
                    help="Experiment: serve 0x0 for ALL typeinfo keys — tests "
                         "whether the DLL resolves classes locally (the real "
                         "server already sends typeinfo_character_model=0).")
    args = ap.parse_args()
    Handler.DELAY = args.delay
    global FORWARD, VENDOR_DNS, ZERO_OFFSETS
    FORWARD = args.forward
    VENDOR_DNS = args.vendor_dns
    ZERO_OFFSETS = args.zero_offsets
    if FORWARD:
        _say("FORWARD mode: replies come from the real vendor and are captured.")
    if ZERO_OFFSETS:
        _say("ZERO-OFFSETS experiment mode: all typeinfo keys served as 0x0.")
    global EXPIRES_TEXT
    EXPIRES_TEXT = args.expires_text
    for p in (args.cert, args.key):
        if not os.path.exists(p):
            _say(f"missing file: {p} (see FAKE_SERVER_GUIDE.md step 2)")
            raise SystemExit(2)
    srv = HTTPServer(("0.0.0.0", args.port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    _say(f"fake license server on 0.0.0.0:{args.port} (TLS). Waiting for cheat requests...")
    _say(f"requests logged to {REQLOG}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
