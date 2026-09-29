#!/usr/bin/env python3
"""brute_force_sig.py — recover the vendor response-signature formula OFFLINE.

Inputs (all local, no network):
  - offsets_capture_*.json  (real vendor LOGIN_SUCCESS replies: nonce, signature,
    offsets_signature, server_time, ...)
  - requests_log.jsonl      (our own requests: key, hwid, timestamp, nonce, signature)
  - HMAC secret (reversed 2026-09-19 from the unpacked loader, CRACK_STATUS.md):
      mQ8vT9zR4pK7xN2cY6sL0aH3dF1wE5uB9jG2nV7qZ4tC8rX6yP1kS5

Stage 1: verify the REQUEST signature format against captured requests
         (sanity check that HMAC-SHA256(secret, msg).hexdigest() is the scheme).
Stage 2: brute-force the LOGIN response `signature` message over subsets/
         permutations of the reply fields.
Stage 3: brute-force `offsets_signature` over offsets encodings.
"""
import glob, hashlib, hmac, itertools, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET = b"mQ8vT9zR4pK7xN2cY6sL0aH3dF1wE5uB9jG2nV7qZ4tC8rX6yP1kS5"

def H(msg):
    if isinstance(msg, str):
        msg = msg.encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()

# ---------- load captures ----------
caps = []
for p in sorted(glob.glob(os.path.join(HERE, "offsets_capture_*.json"))):
    try:
        j = json.load(open(p, encoding="utf-8"))
    except Exception:
        continue
    if j.get("code") == "LOGIN_SUCCESS" and j.get("signature"):
        caps.append(j)
print(f"loaded {len(caps)} LOGIN_SUCCESS captures")
if not caps:
    sys.exit(1)

# ---------- stage 1: request-side sanity ----------
reqs = []
for line in open(os.path.join(HERE, "requests_log.jsonl"), encoding="utf-8"):
    try:
        r = json.loads(line)["req"]
    except Exception:
        continue
    if r.get("key") and r.get("signature"):
        reqs.append(r)
print(f"loaded {len(reqs)} requests")

req_hit = None
for r in reqs:
    msg = "|".join([r["key"], r["hwid"], r["app_id"], r["app_version"],
                    r["timestamp"], r["nonce"]])
    if H(msg) == r["signature"]:
        req_hit = (r, msg)
        break
print("STAGE1 request-format check:",
      "MATCH -> " + (req_hit[1] if req_hit else "no match with known format"))

# ---------- stage 2: login response signature ----------
FIELDS = ["success", "code", "message", "server_time", "expires_at", "hwid", "nonce"]
def val(c, f):
    v = c.get(f)
    return "true" if v is True else ("false" if v is False else str(v))

found = None
tried = 0
for k in range(1, 7):
    for combo in itertools.permutations(FIELDS, k):
        base = [val(caps[0], f) for f in combo]
        for extra in ([], [""]):           # trailing separator variants
            msg = "|".join(base + extra) if extra else "|".join(base)
            tried += 1
            if H(msg) == caps[0]["signature"]:
                found = combo
                break
        if found:
            break
    if found:
        break
print(f"STAGE2 login signature: tried {tried} formats ->",
      ("MATCH fields=" + str(found)) if found else "no match in simple space")

if found:
    ok = all(H("|".join(val(c, f) for f in found)) == c["signature"] for c in caps)
    print("  verifies on ALL captures:", ok)
    LOGIN_FIELDS = found
else:
    LOGIN_FIELDS = None

# ---------- stage 3: offsets_signature ----------
ti_keys = [k for k in caps[0] if k.startswith("typeinfo_")]
orders = [ti_keys, sorted(ti_keys)]
encs = [
    lambda ks, c, sep: sep.join(f"{k}={c[k]}" for k in ks),
    lambda ks, c, sep: sep.join(str(c[k]) for k in ks),
]
prefixes = ["", "typeinfo-v1|", "offsets-v1|"]
suffixes = ["", "|nonce", "|hwid", "|hwid|nonce", "|nonce|hwid"]
found3 = None
tried3 = 0
for ks in orders:
    for enc in encs:
        for pre in prefixes:
            for suf in suffixes:
                for c in caps[:2]:
                    body = enc(ks, c, "|")
                    tail = ""
                    if "nonce" in suf: tail += c["nonce"]
                    if "hwid" in suf: tail += ("|" if tail else "") + c["hwid"]
                    for cand in (pre + body + (("|" + tail) if tail else ""),
                                 pre + body + (("|" + tail) if tail else "") + "|"):
                        tried3 += 1
                        if H(cand) == c["offsets_signature"]:
                            found3 = cand
                            break
                    if found3: break
                if found3: break
            if found3: break
        if found3: break
    if found3: break
print(f"STAGE3 offsets_signature: tried {tried3} formats ->",
      ("MATCH msg=" + found3[:120]) if found3 else "no match in simple space")

json.dump({"login_fields": found, "offsets_msg": found3},
          open(os.path.join(HERE, "sig_formula.json"), "w"), indent=1)
print("saved sig_formula.json")
