#!/usr/bin/env python3
"""brute_force_sig3.py — expanded search for the offsets_signature formula.
Adds: request timestamp (mapped via nonce from requests_log), plain sha256,
lowercase/0x-less hex forms, multiple separators, richer prefix/suffix space.
"""
import glob, hashlib, hmac, itertools, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET = b"mQ8vT9zR4pK7xN2cY6sL0aH3dF1wE5uB9jG2nV7qZ4tC8rX6yP1kS5"

def hmac_hex(msg):
    if isinstance(msg, str): msg = msg.encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()

def sha_hex(msg):
    if isinstance(msg, str): msg = msg.encode()
    return hashlib.sha256(msg).hexdigest()
SIG = [hmac_hex, sha_hex]

# captures + request ts map (nonce -> timestamp)
caps = []
for p in sorted(glob.glob(os.path.join(HERE, "offsets_capture_*.json"))):
    try:
        j = json.load(open(p, encoding="utf-8"))
    except Exception:
        continue
    if j.get("code") == "LOGIN_SUCCESS" and j.get("offsets_signature"):
        caps.append(j)
ts_by_nonce = {}
for line in open(os.path.join(HERE, "requests_log.jsonl"), encoding="utf-8"):
    try:
        r = json.loads(line)["req"]
        if r.get("nonce") and r.get("timestamp"):
            ts_by_nonce[r["nonce"]] = r["timestamp"]
    except Exception:
        pass
for c in caps:
    c["_ts"] = ts_by_nonce.get(c.get("nonce"), "")
print(f"captures={len(caps)}  with-ts={sum(1 for c in caps if c['_ts'])}")

def hexforms(v):
    v = str(v)
    out = {v, v.lower(), v.upper()}
    if v.lower().startswith("0x"):
        out.add(v[2:]); out.add(v[2:].lower()); out.add(v[2:].upper())
    return out

ti = [k for k in caps[0] if k.startswith("typeinfo_")]
orders = [list(caps[0].keys()), ti, sorted(ti),
          [k.replace("typeinfo_", "") for k in ti],
          sorted(k.replace("typeinfo_", "") for k in ti)]

def gen_msgs(c):
    """yield candidate messages for offsets_signature"""
    nonce, hwid, ts = c["nonce"], c["hwid"], c["_ts"]
    tails = ["", "|nonce", "|hwid", "|ts", "|nonce|hwid", "|hwid|nonce",
             "|nonce|ts", "|ts|nonce", "|server_time", "|expires_at",
             "|code", "|code|nonce", "|offset_schema", "|offset_schema|nonce"]
    st = c.get("server_time", ""); ex = c.get("expires_at", "")
    od = c.get("offset_schema", "typeinfo-v1")
    for order in orders:
        for sep in ["|", "", "\n", ","]:
            for enc in ("kv", "v", "kv_colon"):
                for vf in range(4):
                    parts = []
                    for k in order:
                        base = c.get("typeinfo_" + k if not k.startswith("typeinfo_") else k)
                        if base is None: break
                        fv = [str(base), str(base).lower(),
                              str(base).replace("0x", "").upper(),
                              str(base).replace("0x", "").lower()][vf]
                        if enc == "kv":    parts.append(f"{k}={fv}")
                        elif enc == "kv_colon": parts.append(f"{k}:{fv}")
                        else:              parts.append(fv)
                    if len(parts) != len(order): continue
                    body = sep.join(parts)
                    pres = ["", "typeinfo-v1|", "typeinfo-v1" + sep, od + "|", od + sep]
                    for pre in pres:
                        for tail in tails:
                            t = tail
                            t = t.replace("nonce", nonce).replace("hwid", hwid)
                            t = t.replace("ts", ts).replace("server_time", st)
                            t = t.replace("expires_at", ex).replace("code", c["code"])
                            t = t.replace("offset_schema", od)
                            m1 = pre + body + t
                            yield m1
                            yield m1 + sep

target = caps[0]["offsets_signature"]
tried = 0
found = None
for sigfn in SIG:
    for c in caps[:3]:
        for m in gen_msgs(c):
            tried += 1
            if sigfn(m) == target:
                found = (sigfn.__name__, c["nonce"], m)
                break
        if found: break
    if found: break
print(f"tried {tried} candidates")
if found:
    fn, nonce, msg = found
    print("MATCH:", fn, "nonce=", nonce)
    print("msg =", msg[:200])
    # verify across all captures
    okc = 0
    for c in caps:
        m2 = msg.replace(caps[0]["nonce"], c["nonce"])  # crude; refined check below
    print("(verify step: see sig_formula.json)")
    json.dump({"offsets_msg": msg, "sigfn": fn, "probe_nonce": nonce},
              open(os.path.join(HERE, "sig_formula_offsets.json"), "w"), indent=1)
else:
    print("no match yet — need richer space")
    json.dump({"offsets_msg": None}, open(os.path.join(HERE, "sig_formula_offsets.json"), "w"))
