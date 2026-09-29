#!/usr/bin/env python3
"""Probe the local IDA Pro MCP server for usable API endpoints."""
import re
import urllib.request

BASE = "http://127.0.0.1:13338"


def get(path):
    try:
        r = urllib.request.urlopen(BASE + path, timeout=8)
        return r.status, r.read()
    except Exception as e:  # noqa - probe
        return None, str(e).encode()


def main():
    st, body = get("/config.html")
    print("config.html:", st, len(body), "bytes")
    html = body.decode("utf-8", "replace")
    text = re.sub(r"<script.*?</script>", " ", html, flags=re.S)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    print("---- page text (first 3000 chars) ----")
    print(text[:3000].encode("ascii", "replace").decode())
    print("---- candidate endpoints/urls ----")
    for m in sorted(set(re.findall(r"/[A-Za-z0-9_\aretl./-]{2,60}", text))):
        print(m)


if __name__ == "__main__":
    main()
