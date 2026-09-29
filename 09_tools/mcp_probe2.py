#!/usr/bin/env python3
"""Find the MCP tool-call endpoint of the local IDA Pro MCP server."""
import re
import urllib.request

BASE = "http://127.0.0.1:13338"


def get(path, data=None, ctype=None):
    try:
        req = urllib.request.Request(BASE + path, data=data,
                                     headers={"Content-Type": ctype} if ctype else {})
        r = urllib.request.urlopen(req, timeout=8)
        return r.status, r.read()
    except Exception as e:  # noqa - probe
        return None, repr(e).encode()


def main():
    _, html = get("/config.html")
    h = html.decode("utf-8", "replace")
    print("---- urls/paths referenced in page ----")
    for m in sorted(set(re.findall(r"(?:https?://127\.0\.0\.1:13338)?(/[A-Za-z0-9_\aretl./?-]*)", h))):
        if len(m) > 1:
            print(repr(m))
    print("---- probe likely MCP transports ----")
    for p in ["/mcp", "/sse", "/messages", "/api", "/tools", "/rpc",
              "/mcp/sse", "/sse/", "/mcp/tools", "/health", "/api/health"]:
        st, body = get(p)
        print(p, "->", st, body[:150])


if __name__ == "__main__":
    main()
