#!/usr/bin/env python3
"""Minimal MCP client for the local IDA Pro MCP server (POST /mcp, JSON-RPC)."""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:13338/mcp"


def rpc(method, params=None, rpc_id=1):
    payload = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(BASE, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json, text/event-stream"})
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa - diagnostic tool
        return {"_error": repr(e)}


def main():
    print("== initialize ==")
    print(json.dumps(rpc("initialize", {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "opencode-probe", "version": "1.0"}}), indent=1)[:1500])
    print("== tools/list ==")
    res = rpc("tools/list", {}, rpc_id=2)
    s = json.dumps(res)
    print(s[:3000])
    if len(sys.argv) > 1 and sys.argv[1] == "full":
        print(s[3000:])


def call_tool(name, args, rpc_id=10):
    res = rpc("tools/call", {"name": name, "arguments": args}, rpc_id=rpc_id)
    try:
        parts = res["result"]["content"]
        out = []
        for p in parts:
            if p.get("type") == "text":
                out.append(p.get("text", ""))
        return "\n".join(out)
    except Exception:  # noqa - diagnostic tool
        return json.dumps(res)[:4000]


if __name__ == "__main__":
    main()
