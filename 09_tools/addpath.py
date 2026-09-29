#!/usr/bin/env python3
"""Add the project root to the *user* PATH so server.bat/cheat.bat run from anywhere."""
import os
import winreg

ROOT = r"C:\Users\<user>\Desktop\Codm-Dump\iacpc"

with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                    winreg.KEY_READ | winreg.KEY_WRITE) as k:
    try:
        cur, _ = winreg.QueryValueEx(k, "Path")
    except FileNotFoundError:
        cur = ""
    if ROOT.lower() in cur.lower():
        print("PATH already has it")
    else:
        winreg.SetValueEx(k, "Path", 0, winreg.REG_EXPAND_SZ,
                          cur + (";" if cur and not cur.endswith(";") else "") + ROOT)
        print("PATH updated (open a NEW console to use it)")


print("files:", sorted(f for f in os.listdir(ROOT) if f.endswith(".bat")))
