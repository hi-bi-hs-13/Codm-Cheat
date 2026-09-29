@echo off
REM Drag & drop the cheat EXE onto this .bat (or: run_patched.bat "C:\path\cheat.exe" --jit requests_log.jsonl)
REM Must run as Administrator (right-click -> Run as administrator).
REM NOTE: do NOT cd — relative args (like the --jit log path) must resolve
REM against the caller's directory.
"%~dp0venv\Scripts\python.exe" "%~dp0run_patched.py" %*
