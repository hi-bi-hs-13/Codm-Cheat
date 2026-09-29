# Session 5 (2026-09-23) — live validation: forward-MITM, IPC channel, live records
Complements: session-4 bypass docs, ESP logic report, REAL_OFFSETS_2026-09-23.md.
Everything below was proven LIVE (real cheat PBC-1.0.57 + real key + MuMu match).

## 1. Forward-MITM (--forward): real offsets captured
- Design: hosts `api.bestcheatir.com -> 127.0.0.1` + our CA trusted; server
  accepts cheat TLS, relays request VERBATIM to vendor (real IP via explicit
  DNS 8.8.8.8 bypassing hosts: `5.144.129.131`), SNI kept, real cert verified,
  reply returned untouched + saved to `offsets_capture_<ts>.json`.
- Validated keyless first: GET /CODM -> 404 HTML relayed byte-identical.
- Live run with real key `7D74-...`: LOGIN_SUCCESS, expires `2026-10-18`,
  all 16 typeinfo keys + offsets_signature. Files: offsets_capture_*.json.
- Signature is per-request (nonce-bound): two captures minutes apart have
  IDENTICAL offsets but DIFFERENT signatures. Replay of old replies fails on
  unpatched cheat; our P1-P5 patches bypass verify anyway.
- Usage: `server.bat` menu option 2. With real key + real sig, UNPATCHED cheat
  also passes (patches + real response coexist harmlessly).
- fake_server.py OFFSETS table was zip-MISALIGNED by name; fixed to the real
  name->value mapping (only true delta vs dump defaults: character_model=0x0).

## 2. License flow specifics (observed)
- Request (FORM): app_id=my_cpp_app, app_version=1.0.14, hwid, key, nonce,
  signature, timestamp. UA: LicenseClient/1.0. Every attempt (even rejected)
  uploads HWID to vendor. Cheat caches key ("Saved license key found").
- Loader does HTTPS (URL lives in LOADER image, curl statically linked);
  DLL only consumes offsets ("REMOTE TYPEINFO OFFSETS APPLIED" in ITS rdata).

## 3. Launcher<->DLL channel — solved (elimination + proof)
- NOT TCP (zero connections while ESP draws), NOT pipes (empty list),
  NOT files (zero hot files in 15 min while ESP draws),
  NOT named shared section (handle_enum on both PIDs: only generic/system
  objects shared + one VMP-obfuscated mutant `CDdf...`).
- IS: (a) UDP localhost `MuMuNxDevice:50092 -> 127.0.0.1:4042` (ProcMon:
  4672 datagrams/32s ≈145/s; sizes 2992/11968/14960 = 1x/4x/5x 0xBB0 records),
  (b) steady-state render data pushed via WPM into loader heap: frame records
  sit in PBC heap (memtap-proven) while PBC makes ZERO read syscalls
  (ProcMon: 30 profiling events only) and ZERO socket reads (Frida hooks on
  recvfrom/recv/WSARecv/WSARecvFrom/ReadFile/IOCTL all silent while ESP draws).
- Loader IAT has only 12 trivial funcs (VMP stripped the rest; everything via
  GetProcAddress) — why static analysis never showed the channel.
- PBC modules: NO MuMuVMM/VBoxVMM (no direct guest reads), d3d9/dxgi present
  (overlay render in loader), schannel (license TLS).
- ext.dll lives ONLY in MuMuNxDevice (tasklist /m); on-disk copy
  (System32) is ENCRYPTED (scrambled PE, entropy ~7.9, zero strings).
  Live-decrypted copy dumped via RPM: `ext_mem_20260923_130131.dll` (10.6MB).
  RVAs IDENTICAL to old unpacked dump (base 0x180000000 vs live
  0x7fffb8700000) — all prior RE applies 1:1 to the live build.

## 4. Live record findings (loader heap, in-match, focused)
- Layout 0xBB0 confirmed: marker +0x460, id +0x4A0, frame-counter +0x4A8,
  dist float +0x514, active +0x518, name +0x51A ("[BOT]..." seen),
  view matrix (Matrix rec) +0x55C, rotation-row norm EXACTLY 1.0.
- Focus-gating: unfocused emulator => DLL writes EMPTY frames (zeros, no
  players). All captures must be taken while focused in-match.
- Self pawn is NOT listed (observer): expect N-1 players.
- "disconnected" menu + seconds-later silent crash == emulator not open
  (VMM finds no session; frame loop AVs on invalid base). With fake offsets
  the same crash happens even WITH emulator (wrong chain => AV) — NOT a
  bypass bug. MuMu itself hung once (EventLog 06:17, Windows closed it).

## 5. Tool inventory (09_bypass_session4/)
- server.bat (menu: 1 fake / 2 forward; kills stale servers; asks on 443 busy)
- cheat.bat (visible / hidden+auto-key) ; server.vbs/cheat.vbs (fully hidden)
- fake_server.py (--forward, --delay, --expires-text; logs requests_log.jsonl)
- run_patched.py (5 patches P1-P5, JIT, auto-captures ext.dll -> ext_dropped.dll)
- memtap.py (RPM frame tap: --exe/--loop/--warmup; scan-all + matrix validation)
- handle_enum.py (admin; named Section/Event/Mutant/ALPC per PID + SHARED list)
- udp_hook.py (Frida recv*/ReadFile/IOCTL taps on loader)
- wpmpush_hook.py (Frida WPM tap on emulator side)
- moddump.py (dump live module bytes, e.g. decrypted ext.dll)
- Logfile_cheat.csv (92k filtered ProcMon rows: the UDP proof)

## 6. Dead ends (do NOT retry without new info)
- Frida inject into MuMuNxDevice: agent stays dead (anti-inject hardening).
- Static analysis of on-disk ext.dll / packed loader: encrypted/VMP, zero yield.
- udp_hook zero-calls explained (steady-state has no loader-side reads).
- memtap empty-file bug (re-read windows): fixed by returning read chunks.

## 7. Operational notes
- Port 443 conflicts: XAMPP Apache (proven twice), NOT Hyper-V (checked
  excluded ranges), NOT Windscribe (suspected, cleared — but Quit it anyway).
- UAC slider at minimum + admin => silent elevation; "no UAC" is normal.
- server_launch_err.log captures hidden-server failures.
- hosts must contain: 127.0.0.1 api.bestcheatir.com
