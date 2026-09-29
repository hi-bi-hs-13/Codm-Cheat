# BestCheatIR CODM Cheat — Full Reverse-Engineering Package

> **Research / educational archive.** Complete binary analysis of a commercial
> Call of Duty: Mobile cheat ("CODM LOADER"), including the
> packed sample, fully unpacked images, license-protocol crack, anti-cheat
> bypass documentation, and every methodology used — published so the sample
> remains available to future binary-analysis researchers.

- Vendor Telegram: [t.me/anogs](https://t.me/anogs) · [t.me/pouria_cheat](https://t.me/pouria_cheat)
- Product: "CONTROL CENTER — CODM cheat", compatible with CODM v1.0.57, VMProtect 3.x packed, signed with a **misused Sectigo certificate belonging to MB Oyun Yazilim A.S. (Istanbul, TR)** — reportable to Sectigo.

---

## ⚠️ Safety & legal

- **DO NOT RUN any binary in this repo on your daily system.** See
  [`01_reports/MALWARE_ASSESSMENT.md`](01_reports/MALWARE_ASSESSMENT.md):
  admin-required loader, writes `C:\Windows\System32\ext.dll`, remote-thread
  injection into emulator processes, persistent C2 with cloud kill-switch,
  remote-offset delivery (attacker-controlled payload channel), HWID exfil.
  Every login attempt uploads your HWID to the vendor.
- All samples are provided **as-is for static/dynamic analysis in isolated VMs**
  with snapshots. SHA256 of every binary: [`SHA256SUMS.txt`](SHA256SUMS.txt).
- The loader binary (`02_samples/test.bin`) was purchased legitimately by the
  researcher; this archive exists for preservation and study, not for
  distribution-as-a-product. No license keys are included (redacted).

---

## TL;DR findings

| # | Finding | Details |
|---|---------|---------|
| 1 | **Unpacking** | VMProtect 3.x, 14 protection layers defeated with Unicorn emulation → `.text` 85% / `.rdata` 98% recovered ([METHODOLOGY](01_reports/METHODOLOGY.md) M1) |
| 2 | **License protocol fully cracked** | Request/response both HMAC-SHA256 with the reversed secret; **response signature formula recovered offline** by brute-forcing 8 captured real replies: `HMAC(secret, "true\|LOGIN_SUCCESS\|server_time\|expires_at\|hwid\|nonce")` |
| 3 | **Crash root cause** | The vendor DLL (VMP) silently kills the emulator host process when the login reply is not correctly signed — even with the loader's signature check patched out. Fixing the fake server's signature made everything work **with zero binary patches** |
| 4 | **"Local resolution" myth debunked** | Serving `0x0` for all 16 typeinfo offsets still works — but not via local resolution: the parser uses an **atomic commit** (any failed key ⇒ no globals written ⇒ compiled defaults survive). Works only while defaults match the game build |
| 5 | **Game's custom TypeInfo structure decoded** | `Il2CppClass = *( *( *(TypeInfo+0x58) + 0x78 ) + 0x10 )` (validator `0x18002bb30`); standard `klass->name` reads fail because these are *not* standard Il2CppClass objects |
| 6 | **Architecture** | Loader (overlay/render, ImGui-style menu) ↔ DLL injected into `MuMuNxDevice.exe` (guest memory reads via in-process mapping, camera chain `base+OFF0 → +0x78 → +0x70 → +0x150 → +0xC0 → +0x10 → +0xC0`), pushes 0xBB0-byte records into the loader heap via WPM (push-only IPC, zero loader-side reads — ProcMon-proven) |
| 7 | **Security assessment** | Gray-zone trojan TTPs beyond a usual cheat: see the assessment report; IOC list included |

---

## Repository layout

```
01_reports/            ← the analysis itself (start here)
  CODM_Loader_Analysis_Progress.txt   main unpacking report (14 layers, protocol)
  CODM_ESP_Aimbot_BulletTrack_Logic.txt  full cheat logic: chains, globals, pseudo-code
  SESSION5_LIVE_2026-09-23.md         live validation: MITM, IPC, records
  SESSION6_CRASH_SOLVED_2026-09-26.md crash root cause + signature crack + fix
  REAL_OFFSETS_2026-09-23.md          real vendor typeinfo offsets (MITM capture)
  CHEAT_OFFSETS_REFERENCE.txt         the 16-offset protocol + refresh strategies
  RESOLVER_ANALYSIS.md                typeinfo parser/validator reverse-engineering
  RESOLVER_DISASM*.txt                raw disassembly evidence
  METHODOLOGY.md                      all methods, consolidated & reproducible
  MALWARE_ASSESSMENT.md               threat assessment + IOCs
  EXT_MEM_CAMERA_RESEARCH.md          live DLL camera-chain research
02_samples/            ← original packed loader (test.bin)
03_dumps_loader/       ← unpacked loader images (85-98% recovered)
04_dumps_dll_layer2/   ← unpacked injected DLL (final_FULLIMAGE.bin = main artifact)
05_live_dll/           ← live-decrypted DLL dumped from the emulator process
06_asm_disassembly/    ← annotated asm of every cheat feature
07_strings_logs/       ← string/table extraction evidence
09_tools/              ← all tooling: unpackers, fake license server (cracked
                         signatures), JIT patcher, memtap, offline signature
                         brute-forcer, resolver hunters, live memory readers
```

## Reproducibility

Every claim traces to a script in `09_tools/` or a raw disassembly dump.
Start with [`01_reports/METHODOLOGY.md`](01_reports/METHODOLOGY.md) for the
how-to (Unicorn unpacking, forward-MITM captures, offline HMAC brute-force,
memtap, adb-root live memory analysis), then read the reports in the order
above.

*Persian summary (خلاصه فارسی): این مخزن آرشیو تحقیقاتیِ کامل یک چیت تجاری
CODM است — آنپک کامل VMProtect، کرک کامل پروتکل لایسنس (فرمول امضای HMAC)،
ریشه‌یابی کرش، ساختار TypeInfo سفارشی بازی، و تمام متدولوژی. نمونه‌ها فقط
برای تحلیل در ماشین مجازی ایزوله؛ اجرا روی سیستم اصلی ممنوع. کلید لایسنس و
HWID حذف (redact) شده‌اند.*
