# جدول کامل پاسخ سرور + نقاط مرجع (استخراج 2026-09-20، نشست ۴)

منبع: image آنپک لودر (`unpacked_full_memory_image.bin`) — اسکن LEA RIP-relative
در بازه `0x140068e00–0x14006fxxx` (دیسپچر اصلی کلاینت: لایسنس + کش + IPC + injector).

## جدول code -> message (به ترتیب حافظه، VA رشته‌ها)
| code VA | code | message |
|---|---|---|
| 0x1406c3240 | LOGIN_SUCCESS | Login successful (0x1406c3250) |
| 0x1406c3268 | MISSING_FIELDS | Request is incomplete |
| 0x1406c3290 | INVALID_METHOD | Invalid HTTP method |
| 0x1406c32b8 | INVALID_TIMESTAMP | Client/server time mismatch |
| 0x1406c32f0 | REPLAY_DETECTED | Replay detected |
| 0x1406c3310 | RATE_LIMITED | Too many requests |
| 0x1406c3338 | INVALID_SIGNATURE | Invalid request signature |
| 0x1406c3370 | INVALID_KEY | Invalid license key |
| 0x1406c3398 | KEY_DISABLED | License key is disabled |
| 0x1406c33c0 | KEY_EXPIRED | License key is expired |
| 0x1406c33e8 | HWID_MISMATCH | License key is bound to another ... |
| 0x1406c3420 | APP_VERSION_OUTDATED | Your app version is outdated. Pl... |
| 0x1406c3488 | SERVER_ERROR | Server error |
| 0x1406c34a8 | (fallback) | Unknown response |

ارجاع‌دهنده‌ها (برای یافتن verify): `0x1400694e0` (LOGIN_SUCCESS)،
`0x140069511/525/546/55a/57b/58f/5b0/5c3/5e4/5f8/619/62d/64e/662/683/697/6b8/6cc/6ed/701/71f/733/74e/764/76d`.

## فیلدهای JSON پاسخ (VA)
`code` 0x1406c31f8 (ref 0x14006e13c) | `server_time` 0x1406c3200 |
`expires_at` 0x1406c3210 (ref 0x14006e94f) | `hwid` 0x1406c321c (ref 0x14006d4de) |
`nonce` 0x1406c3224 (ref 0x140068f44) | `signature` 0x1406c3230 (ref 0x1400691ee)

## کانتکست HMAC دوم (امضای پاسخ) — `call 0x140065760` در `0x140069158`
- ورودی‌ها: `rcx=[rbp+0xf]` (بافر پیام ساخته‌شده)، `rdx=rax` از `call 0x140067ad0`
- بافر با جداکننده `'|'` (ref در `0x140069b62` → VA 0x1406c0500) و گلوبال‌های
  `0x1406dac28/48/58/88/98` (std::string های secret/app_id/version) ساخته می‌شود
  (ارجاع‌ها در `0x140069b2e/42/49/7e/85/95`).
- پرچم `r14b`: مقایسه فیلد (`call 0x1400e794c` در `0x140069074`) → نامساوی
  (`r14b=1`) یعنی پرش از HMAC (`jne 0x14006946a` در `0x14006913a`)؛ مساوی یعنی محاسبه HMAC.
- فرمول دقیق پیام هنوز باز است (نیاز به دیساسمبلی کامل `0x14006903c–0x140069158`)؛
  حدس اول از روی الگوی درخواست: `server_time|expires_at|hwid|nonce` با همان secret.

## مسیر کش آفلاین (ارجاع‌ها)
- `[+] Saved license key found` ← `0x14006c79f`
- `ENTER YOUR LICENSE KEY` ← `0x14006ca86` | `>> ` ← `0x14006cc18`
- `LICENSE ERROR` / `[X] License key is required` ← `0x14006ccda/6ce38`
- `\\license.key` ← `0x140069a63` | `C:\Windows\System32\keysex.txt` ← `0x14006e236`
- `HEARTBEAT` ← `0x14006fa09` (تأیید دوره‌ای = kill-switch ابری)

## مسیر injector بعد از VERIFY (برای ویدیو: رسیدن به اینجا = اثبات بایپس)
- `LICENSE VERIFIED` ← `0x14006e6c8` | `[+] Expires At : ` ← `0x14006e987`
- `[*] Waiting for target process..` ← `0x14006ed65`
- `[*] Targets: MuMuPlayer or LDPla...` ← `0x14006ed65`
