# وضعیت کرک CODM Loader — نشست ۴ (2026-09-20)

## پروتکل (۱۰۰٪ حل‌شده، از part1 + ریپورت v5)
- سرور: `https://api.bestcheatir.com/CODM` (XOR 0xAB در rdata لودر @VA 0x1406c48e0 و DLL @0x1800b12c0)
- درخواست JSON: `key, hwid, app_id=my_cpp_app, app_version=1.0.14, timestamp, nonce, signature`
- پیام امضا: `key|hwid|my_cpp_app|1.0.14|timestamp|nonce` + SEP=`|`
- امضا: HMAC-SHA256 با secret=`mQ8vT9zR4pK7xN2cY6sL0aH3dF1wE5uB9jG2nV7qZ4tC8rX6yP1kS5` (۵۴ کاراکتر، تابع 0x140065760، SHA256 ثابت 0x6a09e667 در 0x140064c50، پدهای xor 0x5c/0x36)
- HWID: `hex(SHA256(GetComputerNameA+"|local-hwid-salt"))[:32]` — setw(2)+hex، salt=`|local-hwid-salt` (۱۶ بایت)
- nonce: دو uint64 تصادفی به hex (۱۶ کاراکتر)، timestamp: decimal، UA=`LicenseClient/1.0`
- پاسخ: `code, server_time, expires_at, hwid, nonce, signature` + کدهای LOGIN_SUCCESS/MISSING_FIELDS/INVALID_METHOD/INVALID_TIMESTAMP/REPLAY_DETECTED/RATE_LIMITED/INVALID_SIGNATURE/INVALID_KEY/KEY_DISABLED/KEY_EXPIRED/HWID_MISMATCH/APP_VERSION_OUTDATED/SERVER_ERROR

## تابع لاگین (آنپک‌شده، در .text)
- سازنده درخواست در `0x14006d400` (call HMAC در `0x14006d475` به `0x140065760`) — دیساسمبلی سالم
- ارجاع‌های رشته لایسنس در `.text 0x14006cf02-0x14006ef02` پیدا شد (۶۰+ LEA به ناحیه `0x1406c3000-0x1406c4000`):
  - `0x14006e1eb -> LOGIN_SUCCESS`، `0x14006e6c8 -> LICENSE VERIFIED`، `keysex.txt @0x1406c3a1c` و غیره
- پیام‌های مسیر کرک: `[+] Saved license key found` (@0x1406c38ac)، `[*] Logging in`، `[X] Invalid server signature` (@0x1406c39ec)، `[X] Server response is invalid`، `LICENSE VERIFIED`، `C:\Windows\System32\keysex.txt`

## مانع فعلی کرک
- ناحیه تأیید پاسخ (`~0x14006e1eb` به بعد) در دامپ ۸۵٪ .text هنوز رمز است (Capstone بعد از ۱ دستور `add al,ch` می‌ایستد — بایت‌های صفر/رمزنشده). Lazy-decryption VMP آن را فقط در زمان اجرا (بعد از عبور از چک debugger) باز می‌کند.
- `CryptUnprotectData` در image نیست (فقط `CryptProtectData` @0x131e3932) — مسیر load کش باید در کد رمز باقی‌مانده باشد.
- چک نهایی VM (`A debugger has been found...`) هنوز باز است (بعد از IAT storm) — بدون عبور از آن، نه verification باز می‌شود نه می‌توان سرور فیک را داینامیک تست کرد.

## سه مسیر کرک (به ترتیب سختی)
1. **کش آفلاین (keysex.txt + \license.key):** پیام `[+] Saved license key found` یعنی بدون شبکه هم می‌شود وارد شد. باید تابع load کش (اطراف رشته 0x1406c38ac) بعد از آنپک کامل دیده شود + فرمت plaintext قبل از CryptProtectData (احتمالاً JSON با expires_at). DPAPI user-bound است پس باید روی همان ماشین با CryptProtectData ساخت.
2. **سرور فیک (hosts redirect):** `api.bestcheatir.com -> 127.0.0.1` + پاسخ `LOGIN_SUCCESS` با `signature` معتبر. فرمول امضای پاسخ هنوز نامعلوم (حدس: HMAC(secret, server_time|expires_at|hwid|nonce)) — باید از دیساسمبلی رمزگشایی‌شده ناحیه 0x14006e2xx استخراج شود.
3. **پچ باینری (force LICENSE VERIFIED):** پیدا کردن `strcmp(code,"LOGIN_SUCCESS")` + `je` بعد از curl و NOP/patch به `jmp` همیشه موفق. باز هم نیاز به آنپک کامل ناحیه 0x14006e1xx دارد.

## پچ accept-any-key (2026-09-20) ✅ ساخته و تأیید شد
- ابزار: `09_bypass_session4/patch_accept_any_key.py` → خروجی `out/patched_FULLIMAGE_accept_any_key.bin`
- سه پچ (همه روی image آنپک، نه test.bin پک):
  1. `0x14006e201: JE->NOP×6` (چک code #1)
  2. `0x14006e21d: JE->NOP×6` (چک code #2)
  3. `0x14006e287: JNE 0x14006e5be -> JMP 0x14006e5be` (چک `call 0x14006a360` امضای پاسخ)
- اثر: هر کلیدی (حتی INVALID_KEY) وارد مسیر LICENSE VERIFIED می‌شود. آفلاین خالص (curl fail) پوشش داده نمی‌شود — سرور فیک با هر JSON دارای code کافی است.
- هشدارها: پچ دیسک = `File corrupted 0xDEADC0DE` (integrity از نوع SEC_COMMIT) — فقط patch حافظه بعد از Map/Unmap. و طبق تأیید تو: بدون LOGIN_SUCCESS واقعی افست ریموت نمی‌آید (fallback به defaults قدیمی) پس عملاً غیرقابل استفاده — فقط اثبات بایپس، نه چیت کارا.

## لانچر اجرای واقعی (2026-09-20) ✅ مکانیک تأیید شد
- `run_patched.py` + `run_patched.bat` (درگ‌اندراپ چیت روی bat، ادمین اجباری).
- suspend → بیس از PEB (ASLR-safe) → poll تا decrypt → ۳ پچ + verify → رها.
- سلف‌تست روی `conhost.exe`: همه مراحل سبز (شامل فیکس باگ truncate آدرس ۶۴ بیتی).
- اجرای چیت واقعی فقط روی VM ایزوله با راهنمای `RUN_GUIDE.md` (اینجا اجرا نشد).
- خروجی مورد انتظار با کلید شانسی: `LICENSE VERIFIED` → `Waiting for target process`.

## سرور فیک (2026-09-20) ✅ منطق تست شد
- `fake_server.py`: پاسخ `LOGIN_SUCCESS` + echo hwid/nonce + ۱۶ افست (flat و `typeinfo-v1`) — سلف‌تست POST واقعی سبز.
- اجرا فقط همراه `run_patched.py` (وگرنه `Invalid server signature`).
- راهنما: `FAKE_SERVER_GUIDE.md` — hosts، CA+SAN با PowerShell، ترتیب ۳ پنجره، عیب‌یابی.
- یادآوری: افست‌های سروشده = defaults دامپ (احتمالاً قدیمی برای بیلد فعلی بازی) — در ویدیو گفته شود.

## قدم بعدی (اختیاری)
- عبور از چک debugger → دامپ ۱۰۰٪ → فرمول دقیق امضای پاسخ از `0x140069158` → سرور فیک کامل با offsets واقعی.
- تا آن زمان هیچ کلیدی به سرور واقعی ارسال نشود (ریسک RATE_LIMITED/REPLAY_DETECTED/HWID lock).
