# اجرای واقعی چیت با کلید شانسی — راهنما (RUN_GUIDE)

## پیش‌نیاز (اجباری)
1. **VM ایزوله ویندوز** با snapshot تمیز (VirtualBox/VMware). نه سیستم اصلی.
2. داخل VM: کپی `test.bin` (به اسم مثلاً `loader.exe`) + پوشه `09_bypass_session4` (شامل `run_patched.py` + `run_patched.bat` + `venv`).
3. اجرا به‌صورت **Administrator** (روی `run_patched.bat`: راست‌کلیک → Run as administrator).

## تست صفر (۳۰ ثانیه، بدون پچر — اول این را بکن)
روی `test.exe` دابل‌کلیک کن (بدون لانچر، بدون سرور فیک — hosts باشد یا نه فرقی ندارد).
- اگر `ENTER YOUR LICENSE KEY` آمد → محیط سالم است؛ `File corrupted` قبلی کار پچ زودهنگام بود. برو به «اجرای JIT».
- اگر مستقیم `File corrupted` آمد → کپی `test.exe` خراب است (از `test.bin` دوباره کپی بگیر) یا محیط گیر کرده؛ لاگ را بفرست.

## اجرای JIT (برای ویدیو) — ۳ پنجره
1. پنجره ۱ (ادمین): سرور فیک **با تأخیر** (تا verify منتظر بماند و پچر وقت داشته باشد):
   `09_bypass_session4\venv\Scripts\python.exe 09_bypass_session4\fake_server.py --cert C:\fakeca\server.crt --key C:\fakeca\server.key --port 443 --delay 20`
2. پنجره ۲ (ادمین):
   `09_bypass_session4\run_patched.bat "C:\...\test.exe" --jit 09_bypass_session4\requests_log.jsonl`
   خروجی: `launched suspended` → `remote image base` → `JIT mode: ... waiting for cheat request ...`
3. پنجره ۳ (چیت): وقتی `ENTER YOUR LICENSE KEY` آمد کلید شانسی بزن (مثلاً `SHANS-1234-XXXX`) و Enter.
   - سرور فیک می‌نویسد `holding response 20s (JIT patch window)...` و درخواست را لاگ می‌کند.
   - لانچر می‌بیند، هر ۳ پچ را می‌زند (`... -> ... OK`) و می‌نویسد `ALL PATCHES APPLIED`.
   - بعد از ~۲۰ ثانیه پاسخ می‌رسد و verify با بایت‌های پچ‌شده اجرا می‌شود.
4. نتیجه مورد انتظار: `LICENSE VERIFIED` → `[+] Expires At : 2030-01-01...` → `[*] Waiting for target process`. همان صفحه + لاگ سرور (`POST /CODM key=SHANS-... -> LOGIN_SUCCESS`) = قاب‌های ویدیو.

## اگر چیز دیگری دیدی (عیب‌یابی از روی لاگ `run_patched_log.txt`)
- `child exited early ... BEFORE decrypt` + پیام چیت `A debugger has been found` → VMP محیط VM را گرفته (مهمان‌افزونه‌ها/هوک‌ها را خاموش کن، snapshot تمیز).
- `File corrupted! ... Virus or cracked` + کد `0xdeadc0de` → پچ زود اعمال شده یا فایل دیسک دست‌خورده است؛ چیت دست‌نخورده را دوباره کپی کن.
- `TIMEOUT ... never decrypted` → آنپک بیش از ۱۸۰ ثانیه طول کشید (سیستم کند)؛ دوباره تلاش کن.
- `unexpected bytes ... version mismatch` → بیلد چیت با این تحلیل فرق دارد؛ image جدید را بفرست تا سایت‌ها rebase شوند.

## هشدارها (جدی)
- هر تلاش لایسنس (حتی ردشده) **HWID ماشین را به سرور فروشنده می‌فرستد**. VM جدا = HWID جدا.
- چیت `C:\Windows\System32\keysex.txt` (کش) و هنگام تزریق `System32\ext.dll` می‌سازد؛ بعد از تست پاک کن.
- بدون شبیه‌ساز/بازی، چیت روی `Waiting for target process` می‌ماند — همین انتظار می‌رود.
- بدون `LOGIN_SUCCESS` واقعی، سرور **افست نمی‌فرستد** (fallback به defaults قدیمی) → عملاً غیرقابل استفاده در بازی. این را در پیام به سازنده بنویس (اعتبار ویدیو).
