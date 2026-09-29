# راهنمای ضبط ویدیو برای سازنده (صادقانه و بدون دردسر)

## چرا x64dbg و patcher کشیدنی جواب نمی‌دهد (برای گفتن در ویدیو اگر لازم شد)
1. باز کردن چیت در x64dbg در Entry Point نگه می‌دارد، ولی بایت‌های لایسنس
   (`0x14006e201` و ...) آن لحظه اصلاً در حافظه نیستند — همه سکشن‌ها
   `RawSize=0` اند و VMP بعد از ~۹۲۰M بلاک آن‌ها را رمزگشایی می‌کند.
   قبل از آن، VMP با ۱۴ لایه (از جمله `File corrupted 0xDEADC0DE` و
   `A debugger has been found`) دیباگر را می‌کشد.
2. patcher کشیدنی (Drag&Drop exe که پروسه suspended می‌سازد و WriteProcessMemory
   می‌کند) هم به همین دو دیوار می‌خورد: بایت هدف هنوز رمز است + VMP پروسه
   والد/تایمینگ را چک می‌کند. «بی‌دردسر» نیست — نیاز به بایپس ضد-دیباگ سطح کرنل دارد.

## چیزی که ضبط می‌کنی (معتبر، واقعی، قابل تکرار)
دموی `demo_accept_any_key.py` بایت‌های **واقعی** دامپ را با سناریوی کلید شانسی
اجرا می‌کند — نه موک، نه انیمیشن:
1. `patch_accept_any_key.py` را اجرا کن → هر ۳ بایت مورد انتظار تأیید و پچ می‌شود.
2. `demo_accept_any_key.py SHANS-7D74-XXXX-TEST` را اجرا کن → خروجی:
   - `ORIGINAL image : ... RIP=0x14006f242 => FAIL path, key rejected`
   - `PATCHED image  : ... RIP=0x14006e207 => FALLS THROUGH, key accepted`
   - `RESULT: patch converts REJECT into ACCEPT on real bytes. OK to record.`
3. در ویدیو این‌ها را نشان بده: دستورها + خروجی بالا + (اختیاری) دیساسمبلی
   قبل/بعد (`0F84.. -> 90×6` و `0F85.. -> E9..`) از `CRACK_STATUS.md`.

## جمله صادقانه‌ای که باید در ویدیو/پیام باشد (مهم)
«پچ روی image حافظه تست شد و چک code/signature را دور می‌زند؛ ولی بدون
`LOGIN_SUCCESS` واقعی، سرور افست ریموت نمی‌فرستد و چیت روی defaults قدیمی
می‌افتد — یعنی عملاً غیرقابل استفاده است. این اثبات مهندسی معکوس است نه چیت آماده.»
(خودت هم همین را گفته بودی — همین صداقت اعتبار ویدیو را بالا می‌برد.)

## دستورات آماده ضبط
```
.\09_bypass_session4\venv\Scripts\python.exe 09_bypass_session4\patch_accept_any_key.py
.\09_bypass_session4\venv\Scripts\python.exe 09_bypass_session4\demo_accept_any_key.py SHANS-7D74-XXXX-TEST
```
