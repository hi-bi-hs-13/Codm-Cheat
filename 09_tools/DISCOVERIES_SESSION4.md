# کشف‌های نشست ۴ — بایپس چک نهایی VM (بخش باز گزارش v5)
تاریخ: 2026-09-20 | هدف: عبور از چک «A debugger has been found...» و رسیدن به منطق اصلی لودر

---

## 🔴 کشف ۱ — باگ KUSD SystemTime هنوز در کد امولاتور است (گزارش قبلی اشتباه می‌گفت «اصلاح شد»)

**فایل:** `backup-old/2/05_scripts/unicorn_unpack.py` خط 104 (و همین در `dll2_unpack.py` خط 104)

```python
struct.pack_into('<III', kusd, 0x014, 0x0, 0x01D80000, 0x01D8)   # SystemTime (2026-ish)
```

KUSD.SystemTime یک `KSYSTEM_TIME` سه‌فیلدی است: `LowPart@0x14, High1Time@0x18, High2Time@0x1C`.
این کد می‌نویسد: `LowPart=0x0, High1=0x01D80000, High2=0x01D8` → **High1 ≠ High2**

در ویندوز واقعی این دو فیلد **همیشه برابر** هستند (کرنل هر دو را با هم آپدیت می‌کند).
VMP این ناسازگاری را چک می‌کند → محیط را فیک تشخیص می‌دهد → مسیر abort.

⚠️ گزارش بخش ۱۱ مدعی بود «باگ KUSD اصلاح شد» ولی فیکس هیچ‌وقت در کد ذخیره نشده بود.
**همین باگ کاندیدای اصلیِ عامل verdict فعلی است.**

**فیکس:** `struct.pack_into('<III', kusd, 0x014, low, high, high)` با High1 == High2.

---

## 🔴 کشف ۲ — سه منبع زمان امولاتور با هم ناسازگارند (دومین بردار تشخیص)

| منبع | مقدار فعلی | مشکل |
|---|---|---|
| KUSD.SystemTime | 0x01D80000_00000000 | ثابت + High1≠High2 |
| GetSystemTimeAsFileTime | 0x01E0A28E00000000 (هر بار همان) | **فریز شده** — دو فراخوانی پشت‌سرهم مقدار یکسان برمی‌گردانند |
| GetTickCount / QPC | next_tick() — همیشه جلو می‌رود | با FILETIME همگام نیست |

اختلاف KUSD با FILETIME ≈ 2.8 روز. VMP می‌تواند KUSD.SystemTime را با GetSystemTimeAsFileTime
مقایسه کند (هر دو باید یک ساعت باشند) و اختلاف را ببیند. همچنین FILETIME فریزشده + QPC در حال
پیشروی = ترکیب غیرممکن.

**فیکس (طرح emu_v2):** یک ساعت مجازی واحد:
- `virt_filetime()` = BASE_FT + (next_tick_ms × 10_000)  (100ns units)
- GetSystemTimeAsFileTime / GetSystemTime / GetLocalTime → همه از همان
- KUSD.SystemTime.Low/High1/High2 → از همان (High1==High2)
- KUSD.InterruptTime → از همان با آفست ثابت (High1==High2)
- QPC = همان مقدار × 10 (QPF=10MHz) تا نسبت QPC↔FILETIME هم ثابت بماند

---

## 📋 بازسازی زنجیره‌ی تصمیم abort (از emu_log.txt لودر + dll2)

توالی دقیق قبل از MessageBoxW «A debugger has been found...»:
1. `NtQIP(cls=0x1E)` → STATUS_PORT_NOT_SET ✅ عبور
2. `NtSetInformationThread(HideFromDebugger)` ✅
3. `NtQSI(cls=0x23)` KernelDebugger: Enabled=0/NotPresent=1 ✅
4. `NtQSI(cls=0x0B, len=2976)` لیست ماژول‌های کرنل (فیکس L13 اعمال شده — ۵ ماژول فیک) ✅
5. `NtOpenFile(\??\C:\CODM\loader.exe)` + `NtCreateSection` + `NtMapViewOfSection` — integrity فایل ✅
6. موج سوم `IsDebuggerPresent/CheckRemoteDebuggerPresent` ✅ (همه تمیز)
7. بعد از این‌ها، بدون هیچ API قابل‌مشاهده‌ای → verdict در بایت‌کد VM → MessageBoxW + ExitProcess

⬅ یعنی عامل verdict **داده‌ی محیطی ناسازگار** است، نه API غایب. کاندیدای شماره ۱: KUSD High1≠High2.
کاندیدای شماره ۲: ناسازگاری سه منبع زمان (کشف ۲). کاندیدای شماره ۳: fidelity سنتز DLLها (بخش ۱۱).

---

---

## 🔴 کشف ۳ (بعد از رد KUSD/RDTSC) — مپ SEC_IMAGE غلط در NtMapViewOfSection ★ کاندیدای اصلی جدید

**تاریخ آزمایش:** فیکس‌های KUSD + ساعت واحد + RDTSC دومرحله‌ای اعمال و اجرا شد (emu_log_v2.txt) →
verdict **باز هم** در همان نقطه (خط 1111، توالی ۱۰۰٪ یکسان با لاگ قدیم) → KUSD/ساعت/RDTSC عامل نبودند.

RDTSC دومرحله‌ای جدید درست کار می‌کند (جفت متوالی d=54، دور d=2131-6000) — این بخش سالم است.

**باگ اصلی کشف‌شده:** لایه‌بندی فایل لودر:
```
.vmp1:  RVA=0xA73000  raw_ptr=0x400   (اختلاف ~10.9MB!)
.reloc: RVA=0x15AC000 raw_ptr=0xB38C00
.rsrc:  RVA=0x15AD000 raw_ptr=0xB38E00
SizeOfImage = 0x15AE000
```

امولاتور `NtMapViewOfSection` را «raw فایل به‌صورت خطی» مپ می‌کند:
`NtMapViewOfSection -> REAL FILE mapped (11,772,208 bytes) at 0x500000000`

ولی `NtMapViewOfSection` با SEC_IMAGE در ویندوز واقعی، سکشن‌ها را **در آفست RVA** مپ می‌کند.
→ VMP چک integrity خودش را از روی view مپ‌شده با آفست RVA انجام می‌دهد؛
در امولاسیون ما `mapped[RVA 0xA73000]` = بایت‌های وسط blob خام vmp1 (آشغال) به‌جای شروع سکشن vmp1
→ هش mismatch → verdict «debugger found»!

**گزارش قبلی می‌گفت L06 عبور کرد («هش منطبق») — نادرست بود؛ فقط موفقیت مپ چک شده بود نه منطبق‌بودن بایت‌ها.**

**فیکس:** بازنویسی handler مپ به‌صورت SEC_IMAGE: هدر در RVA=0، هر سکشن در RVA خودش از raw content،
سکشن‌های RawSize=0 صفر، طول کل = SizeOfImage.

---

## ✅ کشف ۴ — فیکس SEC_IMAGE در emu_v2.py اعمال شد (2026-09-20)
فایل: `09_bypass_session4/emu_v2.py` — هندلر `ntmapviewofsection`
تغییر:
- قبل: `virt_alloc(len(data)) + mem_write(vb, data)` — مپ خطی خام (غلط)
- بعد: `virt_alloc(pgup(SOI)) + zero + headers[:SOH] + هر سکشن در vb+RVA` — مپ SEC_IMAGE واقعی
- `ViewSize` از `len(data)=11,772,208` به `SizeOfImage=0x15AE000 (22,683,648)` اصلاح شد
- `SOH = oh.SizeOfHeaders` + هلپر `fileoff_to_rva()` اضافه شد
- `sync_patch_to_fileviews` هم اصلاح شد: `vb+off` → `vb+rva` (سازگار با SEC_IMAGE)
لاگ جدید مورد انتظار: `NtMapViewOfSection -> SEC_IMAGE mapped (SizeOfImage=0x15ae000 ...)`

---

## 🔴 کشف ۵ — فرضیه SEC_IMAGE رد شد! مپ از نوع SEC_COMMIT است (2026-09-20)
**آزمایش:** فیکس کشف ۴ اجرا شد → نتیجه معکوس!
- لاگ جدید: `NtMapViewOfSection -> SEC_IMAGE mapped (SizeOfImage=0x15ae000)` سپس فوری:
  `*** [MESSAGEBOX 'loader.exe'] File corrupted! This program has been manipulated and maybe it's infected by a Virus or cracked. This file won't work anymore. ***`
  + `API ExitProcess(3735929054 = 0xDEADC0DE)`
- رفتار قدیم (مپ خطی): ادامه تا `NtProtectVirtualMemory×5` + طوفان IAT + سپس `A debugger has been found...`
- رفتار جدید (SEC_IMAGE): توقف فوری بعد از `NtUnmapViewOfSection` — بدون هیچ NtProtect/IAT — یعنی چک integrity زودهنگام FAIL شد.
- `.text fill=0.00% .rdata fill=0.00%` (آنپک شروع نشد)

**ریشه (اثبات‌شده با لاگ آرگومان‌ها):**
- `NtCreateSection(desired=0x4, pageprot=0x2, allocattrs=0x8000000, filehandle=0x21001) [SEC_IMAGE=False SEC_COMMIT=True]`
- پس VMP فایل را به‌صورت DATA (خام خطی) مپ کرده، نه IMAGE. مپ خطی قبلی درست بود!
- تریس VIEW-READ: تک RIP `0x14146226c` بایت‌به‌بایت از `view_off=0x130` (داخل هدر PE) می‌خواند — حلقه هش/چک‌سام هدر. با مپ SEC_IMAGE این هش می‌شکند چون چیدمان بایت‌ها فرق دارد (`.vmp1: RVA=0xA73000 vs raw_ptr=0x400`).
- فایل‌های شاهد: `run_secimage.txt` (verdict جدید) + `run_sectattrs.txt` + `run_viewtrace.txt`

**فیکس نهایی:** هندلر `ntmapviewofsection` دوشاخه شد:
- اگر `allocattrs & SEC_IMAGE (0x1000000)` → مپ SEC_IMAGE (headers + سکشن در RVA، ViewSize=SOI)
- وگرنه (SEC_COMMIT مثل این لودر) → مپ DATA خطی (raw file، ViewSize=len(data)) ✅
- `mapped_views` حالا `(vb, is_image)` ذخیره می‌کند و `sync_patch_to_fileviews` هر دو را درست patch می‌کند.
- نتیجه: کشف ۳ (کاندیدای SEC_IMAGE) رسماً باطل شد. تمرکز بعدی = verdict دیرهنگام `debugger found` (بعد از IAT storm).

## ✅ کشف ۷ — پچ accept-any-key ساخته و تأیید شد (2026-09-20)
**نقاط پچ (دیساسمبلی image آنپک‌شده، base 0x140000000):**
- `P1 0x14006e201 (img 0x6e201): 0F843B100000 (JE 0x14006f242) -> 90×6` — چک `strcmp(code,"LOGIN_SUCCESS")#1`
- `P2 0x14006e21d (img 0x6e21d): 0F841F100000 (JE 0x14006f242) -> 90×6` — چک دوم code
- `P3 0x14006e287 (img 0x6e287): 0F8531030000 (JNE 0x14006e5be) -> E93203000090 (JMP)` — چک `call 0x14006a360 (signature verify->AL)`
- بایت‌های مورد انتظار هر سه تأیید و پچ شد؛ دیساسمبلی بعد از پچ: `NOP×6 / NOP×6 / JMP 0x14006e5be` ✅
- کشف جانبی: فقط ۲ فراخوانی HMAC (`0x140065760`) در کل image هست: `0x14006d475` (امضای درخواست) و `0x140069158` (ساخت امضای پاسخ) — چک امضا به VMP (`call 0x1408e5875`) می‌رود، پس پچ مستقیم Jcc تمیزترین راه بود.
- فایل‌ها: `09_bypass_session4/patch_accept_any_key.py` + `09_bypass_session4/out/patched_FULLIMAGE_accept_any_key.bin` (۲۲.۷MB)
- **محدودیت‌ها (مهم):** پچ روی image آنپک اعمال می‌شود نه test.bin (پک)؛ پچ روی دیسک = `File corrupted (0xDEADC0DE)` چون integrity از نوع SEC_COMMIT است — فقط patch حافظه بعد از Map/Unmap. آفلاین کامل (curl fail) هنوز در `INVALID RESPONSE` می‌ماند — سرور فیک با هر JSON دارای فیلد code کافی است. و طبق تأیید کاربر: بدون `LOGIN_SUCCESS` واقعی، سرور افست نمی‌فرستد → fallback به defaults قدیمی → عملاً غیرقابل استفاده. فقط اثبات بایپس.

---

## ✅ کشف ۸ — تست واقعی پچ با کلید شانسی روی بایت‌های اصلی (2026-09-20)
- ابزار: `09_bypass_session4/demo_accept_any_key.py` (امولاسیون Unicorn خالص، بدون اجرای چیت)
- سناریو: کلید شانسی (مثلاً `SHANS-7D74-XXXX-TEST`) → سرور `code="INVALID_KEY"` برمی‌گرداند (std::string واقعی با SSO در `[rsp+0x360]`) → اجرای بایت‌های واقعی `0x14006e1eb` (lea/call/test/je):
  - image اصلی: `RIP=0x14006f242` (مسیر FAIL، کلید رد شد)
  - image پچ‌شده: `RIP=0x14006e207` (fall-through، کلید قبول شد)
- نکته فنی: تابع compare در `0x140077510` کاملاً رمزگشایی‌شده است (`AL=1` برابر، `AL=0` نابرابر) و برای طول نابرابر (`INVALID_KEY`=۱۱ در برابر `LOGIN_SUCCESS`=۱۳) اصلاً وارد ناحیه رمز (`0x1400e794c`) نمی‌شود — پس تست کاملاً معتبر است.
- خروجی مورد انتظار برای ضبط: `RESULT: patch converts REJECT into ACCEPT on real bytes. OK to record.`

---

## ✅ کشف ۹ — لانچر runtime patcher ساخته + مکانیک روی پروسه بی‌خطر تأیید شد (2026-09-20)
- فایل‌ها: `09_bypass_session4/run_patched.py` + `run_patched.bat` (درگ‌اندراپ: چیت را روی bat بینداز؛ حتماً Run as administrator)
- منطق: `CreateProcess(SUSPENDED)` → خواندن بیس واقعی از PEB ریموت (ASLR-safe) → resume → نظرسنجی ۳ سایت تا بایت پیش‌پچ دیده شود (یعنی VMP آن ناحیه `.text` را رمزگشایی کرده — **بعد** از چک integrity فایل SEC_COMMIT، پس هش فایل نمی‌شکند) → `WriteProcessMemory` هر ۳ پچ + read-back verify → رها کردن پروسه.
- باگ واقعی که گرفته شد: `restype` پیش‌فرض ctypes (c_int) آدرس ۶۴ بیتی را truncate می‌کرد (`WriteProcessMemory err=87`) — با `argtypes/restype` صریح فیکس شد.
- سلف‌تست روی `conhost.exe` (نه چیت!): suspend ✅، بیس PEB ✅، خواندن `MZ` ✅، alloc/write/readback ✅، resume ✅، `exit=259 running` ✅.
- چیت واقعی **اینجا اجرا نشد** (می‌افتاد دنبال `System32\ext.dll` + تماس C2 + آپلود HWID) — اجرا با کاربر روی VM ایزوله است (راهنما: `RUN_GUIDE.md`).
- کانتکست کش (برای مسیر آفلاین آینده): ذخیره در `0x14006e236` (ساخت مسیر `keysex.txt` بعد از success)؛ لود از ناحیه `0x14006c79f`؛ `CryptProtectData` موجود ولی `CryptUnprotectData` در image نیست (مسیر لود احتمالاً در ناحیه هنوزرمز است).

---

## ✅ کشف ۱۰ — سرور فیک ساخته و منطقش تست شد (2026-09-20)
- فایل: `09_bypass_session4/fake_server.py` — همیشه `LOGIN_SUCCESS` + `expires_at=2030-01-01` + echo دقیق `hwid/nonce` درخواست + ۱۶ افست typeinfo (هم flat هم زیر `typeinfo-v1`) + `offsets_signature` نگهدارنده.
- افست‌ها = defaults کامپایل‌شده خود DLL از دامپ (`0x1800d2460...`، حوالی `0x0E85xxxxx`، یک slot صفر) — با پچ P1-P3 امضا لازم نیست؛ بدترین حالت fallback به همین defaults.
- سلف‌تست واقعی (POST /CODM با کلید شانسی): `HTTP 200 | LOGIN_SUCCESS | echo OK | 16+16 keys` ✅
- زنجیره کامل اجرا: `fake_server.py --cert/--key --port 443` → `run_patched.bat <cheat>` → کلید شانسی. راهنما: `FAKE_SERVER_GUIDE.md` (hosts + CA/SAN با PowerShell خالص، بدون openssl + عیب‌یابی DoH/cert/شکل JSON).
- فایل‌های شاهد: `RESPONSE_TABLE.md` (جدول ۱۴ code→message + VA فیلدها + کانتکست HMAC دوم در `0x140069158` با جداکننده `|`).

---

## ✅ کشف ۲۴ — حالت مخفی کامل (hidden + auto-key) آماده و تست شد (2026-09-21)
- `cheat.bat hidden` / `server.bat hidden`: اجرا با `pythonw` (بدون هیچ پنجره‌ای)؛ کنسول چیت مخفی (`SW_HIDE` ولی کنسول واقعی تا API کار کند)؛ کلید لایسنس خودکار از لوله stdin (`--auto-key test`)؛ مانیتورینگ فقط با فایل (`run_patched_log.txt` + `requests_log.jsonl` + `fake_server_stdout.log`).
- دو باگ واقعی گرفته و فیکس شد: (۱) `print` زیر pythonw کرش می‌کرد → safe-print + لاگ فایل؛ (۲) هندل read پایپ **قبل** از CreateProcess بسته می‌شد و بچه هیچی به ارث نمی‌برد (`WriteFile err=232`) → بستن بعد از ساخت پروسه.
- سلف‌تست با `sort.exe` (خواننده واقعی stdin): `11/11 bytes OK` + ۱۰ ثانیه بلاک روی read = لوله سالم. (نامعلوم باقی‌مانده: چیت با CRT می‌خواند یا ReadConsole خام — تست زنده مشخص می‌کند.)

---

## ✅ کشف ۲۳ — تگ دلخواه روی Expires At + کنسول جدا (2026-09-21، تست زنده)
- `--expires-text "cracked by hi-bi-hs-13"` → روی صفحه چیت: `[+] Expires At : cracked by hi-bi-hs-13` ✅ پس پارسر `expires_at` را opaque (string) هم می‌پذیرد — بدون اعتبارسنجی عددی. (برای ویدیو عالی است.)
- باگ UX پیدا شد: چیت کنسول را با لانچر شریک می‌شد + `pause` آخر bat وسط خروجی چیت می‌افتاد و با پرامپت `>>` قاطی می‌کرد. فیکس: لانچر با `CREATE_NEW_CONSOLE` (دقیقاً مثل دابل‌کلیک عادی)، حذف `pause`، + بزرگ‌کردن بافر اسکرول (۹۰۰۰ خط) و دکمه‌های پنجره برای کنسول چیت.

---

## ✅ کشف ۲۲ — LICENSE VERIFIED زنده با کلید شانسی (2026-09-21، اثبات کامل)
- هر ۵ پچ OK → سرور فیک `LOGIN_SUCCESS` → چیت: `LICENSE VERIFIED / Status: Login successful / Expires At: 1893456000` → `=== Waiting Injector === / Waiting for emulator...`.
- زنجیره کامل تأیید شد: hosts → TLS (self-signed Root) → FORM → parse مینیمال → JIT patch → verify skip → offsets(پیش‌فرض). لاگ سرور: `POST /CODM-PC/login.php key=test... -> LOGIN_SUCCESS`.
- برای ویدیو: قاب بنر + همین صفحه + لاگ سرور کافی است. (طبق انتظار: بدون emulator روی Waiting می‌ماند؛ افست‌ها defaults.)

---

## 🔴 کشف ۲۱ — گیت اصلی امضا (`call 0x140068d80`) + پچ P5 (2026-09-21، تست زنده)
- با وجود P1-P4 باز `Invalid server signature` آمد → گیت واقعی جای دیگری است: `call 0x140068d80` در `0x14006dc08` (اولین کاری که می‌کند fetch فیلد `"signature"` از پاسخ است) با `test/jne-success` در `0x14006dc0d/0f`؛ مسیر fail می‌رود به بلوک `SECURITY WARNING` در `0x14006dc70` (همان `0x14006ddd4`).
- پچ P5: `0x14006dc0f: 0F8506050000 (JNE 0x14006e11b) -> E90705000090 (JMP)` — کل بلوک امضا skip می‌شود. هر ۵ پچ در اسکریپت تأیید شدند. در انتظار تست زنده.

---

## 🔴 کشف ۲۰ — چک امضای دوم (HMAC compare در 0x1400693de) + پچ P4 (2026-09-21، تست زنده)
- بعد از رد شدن parse، خطا شد `Invalid server signature` با وجود P1-P3: یعنی verify امضای پاسخ در VMP (`call 0x1408e5875` در `0x14006e65a`) یا HMAC-compare داخلی می‌افتد.
- HMAC-compare داخلی پیدا شد (`0x1400693d5`: memcmp امضای محاسبه‌شده با امضای پاسخ؛ `0x1400693de: jne→r15b=0 fail`؛ `0x1400693e0: mov r15b,1` که به‌عنوان نتیجه verify برمی‌گردد در `0x140069464`).
- پچ P4: `0x1400693de: 7505 -> 9090` (همیشه match). به `patch_accept_any_key.py` (تأیید شد، هر ۴ بایت خورد) و `run_patched.py` اضافه شد. در انتظار تست زنده.
- پلن B اگر P4 کافی نبود: forgery امضای واقعی — فرمول کاندیدا `HMAC(secret, code|server_time|expires_at|hwid|nonce)` و ترتیبات مشابه، با `--sig-candidate` و تست تکی‌تکی زنده.

---

## 🔴 کشف ۱۹ — پارسر JSON دست‌ساز strict است؛ تفکیک login/offsets (2026-09-21)
- دیساسمبلی دروازه parse (`call 0x140066ee0` در `0x14006d6e5`، `test al,al/jne success`): تابع `0x140066ee0` یک JSON parser دست‌ساز recursive-descent است (انتظار `{`=`0x7b`، `}`=`0x7d`، `:`=`0x3a`، skip-whitespace، استخراج کلید در `call 0x140067460`).
- فرضیه: parser روی کلیدهای ناشناس (۱۶ typeinfo که ما قاطی جواب لاگین کرده بودیم) خفه می‌شود → `INVALID RESPONSE` قبل از رسیدن به چک‌های پچ‌شده.
- فیکس: جواب `POST /CODM-PC/login.php` فقط ۶ فیلد (`code/server_time/expires_at/hwid/nonce/signature`)؛ افست‌ها فقط روی `/CODM` (دومرحله‌ای — با بافر XOR همان سرور هم می‌خواند: لاگین جدا، افست جدا). سلف‌تست هر دو مسیر سبز.
- در انتظار تست زنده با همین شکل.

---

## ✅ کشف ۱۸ — پروتکل واقعی FORM است + امضای HMAC آفلاین تأیید شد (2026-09-21، تست زنده)
- درخواست واقعی: `POST /CODM-PC/login.php` با بدنه FORM (نه JSON):
  `app_id=my_cpp_app&app_version=1.0.14&hwid=aeb7c7...&key=test&nonce=b3ca...&signature=99654f...&timestamp=1789981497` (UA `LicenseClient/1.0`).
- اثبات آفلاین فرمول امضا با ترافیک زنده: `HMAC-SHA256(secret, "test|aeb7c7...|my_cpp_app|1.0.14|1789981497|b3ca...")` == امضای مشاهده‌شده (64hex، MATCH در اولین حدس!). secret، ترتیب فیلدها، جداکننده `|` و SHA256 همگی ۱۰۰٪ تأیید شدند.
- علت `INVALID RESPONSE`: سرور فیک echo نمی‌کرد (`hwid/nonce=""`) + زمان‌ها string بودند؛ فیکس: parse کردن FORM + echo واقعی + `server_time/expires_at` عددی (epoch). فایل: `fake_server.py` (نیاز به ری‌استارت سرور).
- نکته: `timestamp=1789981497` (epoch ثانیه‌ای) و `hwid` ۳۲hex و `nonce` ۳۲hex در ترافیک واقعی دیده شد.

---

## 🔴 کشف ۱۷ — endpoint واقعی `/CODM-PC/login.php` است + پاسخ ما parse نشد (2026-09-21، تست زنده)
- لاگ سرور فیک: `POST /CODM-PC/login.php key=?... -> LOGIN_SUCCESS` — دو کشف در یک خط:
  ۱. مسیر واقعی لاگین `/CODM-PC/login.php` است، نه `/CODM` (بافر XOR همان سرور، URL پایه/قدیمی یا endpoint دوم افست‌هاست).
  ۲. `key=?` یعنی JSON درخواستی فیلدی به اسم `key` ندارد! نام فیلدهای واقعی فرق دارد.
- چیت: `INVALID RESPONSE / Server response is invalid` — یعنی parse پاسخ (مرحله `0x14006dxxx`) قبل از چک‌های code ما (در `0x14006e1xx`) شکست خورد؛ پچ‌ها سالم بودند ولی نوبت اجرا به آن‌ها نرسید.
- قدم بعدی: خواندن درخواست خام از `requests_log.jsonl` (آخرین خط) → استخراج نام/نوع واقعی فیلدهای درخواست و پاسخ → اصلاح `build_response`.

---

## 🔴 کشف ۱۶ — دو باگ خودمان: CWD در bat + delay بلندتر از تایم‌اوت چیت (2026-09-21، تست زنده)
- درخواست واقعی چیت به سرور فیک رسید (TLS سالم!) ولی: (۱) لانچر درخواست را ندید چون `run_patched.bat` با `cd` مسیر نسبی `--jit` را خراب می‌کرد (`09_bypass_session4\09_bypass_session4\...` ناموجود → همیشه صفر). فیکس: bat دیگر `cd` نمی‌کند و با `%~dp0` مسیر مطلق می‌سازد.
- (۲) `--delay 20` بلندتر از تایم‌اوت داخلی curl چیت بود → چیت با `Timeout was reached` (exit 1) خودش قطع کرد و سرور `SSLEOFError` خورد. فیکس: delay پیشنهادی ۶ ثانیه (واکنش پچر <۱ ثانیه است) + `try/except` دور write پاسخ برای لاگ تمیز ویدیو.
- فایل‌ها: `run_patched.bat` + `fake_server.py` آپدیت شدند. اجرای بعدی: سرور `--delay 6` + لانچر `--jit`.

---

## 🔴 کشف ۱۵ — CRYPT_E_NO_REVOCATION_CHECK: راه‌حل leaf خودامضا در Root (2026-09-21، تست زنده)
- بعد از فیکس EKU (`-Type SSLServerAuthentication`)، خطا شد `CRYPT_E_NO_REVOCATION_CHECK (0x80092012)` — Schannel نمی‌تواند revocation را چک کند چون CA محلی نه CRL دارد نه OCSP، و curl/libcurl به‌صورت پیش‌فرض hard-fail می‌کند (چیت هم همین رفتار را خواهد داشت).
- راه‌حل بدون CRL: گواهی **خودامضای** سرور (بدون Signer) مستقیم در `LocalMachine\Root` نصب شود — trust anchor صریح است، پس Schannel اصلاً دنبال revocation نمی‌گردد. ریسک محدود (فقط همین SAN معتبر است؛ بعد از تست حذف شود).

---

## 🔴 کشف ۱۴ — SEC_E_CERT_WRONG_USAGE: EKU برگ مشکل دارد (2026-09-21، تست زنده)
- بعد از فیکس CA، handshake جلوتر رفت ولی Schannel گفت `SEC_E_CERT_WRONG_USAGE (0x80090349)` = leaf از نظر EKU/KeyUsage برای server-auth مجاز نیست.
- اقدام: دامپ اکستنشن‌ها + ساخت leaf مینیمال (فقط SAN، بدون EKU محدودکننده).

---

## 🔴 کشف ۱۳ — SSL connect error: گواهی CA فاقد BasicConstraints (2026-09-21، تست زنده)
- زنجیره JIT تا `[*] Logging in` رفت (درخواست ساخته شد) ولی `curl_easy_perform failed: SSL connect error` — یعنی مسیریابی hosts درست بود و handshake مرد.
- علت محتمل: CA ساخته‌شده با `New-SelfSignedCertificate -Type Custom` فاقد اکستنشن `BasicConstraints cA=true` است → Schannel آن را CA معتبر حساب نمی‌کند و زنجیره می‌شکند (گواهی leaf به‌تنهایی SAN/EKU درست را داشت).
- راه‌حل: ساخت مجدد CA با `-TextExtension '2.5.29.19={text}cA=true&pathlength=1'` + leaf با `KeyUsage DigitalSignature,KeyEncipherment`؛ تست سریع handshake با `curl.exe -v https://api.bestcheatir.com/CODM` (بدون نیاز به اجرای چیت) تا `SSL certificate verify ok` + `LOGIN_SUCCESS` دیده شود، بعد JIT دوباره.

---

## ✅ کشف ۱۲ — اجرای مستقیم سالم: بنر + پرامپت لایسنس (2026-09-21، تست زنده)
- `test.exe` بدون لانچر: ~۱-۲ ثانیه cmd خالی (فاز آنپک VMP) → بنر `CODM LOADER / Telegram : @PouRia_Cheat` → `ENTER YOUR LICENSE KEY` + `>>`.
- نتیجه: محیط کاربر تمیز است (هیچ verdict ای) → `File corrupted` کشف ۱۱ قطعاً کار پچ زودهنگام بود، نه محیط. تئوری memory-integrity دیرهنگام تأیید شد. مسیر JIT معتبر است.

---

## 🔴 کشف ۱۱ — پچ زودهنگام = File corrupted؛ راه‌حل JIT (2026-09-21، تست زنده)
- تست زنده روی سیستم کاربر: هر ۳ پچ با بیس ASLR (`0x7ff71ccc0000`) روی پروسه واقعی OK خورد (`0f84..->9090..` هر سه)، ولی بلافاصله مسیج‌باکس `File corrupted! ... Virus or cracked` آمد.
- تحلیل: VMP علاوه بر چک فایل (SEC_COMMIT، زودهنگام) یک **memory-integrity دیرهنگام** روی `.text` دارد (همان درسی که در RDTSC گرفته بودیم: patch بایت → trip). پچ ما در همان ثانیه resume اعمال شد — یعنی قبل از اتمام چک‌های دوره‌ای.
- راه‌حل ساخته‌شده (JIT): سرور فیک با `--delay 20` پاسخ را نگه می‌دارد؛ `run_patched.py --jit requests_log.jsonl` فقط وقتی پچ می‌کند که درخواست چیت لاگ شده باشد = همه چک‌ها رد شده + verify هنوز منتظر پاسخ است. پنجره امن ~۲۰ ثانیه‌ای.
- فایل‌ها: `fake_server.py (+--delay)` + `run_patched.py (+--jit/--jit-timeout)` + `run_patched.bat` (الان `%*` می‌فرستد).
- تست تفکیکی پیشنهادی (۳۰ ثانیه، بدون پچر): دابل‌کلیک مستقیم چیت — اگر پرامپت لایسنس آمد، محیط سالم است و مقصر پچ زودهنگام بود (تأیید تئوری memory-check).

---

## ✅ کشف ۶ — برگشت به مسیر قبلی تأیید شد (2026-09-20)
اجرای `run_reverted.txt` با هندلر دوشاخه:
- `NtCreateSection(... allocattrs=0x8000000 ...) [SEC_IMAGE=False SEC_COMMIT=True]`
- `NtMapViewOfSection -> DATA mapped (11,772,208 bytes) [SEC_COMMIT, linear]`
- `NtProtectVirtualMemory×5` + `getmodulehandlea:31` (طوفان IAT) + `A debugger has been found running in your system.`
- یعنی integrity زودهنگام PASS شد و به verdict دیرهنگام برگشتیم — رفتار دترمینیستیک و سالم.
- شاهد: `09_bypass_session4/run_reverted.txt`

---

## نقشه اجرا نشست ۴
1. `emu_v2.py` = نسخه ویندوزی‌شده `unicorn_unpack.py` + فیکس ساعت واحد + مود `bypass=skip`
2. اجرا روی `02_samples/test.bin` (لودر) → عبور از چک → dump کامل + شکار فراخوانی‌های منطق اصلی
3. در صورت عبور: همان فیکس به `dll2_unpack.py` هم اعمال و اجرا (لایه دوم)
4. هر کشف جدید فوراً به همین فایل اضافه می‌شود
