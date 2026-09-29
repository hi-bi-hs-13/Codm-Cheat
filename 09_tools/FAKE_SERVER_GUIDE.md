# سرور فیک لایسنس — راهنمای راه‌اندازی (فقط VM ایزوله، ادمین)

## ترتیب اجرا (هر ۳ لایه با هم)
1. `fake_server.py` (این فایل) — جواب `LOGIN_SUCCESS` + افست‌ها می‌دهد.
2. `run_patched.py` — چک code و امضا را در حافظه دور می‌زند (بدون آن، امضای
   `bypass-with-patch` رد می‌شود و `Invalid server signature` می‌گیری).
3. چیت + کلید شانسی → `LICENSE VERIFIED` → `Waiting for target process`.

## قدم ۱ — hosts (PowerShell ادمین)
```powershell
Add-Content "$env:SystemRoot\System32\drivers\etc\hosts" "`n127.0.0.1 api.bestcheatir.com"
ping api.bestcheatir.com   # باید 127.0.0.1 جواب بدهد
```

## قدم ۲ — سرتیفیکیت (چون آدرس https است و curl گواهی را چک می‌کند)
با PowerShell (ادمین) — بدون نیاز به openssl:
```powershell
# ۱) CA محلی
$ca = New-SelfSignedCertificate -Type Custom -KeyUsageProperty Sign -KeyUsage CertSign `
  -Subject "CN=LocalTestCA" -CertStoreLocation "Cert:\LocalMachine\My" `
  -NotAfter (Get-Date).AddYears(2)
# ۲) گواهی سرور با SAN درست، امضاشده با همان CA
$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=api.bestcheatir.com" `
  -DnsName "api.bestcheatir.com" -Signer $ca -CertStoreLocation "Cert:\LocalMachine\My" `
  -KeyUsage DigitalSignature -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.1") `
  -NotAfter (Get-Date).AddYears(2)
# ۳) اعتماد به CA (تا Schannel/curl قبول کند)
$store = New-Object Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
$store.Open("ReadWrite"); $store.Add($ca); $store.Close()
# ۴) خروجی PEM برای fake_server.py (پسورد را عوض کن)
$pwd = ConvertTo-SecureString "changeit" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath C:\fakeca\server.pfx -Password $pwd
```
تبدیل PFX به PEM (با همان ویندوز — certutil هست، ولی کلید خصوصی را نمی‌دهد؛
ساده‌ترین راه: ماژول `cryptography` پایتون. اگر نصب نیست:
`venv\Scripts\python.exe -m pip install cryptography` سپس:)
```powershell
venv\Scripts\python.exe -c "from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption; p=pkcs12.load_key_and_certificates(open('C:\fakeca\server.pfx','rb').read(), b'changeit'); open('C:\fakeca\server.key','wb').write(p[0].private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())); open('C:\fakeca\server.crt','wb').write(p[1].public_bytes(Encoding.PEM))"
```

## قدم ۳ — اجرا (۳ پنجره جدا، به همین ترتیب)
```powershell
# پنجره ۱ (ادمین) — پورت ۴۴۳ ادمین می‌خواهد
venv\Scripts\python.exe 09_bypass_session4\fake_server.py --cert C:\fakeca\server.crt --key C:\fakeca\server.key --port 443
# پنجره ۲ (ادمین)
09_bypass_session4\run_patched.bat "C:\path\to\loader.exe"
# پنجره ۳ همان چیت است که لانچر بالا آورد — کلید شانسی بزن
```

## چه چیزی موفقیت است (برای ویدیو)
- لاگ سرور فیک: `POST /CODM key=SHANS-... -> LOGIN_SUCCESS` (یعنی ترافیک واقعاً به دام افتاد، نه سرور اصلی!)
- صفحه چیت: `LICENSE VERIFIED` + `[+] Expires At : 2030-01-01...` + `Waiting for target process`
- فایل `requests_log.jsonl`: کل درخواست واقعی چیت (سند مهندسی معکوس پروتکل)

## عیب‌یابی
- لاگ سرور خالی ولی چیت خطای شبکه داد → hosts اعمال نشده / DoH دور زده / فایروال. اول `ping` را چک کن.
- `Invalid server signature` با وجود سرور فیک → پچ P3 اعمال نشده (لاگ `run_patched_log.txt` را ببین: هر ۳ سایت باید OK باشند).
- `curl_easy_perform failed: ... certificate` → CA در Root نصب نشده یا SAN گواهی اشتباه است (باید دقیقاً `api.bestcheatir.com` باشد).
- چیت بالا آمد ولی `REMOTE TYPEINFO OFFSETS UNAVAILABLE` → شکل JSON را نگاه کن؛ مقادیر فعلی = defaults خود دامپ (۱۶ عدد، یکیش صفر). برای بیلد فعلی بازی ممکن است قدیمی باشند — همین را در ویدیو بگو (صداقت).
