# restart_fake_server.ps1 — kill any fake_server instance, restart in FAKE mode (option 1)
$ErrorActionPreference = 'SilentlyContinue'
$dir = 'C:\Users\<user>\Desktop\Codm-Dump\iacpc\09_bypass_session4'
$py  = Join-Path $dir 'venv\Scripts\python.exe'

# 1. kill every fake_server instance (forward or fake)
Get-CimInstance Win32_Process |
  Where-Object { ($_.Name -eq 'python.exe' -or $_.Name -eq 'pythonw.exe') -and $_.CommandLine -match 'fake_server' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 1

# 2. kill anything still LISTENING on 443 (stale XAMPP etc.)
Get-NetTCPConnection -LocalPort 443 -State Listen | ForEach-Object {
  Stop-Process -Id $_.OwningProcess -Force
}
Start-Sleep -Seconds 1

# 3. start fake-mode server (hidden), real offsets auto-loaded from newest capture
Start-Process -FilePath $py `
  -ArgumentList 'fake_server.py','--cert','C:\fakeca\server4.crt','--key','C:\fakeca\server4.key','--port','443','--delay','6','--expires-text','cracked by hi-bi-hs-13' `
  -WorkingDirectory $dir -WindowStyle Hidden
Start-Sleep -Seconds 2

# 4. report
$conn = Get-NetTCPConnection -LocalPort 443 -State Listen
if ($conn) {
  Write-Output ("SERVER UP  PID=" + ($conn.OwningProcess | Select-Object -First 1))
} else {
  Write-Output "SERVER FAILED TO BIND 443"
}
