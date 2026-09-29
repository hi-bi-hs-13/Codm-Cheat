$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== A. requests_log: all LicenseClient + /CODM entries (last 12) ==="
Get-Content "C:\Users\<user>\Desktop\Codm-Dump\iacpc\09_bypass_session4\requests_log.jsonl" -Tail 12 | ForEach-Object {
  $j = $_ | ConvertFrom-Json
  $ua = $j.ua; $p = $j.path; $ts = $j.req.timestamp
  Write-Output ("path=" + $p + "  ua=" + $ua + "  ts=" + $ts)
}

Write-Output ""
Write-Output "=== B. run_patched_log (today's launch) ==="
Get-Content "C:\Users\<user>\Desktop\Codm-Dump\iacpc\09_bypass_session4\run_patched_log.txt" -Tail 12 | Write-Output

Write-Output ""
Write-Output "=== C. Event log: Application 1000/1001 + System errors, last 3h, any MuMu/ext/test ==="
$since = (Get-Date).AddHours(-3)
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$since} -MaxEvents 60 |
  Where-Object { ($_.Id -in 1000,1001,1002) -or ($_.Message -match 'MuMu|ext\.dll|test\.exe') } |
  Select-Object -First 8 |
  ForEach-Object {
    Write-Output ("---- Id=" + $_.Id + "  " + $_.TimeCreated + "  " + $_.ProviderName)
    ($_.Message -split "`r?`n" | Select-Object -First 10) | Write-Output
  }
Write-Output ""
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=$since} -MaxEvents 40 |
  Where-Object { $_.Message -match 'MuMu|NxDevice' } |
  Select-Object -First 5 |
  ForEach-Object {
    Write-Output ("---- SYSTEM Id=" + $_.Id + "  " + $_.TimeCreated)
    ($_.Message -split "`r?`n" | Select-Object -First 6) | Write-Output
  }

Write-Output ""
Write-Output "=== D. WER ReportArchive for MuMu (last 3h) ==="
Get-ChildItem "C:\ProgramData\Microsoft\Windows\WER\ReportArchive","C:\ProgramData\Microsoft\Windows\WER\ReportQueue" -Directory |
  Where-Object { $_.LastWriteTime -gt $since -and $_.Name -match 'MuMu|NxDevice' } |
  ForEach-Object {
    Write-Output ("---- " + $_.Name + "  " + $_.LastWriteTime)
    $rp = Join-Path $_.FullName "Report.wer"
    if (Test-Path $rp) {
      Get-Content $rp | Where-Object { $_ -match 'AppName|FaultingModule|ExceptionCode|FaultingOffset|ModulePath|Sig\[' } | Select-Object -First 12 | Write-Output
    }
  }
