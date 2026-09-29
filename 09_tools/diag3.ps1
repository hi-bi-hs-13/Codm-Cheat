$ErrorActionPreference = 'SilentlyContinue'
$dir = "C:\Users\<user>\Desktop\Codm-Dump\iacpc\09_bypass_session4"

Write-Output "=== 1. port 443 / server ==="
$c = Get-NetTCPConnection -LocalPort 443 -State Listen
if ($c) { Write-Output ("LISTENING PID=" + ($c.OwningProcess | Select-Object -First 1)) } else { Write-Output "SERVER DOWN!" }

Write-Output ""
Write-Output "=== 2. processes: test.exe / pythonw / MuMu ==="
foreach ($n in 'test','pythonw','python','MuMuNxDevice','MuMuNxMain') {
  $p = Get-Process -Name $n
  if ($p) { Write-Output ($n + " ALIVE PID=" + ($p.Id -join ',')) } else { Write-Output ($n + " dead") }
}

Write-Output ""
Write-Output "=== 3. requests_log last 3 (ts decoded) ==="
Get-Content "$dir\requests_log.jsonl" -Tail 3 | ForEach-Object {
  $j = $_ | ConvertFrom-Json
  $t = [DateTimeOffset]::FromUnixTimeSeconds([long]$j.req.timestamp).LocalDateTime
  Write-Output ($t.ToString("HH:mm:ss") + "  " + $j.path + "  ua=" + $j.ua + "  key=" + $j.req.key)
}

Write-Output ""
Write-Output "=== 4. run_patched_log last 10 ==="
Get-Content "$dir\run_patched_log.txt" -Tail 10 | Write-Output

Write-Output ""
Write-Output "=== 5. Event log: test.exe / MuMu crashes last 30 min ==="
$since = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1001,1002; StartTime=$since} -MaxEvents 10 |
  Where-Object { $_.Message -match 'test\.exe|MuMu|ext\.dll' } |
  ForEach-Object {
    Write-Output ("---- Id=" + $_.Id + "  " + $_.TimeCreated)
    $x = $_.Properties
    if ($x.Count -ge 9) {
      Write-Output ("  app=" + $x[0].Value + " module=" + $x[3].Value + " exc=" + $x[6].Value + " offset=" + $x[8].Value)
    } else { ($_.Message -split "`r?`n" | Select-Object -First 6) | Write-Output }
  }
Write-Output "(empty = nothing recorded)"
