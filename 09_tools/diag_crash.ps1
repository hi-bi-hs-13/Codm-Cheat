$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== 1. cheat loader (test.exe) ==="
$t = Get-Process -Name test
if ($t) { Write-Output ("ALIVE PID=" + $t.Id + " -> killing now (user authorized)"); Stop-Process -Id $t.Id -Force; Start-Sleep 1 } else { Write-Output "not running" }

Write-Output ""
Write-Output "=== 2. MuMu now ==="
Get-Process | Where-Object { $_.Name -like 'MuMu*' } | ForEach-Object { Write-Output ("PID=" + $_.Id + " " + $_.Name) }
$nx = Get-Process -Name MuMuNxDevice
if ($nx) {
  Write-Output "--- ext.dll loaded in new NxDevice? ---"
  & tasklist /m ext.dll /fi ("PID eq " + $nx.Id) 2>&1 | Write-Output
}

Write-Output ""
Write-Output "=== 3. fake server log tail ==="
Get-Content "C:\Users\<user>\Desktop\Codm-Dump\iacpc\09_bypass_session4\fake_server_stdout.log" -Tail 10 | Write-Output

Write-Output ""
Write-Output "=== 4. requests_log: last 4 ==="
Get-Content "C:\Users\<user>\Desktop\Codm-Dump\iacpc\09_bypass_session4\requests_log.jsonl" -Tail 4 | Write-Output

Write-Output ""
Write-Output "=== 5. Windows Event Log - recent app crashes (last 120 min) ==="
$since = (Get-Date).AddMinutes(-120)
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=$since} -MaxEvents 8 |
  ForEach-Object {
    Write-Output ("---- " + $_.TimeCreated)
    $x = $_.Properties
    Write-Output ("  app:    " + $x[0].Value + "  ver:" + $x[1].Value)
    Write-Output ("  module: " + $x[3].Value + "  ver:" + $x[4].Value)
    Write-Output ("  exc:    " + $x[6].Value + "  code:" + $x[7].Value)
    Write-Output ("  offset: " + $x[8].Value)
  }
