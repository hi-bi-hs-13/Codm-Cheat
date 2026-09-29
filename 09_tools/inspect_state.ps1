Get-CimInstance Win32_Process | Where-Object { ($_.Name -in 'python.exe','pythonw.exe') -and $_.CommandLine -match 'fake_server' } | ForEach-Object {
  Write-Output ("PID=" + $_.ProcessId)
  Write-Output ("CMD=" + $_.CommandLine)
}
$cheat = Get-Process -Name test -ErrorAction SilentlyContinue
if ($cheat) { Write-Output ("CHEAT RUNNING PID=" + $cheat.Id) } else { Write-Output "CHEAT NOT RUNNING" }
Write-Output "--- ext.dll modules ---"
& tasklist /m ext.dll 2>$null | Select-Object -First 5
