Write-Output "=== ext.dll in current MuMuNxDevice (12464)? ==="
& tasklist /m ext.dll /fi "PID eq 12464" 2>&1 | Write-Output
Write-Output ""
Write-Output "=== adb connect MuMu ==="
& adb connect 127.0.0.1:16384 2>&1 | Write-Output
& adb connect 127.0.0.1:7555 2>&1 | Write-Output
& adb devices 2>&1 | Write-Output
Write-Output ""
Write-Output "=== MuMu window ==="
Get-Process | Where-Object { $_.Name -like 'MuMu*' -and $_.MainWindowTitle } | ForEach-Object {
  Write-Output ("PID=" + $_.Id + "  TITLE=" + $_.MainWindowTitle)
}
