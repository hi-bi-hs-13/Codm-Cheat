$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== killing leftover MuMu processes ==="
Get-Process | Where-Object { $_.Name -like 'MuMu*' } | ForEach-Object {
  Write-Output ("kill " + $_.Name + " PID=" + $_.Id)
  Stop-Process -Id $_.Id -Force
}
Start-Sleep -Seconds 3

Write-Output ""
Write-Output "=== starting MuMu (MuMuNxMain.exe) ==="
Start-Process -FilePath "C:\Program Files\Netease\MuMuPlayer\nx_main\MuMuNxMain.exe"
Write-Output "started, waiting 45s for boot..."
Start-Sleep -Seconds 45

Write-Output ""
Write-Output "=== processes after boot ==="
Get-Process | Where-Object { $_.Name -like 'MuMu*' } | ForEach-Object {
  Write-Output ("PID=" + $_.Id + " " + $_.Name)
}
