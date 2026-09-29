$mumu = Get-Process | Where-Object { $_.Name -like 'MuMu*' -or $_.Name -like 'Nemu*' -or $_.Name -like 'codm*' }
if ($mumu) {
  $mumu | Select-Object Id, Name, Path | Format-Table -AutoSize | Out-String -Width 220 | Write-Output
} else {
  Write-Output "NO MUMU PROCESSES"
}
Write-Output "--- adb devices ---"
& adb devices 2>&1 | Write-Output
