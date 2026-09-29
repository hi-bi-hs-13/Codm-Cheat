$ErrorActionPreference = 'SilentlyContinue'

Write-Output "=== 1. Defender threat detections (last 14 days, MuMu/ext related) ==="
Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-14) } |
  Select-Object -First 8 |
  ForEach-Object {
    Write-Output ("---- " + $_.InitialDetectionTime + "  threat=" + $_.ThreatID + "  action=" + $_.CleaningActionID)
    $_.Resources | ForEach-Object { Write-Output ("    " + $_) }
  }
Write-Output "(empty = no detections)"

Write-Output ""
Write-Output "=== 2. Defender threats list ==="
Get-MpThreat | Select-Object -First 6 | ForEach-Object {
  Write-Output ("ThreatID=" + $_.ThreatID + "  name=" + $_.ThreatName)
}

Write-Output ""
Write-Output "=== 3. VBS / HVCI (Core Isolation) status ==="
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
Write-Output ("VBS status (2=running): " + $dg.VirtualizationBasedSecurityStatus)
Write-Output ("HVCI running: " + $dg.SecurityServicesRunning)

Write-Output ""
Write-Output "=== 4. Recent Windows hotfixes ==="
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 | ForEach-Object {
  Write-Output ($_.InstalledOn.ToString("yyyy-MM-dd") + "  " + $_.HotFixID + "  " + $_.Description)
}

Write-Output ""
Write-Output "=== 5. OS build ==="
[System.Environment]::OSVersion.VersionString
