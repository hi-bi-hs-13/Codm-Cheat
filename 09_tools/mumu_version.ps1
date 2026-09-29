$ErrorActionPreference = 'SilentlyContinue'
Write-Output "=== MuMu key binaries: version + modified date ==="
$paths = @(
  "C:\Program Files\Netease\MuMuPlayer\nx_device\15.0\shell\MuMuNxDevice.exe",
  "C:\Program Files\Netease\MuMuPlayer\nx_main\MuMuNxMain.exe",
  "C:\Program Files\MuMuNxVbox\Hypervisor\MuMuNxSVC.exe"
)
foreach ($p in $paths) {
  if (Test-Path $p) {
    $f = Get-Item $p
    $v = $f.VersionInfo.FileVersion
    Write-Output ($f.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + "  v" + $v + "  " + $p)
  } else { Write-Output ("MISSING: " + $p) }
}
Write-Output ""
Write-Output "=== MuMu install dirs (which shell versions exist) ==="
Get-ChildItem "C:\Program Files\Netease\MuMuPlayer" -Directory | ForEach-Object { Write-Output $_.FullName }
Get-ChildItem "C:\Program Files\Netease\MuMuPlayer\nx_device" -Directory | ForEach-Object { Write-Output $_.FullName }
Write-Output ""
Write-Output "=== MuMuVMM / VBox files (the VMM engine the DLL drives) ==="
Get-ChildItem "C:\Program Files\MuMuNxVbox" -Recurse -Filter "*.dll" -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'VMM|VBoxVMM|Nemu|MuMu' } |
  Select-Object -First 10 |
  ForEach-Object { Write-Output ($_.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + "  " + $_.FullName) }
