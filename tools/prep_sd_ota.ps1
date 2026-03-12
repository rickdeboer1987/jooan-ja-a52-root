# Format SD card (disk 2) as FAT32 and copy JOOAN_FW_PKG
$ErrorActionPreference = "Stop"

Write-Host "=== Preparing SD card for Jooan OTA ==="

# Clear and repartition
Write-Host "[1] Clearing disk 2..."
Clear-Disk -Number 2 -RemoveData -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[2] Creating FAT32 partition..."
$part = New-Partition -DiskNumber 2 -UseMaximumSize -AssignDriveLetter
$drive = $part.DriveLetter
Format-Volume -DriveLetter $drive -FileSystem FAT32 -NewFileSystemLabel "JOOAN_OTA" -Confirm:$false

Write-Host "[3] Copying OTA file as JOOAN_FW_PKG to ${drive}:\..."
Copy-Item "C:\Users\Rick\CAMERA\jooan_ota_root.bin" "${drive}:\JOOAN_FW_PKG"

Write-Host "[4] Verifying..."
Get-ChildItem "${drive}:\" | Format-Table Name, Length -AutoSize

$hash = (Get-FileHash "${drive}:\JOOAN_FW_PKG" -Algorithm MD5).Hash
Write-Host "    MD5: $hash"

Write-Host ""
Write-Host "=== DONE ==="
Write-Host "SD card ready. Insert into camera, power cycle."
Write-Host "The camera should detect JOOAN_FW_PKG and run the upgrade."
Start-Sleep 3
