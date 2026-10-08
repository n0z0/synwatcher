[CmdletBinding()]
param (
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\synwatcher"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " synwatcher Installer / Upgrader (Windows)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Tentukan tag rilis
$Repo = "n0z0/synwatcher"
if ($Version -eq "latest") {
    Write-Host "[*] Memeriksa rilis terbaru dari GitHub..." -ForegroundColor Yellow
    try {
        $ReleaseUrl = "https://api.github.com/repos/$Repo/releases/latest"
        $Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers @{ "User-Agent" = "PowerShell" }
        $TargetTag = $Release.tag_name
    } catch {
        Write-Error "Gagal mendapatkan metadata rilis terbaru: $_"
    }
} else {
    if (-not $Version.StartsWith("v")) {
        $TargetTag = "v" + $Version
    } else {
        $TargetTag = $Version
    }
}

Write-Host "[*] Target versi: $TargetTag" -ForegroundColor Green

# 2. Cek apakah versi sudah terpasang
$CurrentExe = Join-Path $InstallDir "synwatcher.exe"
if (Test-Path $CurrentExe) {
    try {
        $InstalledVer = (& $CurrentExe -version 2>&1).Trim()
        Write-Host "[*] Versi terpasang saat ini: $InstalledVer" -ForegroundColor Cyan
        if ($InstalledVer -like "*$TargetTag*") {
            Write-Host "[OK] synwatcher sudah berada pada versi terbaru ($TargetTag)." -ForegroundColor Green
            Write-Host "    Lokasi: $CurrentExe"
            $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if ($UserPath -notlike "*$InstallDir*") {
                $UpdatedPath = $UserPath.TrimEnd(';') + ';' + $InstallDir
                [Environment]::SetEnvironmentVariable("Path", $UpdatedPath, "User")
                $env:Path = "$env:Path;$InstallDir"
                Write-Host "[*] PATH berhasil ditambahkan." -ForegroundColor Green
            }
            return
        }
    } catch {}
}

# 3. Download asset
$ZipName = "synwatcher_" + $TargetTag + "_windows_amd64.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$TargetTag/$ZipName"
$TempDir = Join-Path $env:TEMP ("synwatcher_install_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
$ZipPath = Join-Path $TempDir $ZipName

Write-Host "[*] Mengunduh $DownloadUrl ..." -ForegroundColor Yellow
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
} catch {
    Write-Error "Gagal mengunduh $DownloadUrl. Error: $_"
}

# 4. Ekstrak dan pasang
Write-Host "[*] Mengekstrak file..." -ForegroundColor Yellow
Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force

$ExtractedFolder = Join-Path $TempDir ("synwatcher_" + $TargetTag + "_windows_amd64")
if (-not (Test-Path $ExtractedFolder)) {
    $ExtractedFolder = $TempDir
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "[*] Memasang ke $InstallDir ..." -ForegroundColor Yellow
Copy-Item -Path (Join-Path $ExtractedFolder "*") -Destination $InstallDir -Recurse -Force

# Bersihkan temp
Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue

# 5. Daftarkan ke PATH User
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "[*] Menambahkan $InstallDir ke PATH pengguna..." -ForegroundColor Yellow
    $UpdatedPath = $UserPath.TrimEnd(';') + ';' + $InstallDir
    [Environment]::SetEnvironmentVariable("Path", $UpdatedPath, "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "[OK] Direktori berhasil ditambahkan ke PATH!" -ForegroundColor Green
} else {
    Write-Host "[*] Direktori sudah ada di PATH." -ForegroundColor Gray
}

# 6. Selesai
Write-Host "==========================================" -ForegroundColor Green
Write-Host " Sukses! synwatcher berhasil dipasang/diupgrade." -ForegroundColor Green
Write-Host " Versi: $TargetTag" -ForegroundColor Green
Write-Host " Lokasi: $CurrentExe" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Catatan:"
Write-Host "1. Pastikan Npcap sudah terinstal di Windows Anda."
Write-Host "2. Buka terminal baru (Administrator) dan jalankan langsung:"
Write-Host '   synwatcher -iface "\Device\NPF_{GUID}"' -ForegroundColor Yellow
