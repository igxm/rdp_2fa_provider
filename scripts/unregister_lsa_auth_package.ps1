param(
    [string] $PackageName = "Rdp2FaAuthPackage",
    [switch] $RemoveDll
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$existing = @(Get-ItemPropertyValue -Path $lsaPath -Name "Authentication Packages")
$updated = @($existing | Where-Object { $_ -ne $PackageName })
Set-ItemProperty -Path $lsaPath -Name "Authentication Packages" -Type MultiString -Value $updated

$configPath = "HKLM:\SOFTWARE\facewinunlock-tauri"
if (Test-Path $configPath) {
    Remove-ItemProperty -Path $configPath -Name "CUSTOM_AUTH_PACKAGE_NAME" -ErrorAction SilentlyContinue
}

if ($RemoveDll) {
    $targetDll = Join-Path $env:WINDIR "System32\$PackageName.dll"
    Remove-Item -LiteralPath $targetDll -Force -ErrorAction SilentlyContinue
}

Write-Host "Removed $PackageName from LSA Authentication Packages."
Write-Host "Restart Windows before retesting LSA package lookup."
