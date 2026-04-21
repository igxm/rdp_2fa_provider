param(
    [Parameter(Mandatory = $true)]
    [string] $BuiltDllPath,

    [string] $PackageName = "Rdp2FaAuthPackage"
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$resolvedDll = (Resolve-Path -LiteralPath $BuiltDllPath).Path
$targetDll = Join-Path $env:WINDIR "System32\$PackageName.dll"
Copy-Item -LiteralPath $resolvedDll -Destination $targetDll -Force

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$existing = @(Get-ItemPropertyValue -Path $lsaPath -Name "Authentication Packages")
if ($existing -notcontains $PackageName) {
    $updated = @($existing + $PackageName)
    Set-ItemProperty -Path $lsaPath -Name "Authentication Packages" -Type MultiString -Value $updated
}

$configPath = "HKLM:\SOFTWARE\facewinunlock-tauri"
if (-not (Test-Path $configPath)) {
    New-Item -Path $configPath -Force | Out-Null
}
Set-ItemProperty -Path $configPath -Name "CUSTOM_AUTH_PACKAGE_NAME" -Type String -Value $PackageName

Write-Host "Installed $PackageName to $targetDll"
Write-Host "Restart Windows before testing LSA package lookup from LogonUI."
