param(
    [string] $PackageName = "Rdp2FaAuthPackage",
    [string] $ProviderDllName = "rdp_2fa_provider.dll",
    [string] $ProviderClsid = "{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}",
    [string] $ConfigRegistryPath = "HKLM:\SOFTWARE\facewinunlock-tauri"
)

$ErrorActionPreference = "Stop"

function Add-CheckResult {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]] $Results,
        [Parameter(Mandatory = $true)]
        [string] $Name,
        [Parameter(Mandatory = $true)]
        [bool] $Passed,
        [string] $Detail = ""
    )

    $Results.Add([pscustomobject]@{
        Check  = $Name
        Passed = $Passed
        Detail = $Detail
    }) | Out-Null
}

$results = [System.Collections.Generic.List[object]]::new()

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$authPackages = @()
try {
    $authPackages = @(Get-ItemPropertyValue -Path $lsaPath -Name "Authentication Packages")
    Add-CheckResult $results "Read LSA Authentication Packages" $true $lsaPath
} catch {
    Add-CheckResult $results "Read LSA Authentication Packages" $false $_.Exception.Message
}

Add-CheckResult `
    $results `
    "LSA package is registered" `
    ($authPackages -contains $PackageName) `
    ("Authentication Packages = " + (($authPackages | Where-Object { $_ }) -join ", "))

$packageDll = Join-Path $env:WINDIR "System32\$PackageName.dll"
Add-CheckResult `
    $results `
    "LSA package DLL exists" `
    (Test-Path -LiteralPath $packageDll) `
    $packageDll

$providerDll = Join-Path $env:WINDIR "System32\$ProviderDllName"
Add-CheckResult `
    $results `
    "Credential Provider DLL exists" `
    (Test-Path -LiteralPath $providerDll) `
    $providerDll

$providerRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$ProviderClsid"
Add-CheckResult `
    $results `
    "Credential Provider is registered" `
    (Test-Path -LiteralPath $providerRegistryPath) `
    $providerRegistryPath

$classRegistryPath = "Registry::HKEY_CLASSES_ROOT\CLSID\$ProviderClsid\InprocServer32"
Add-CheckResult `
    $results `
    "Credential Provider COM class is registered" `
    (Test-Path -LiteralPath $classRegistryPath) `
    $classRegistryPath

$configuredPackageName = $null
$configuredLogPath = $null
if (Test-Path -LiteralPath $ConfigRegistryPath) {
    $configuredPackageName = Get-ItemPropertyValue -Path $ConfigRegistryPath -Name "CUSTOM_AUTH_PACKAGE_NAME" -ErrorAction SilentlyContinue
    $configuredLogPath = Get-ItemPropertyValue -Path $ConfigRegistryPath -Name "DLL_LOG_PATH" -ErrorAction SilentlyContinue
}

Add-CheckResult `
    $results `
    "Custom auth package config matches" `
    ($configuredPackageName -eq $PackageName) `
    "CUSTOM_AUTH_PACKAGE_NAME = $configuredPackageName"

Add-CheckResult `
    $results `
    "Log path config is present" `
    (-not [string]::IsNullOrWhiteSpace($configuredLogPath)) `
    "DLL_LOG_PATH = $configuredLogPath"

$logFile = if ([string]::IsNullOrWhiteSpace($configuredLogPath)) {
    "C:\ProgramData\facewinunlock\facewinunlock.log"
} else {
    Join-Path $configuredLogPath "facewinunlock.log"
}
Add-CheckResult `
    $results `
    "Provider log file path is writable or exists" `
    ((Test-Path -LiteralPath $logFile) -or (Test-Path -LiteralPath (Split-Path -Parent $logFile))) `
    $logFile

$results | Format-Table -AutoSize

$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    Write-Error "VM registration preflight failed: $($failed.Count) check(s) failed."
    exit 1
}

Write-Host "VM registration preflight passed. Restart Windows before interactive LogonUI testing if registration changed."
