# VM validation checklist

This project changes both Credential Provider registration and LSA Authentication
Package registration. Run these steps only inside a disposable Windows VM with a
known rollback path, snapshot, or console access.

## Scope

The VM pass validates the Scheme A data flow:

1. Credential Provider tile loads from `rdp_2fa_provider.dll`.
2. Provider looks up `Rdp2FaAuthPackage` with `LsaLookupAuthenticationPackage`.
3. `GetSerialization` submits the custom `RDP2FA` payload.
4. Winlogon routes the payload to the LSA package.
5. `LogonUserEx2` parses and verifies the payload.
6. LSA token/profile outputs are accepted or failures are reported cleanly.

## Before installing

1. Create a VM snapshot.
2. Ensure there is a second local administrator account or console recovery path.
3. Build the DLL with the same target architecture as the VM.
4. Keep `scripts/unregister_lsa_auth_package.ps1` available inside the VM.
5. Confirm the expected provider CLSID is `{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}`.

## Install

From an elevated PowerShell prompt inside the VM:

```powershell
cargo build
Copy-Item .\target\debug\rdp_2fa_provider.dll C:\Windows\System32\rdp_2fa_provider.dll -Force
reg import .\register.reg
.\scripts\register_lsa_auth_package.ps1 -BuiltDllPath .\target\debug\rdp_2fa_provider.dll
.\scripts\test_vm_registration_state.ps1
Restart-Computer
```

Use the release DLL path instead of `target\debug` when validating a release
build.

## Interactive test cases

1. Confirm the custom tile is visible when `SHOW_TILE=1`.
2. Confirm SMS mode accepts a username, sends the mock code, and submits the payload.
3. Confirm secondary-password mode accepts a username and secondary password.
4. Confirm an empty username or empty mode-specific secret blocks submission in the UI.
5. Confirm an unregistered LSA package shows a user-facing failure instead of crashing LogonUI.
6. Confirm a failed LSA response resets the credential state and keeps the tile usable.

## Evidence to collect

1. `C:\ProgramData\facewinunlock\facewinunlock.log`.
2. Output from `scripts/test_vm_registration_state.ps1`.
3. Screenshots or notes for each interactive test case.
4. Windows version and build number from `winver`.
5. Whether the run used debug or release DLLs.

## Rollback

From an elevated PowerShell prompt:

```powershell
.\scripts\unregister_lsa_auth_package.ps1 -RemoveDll
Remove-Item -LiteralPath C:\Windows\System32\rdp_2fa_provider.dll -Force -ErrorAction SilentlyContinue
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}" /f
reg delete "HKCR\CLSID\{8a7b9c6d-4e5f-89a0-8b7c-6d5e4f3e2d1c}" /f
Restart-Computer
```

If the VM cannot reach the desktop, restore the snapshot or use offline registry
recovery to remove `Rdp2FaAuthPackage` from
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`.

## Pass criteria

The VM validation item can be marked complete only after an interactive logon
attempt exercises the full Credential Provider to LSA path and the result is
captured with logs. A clean preflight alone is not enough to mark VM login
testing complete.
