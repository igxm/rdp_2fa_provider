# LSA Token/Profile Construction Strategy

This document records the implementation strategy for Scheme A after the custom
payload has been parsed and verified by `auth::verification`.

## Primary API Contract

The package implements `LogonUserEx2` through `src/lsa/package.rs`. On success,
the callback must return the data that LSA/Winlogon needs to complete the logon:

1. `ProfileBuffer` and `ProfileBufferSize`
2. `LogonId`
3. `TokenInformationType`
4. `TokenInformation`
5. `AccountName`
6. `AuthenticatingAuthority`
7. Optional `MachineName`
8. Optional primary/supplemental credentials

Microsoft's `LSA_AP_LOGON_USER_EX2` contract says the authentication package is
responsible for allocating the profile buffer in the client process by calling
`AllocateClientBuffer`, and for allocating `TokenInformation`, `AccountName`,
and `AuthenticatingAuthority`; LSA later frees the memory it owns.

## Chosen Implementation Path

Use `LSA_SECPKG_FUNCTION_TABLE` captured in `SpInitialize`.

The preferred path is:

1. Parse and verify `CustomAuthSerialization`.
2. Resolve the Windows account identity for the verified username/domain.
3. Build `LSA_TOKEN_INFORMATION_V1` or use an LSA helper path that produces
   equivalent token information.
4. Allocate profile data for the client with `AllocateClientBuffer`.
5. Return account/audit strings allocated with `AllocateLsaHeap`.
6. Return `STATUS_SUCCESS` only after every required output parameter is valid.

## Open Token Construction Decision

There are two possible token paths:

1. Direct token information path:
   - Fill `LSA_TOKEN_INFORMATION_V1`.
   - Requires resolving SID, group SIDs, primary group, owner, default DACL, and
     expiration.
   - This is explicit but easy to get wrong.

2. LSA helper path:
   - Use LSA-provided helpers such as `ConvertAuthDataToToken` or `CreateToken`
     when a suitable auth-data source is available.
   - This is safer if we can obtain trusted SAM/domain auth data, but requires
     validating which helper is appropriate for a custom passwordless flow.

For the next implementation step, keep `LogonUserEx2` returning
`STATUS_NOT_IMPLEMENTED` after verification. Add small, isolated helpers first:

1. LSA heap Unicode string allocation.
2. Client profile buffer allocation/copy.
3. Account/domain audit string output wiring.
4. Unit-testable builders for data that does not require LSASS.

Only after those helpers are in place should we attempt a success path.

## Safety Rules

1. Never return `STATUS_SUCCESS` from `LogonUserEx2` until profile, account name,
   authenticating authority, token information type, and token information are
   all valid.
2. Never write to output pointers before all required allocation inputs are
   verified.
3. Keep VM rollback scripts available before registering the package.
4. Prefer `STATUS_INVALID_PARAMETER` for malformed payload and
   `STATUS_NOT_IMPLEMENTED` for verified-but-not-yet-logon-capable payload.

## References

1. Microsoft Learn: `LSA_AP_LOGON_USER_EX2`
   https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-lsa_ap_logon_user_ex2
2. Microsoft Learn: `LSA_SECPKG_FUNCTION_TABLE`
   https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/ns-ntsecpkg-lsa_secpkg_function_table
