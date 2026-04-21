use std::{ffi::c_void, slice, sync::OnceLock};

use windows::Win32::{
    Foundation::{
        LUID, NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS,
    },
    Security::Authentication::Identity::{
        LSA_DISPATCH_TABLE, LSA_SECPKG_FUNCTION_TABLE, LSA_STRING, LSA_TOKEN_INFORMATION_TYPE,
        LSA_UNICODE_STRING, SECPKG_FUNCTION_TABLE, SECPKG_INTERFACE_VERSION, SECPKG_PARAMETERS,
        SECPKG_PRIMARY_CRED, SECPKG_SUPPLEMENTAL_CRED_ARRAY, SECURITY_LOGON_TYPE,
    },
};
use windows_core::PSTR;

use crate::auth::{CustomAuthSerialization, DEFAULT_AUTH_PACKAGE_NAME};

static PACKAGE_TABLE: OnceLock<SECPKG_FUNCTION_TABLE> = OnceLock::new();
static LSA_FUNCTION_TABLE: OnceLock<LSA_SECPKG_FUNCTION_TABLE> = OnceLock::new();

/// Entry point used by LSA to discover this authentication package's callbacks.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SpLsaModeInitialize(
    _lsaversion: u32,
    packageversion: *mut u32,
    pptables: *mut *mut SECPKG_FUNCTION_TABLE,
    pctables: *mut u32,
) -> NTSTATUS {
    if packageversion.is_null() || pptables.is_null() || pctables.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let table = PACKAGE_TABLE.get_or_init(|| SECPKG_FUNCTION_TABLE {
        InitializePackage: Some(lsa_initialize_package),
        LogonUserEx2: Some(lsa_logon_user_ex2),
        Initialize: Some(sp_initialize),
        ..Default::default()
    });

    unsafe {
        *packageversion = SECPKG_INTERFACE_VERSION;
        *pptables = table as *const _ as *mut _;
        *pctables = 1;
    }

    STATUS_SUCCESS
}

unsafe extern "system" fn sp_initialize(
    _packageid: usize,
    _parameters: *const SECPKG_PARAMETERS,
    functiontable: *const LSA_SECPKG_FUNCTION_TABLE,
) -> NTSTATUS {
    if functiontable.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let _ = LSA_FUNCTION_TABLE.set(unsafe { *functiontable });
    STATUS_SUCCESS
}

unsafe extern "system" fn lsa_initialize_package(
    _authenticationpackageid: u32,
    lsadispatchtable: *const LSA_DISPATCH_TABLE,
    _database: *const LSA_STRING,
    _confidentiality: *const LSA_STRING,
    authenticationpackagename: *mut *mut LSA_STRING,
) -> NTSTATUS {
    if lsadispatchtable.is_null() || authenticationpackagename.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let Some(allocate_lsa_heap) = (unsafe { (*lsadispatchtable).AllocateLsaHeap }) else {
        return STATUS_INVALID_PARAMETER;
    };

    let name = DEFAULT_AUTH_PACKAGE_NAME.as_bytes();
    let name_struct = unsafe { allocate_lsa_heap(size_of::<LSA_STRING>() as u32) } as *mut LSA_STRING;
    let name_buffer = unsafe { allocate_lsa_heap((name.len() + 1) as u32) } as *mut u8;
    if name_struct.is_null() || name_buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), name_buffer, name.len());
        *name_buffer.add(name.len()) = 0;
        *name_struct = LSA_STRING {
            Length: name.len() as u16,
            MaximumLength: (name.len() + 1) as u16,
            Buffer: PSTR(name_buffer),
        };
        *authenticationpackagename = name_struct;
    }

    STATUS_SUCCESS
}

unsafe extern "system" fn lsa_logon_user_ex2(
    _clientrequest: *const *const c_void,
    _logontype: SECURITY_LOGON_TYPE,
    protocolsubmitbuffer: *const c_void,
    _clientbufferbase: *const c_void,
    submitbuffersize: u32,
    _profilebuffer: *mut *mut c_void,
    _profilebuffersize: *mut u32,
    _logonid: *mut LUID,
    substatus: *mut i32,
    _tokeninformationtype: *mut LSA_TOKEN_INFORMATION_TYPE,
    _tokeninformation: *mut *mut c_void,
    _accountname: *mut *mut LSA_UNICODE_STRING,
    _authenticatingauthority: *mut *mut LSA_UNICODE_STRING,
    _machinename: *mut *mut LSA_UNICODE_STRING,
    _primarycredentials: *mut SECPKG_PRIMARY_CRED,
    _supplementalcredentials: *mut *mut SECPKG_SUPPLEMENTAL_CRED_ARRAY,
) -> NTSTATUS {
    if protocolsubmitbuffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let payload =
        unsafe { slice::from_raw_parts(protocolsubmitbuffer as *const u8, submitbuffersize as usize) };
    if CustomAuthSerialization::from_bytes(payload).is_err() {
        return STATUS_INVALID_PARAMETER;
    }

    if LSA_FUNCTION_TABLE.get().is_none() {
        return STATUS_INVALID_PARAMETER;
    }

    if !substatus.is_null() {
        unsafe {
            *substatus = STATUS_NOT_IMPLEMENTED.0;
        }
    }

    // The parser and LSA entry points are wired. Token construction is the next task.
    STATUS_NOT_IMPLEMENTED
}
