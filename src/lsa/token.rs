use std::ffi::c_void;

use windows::Win32::{
    Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS},
    Security::{
        CreateWellKnownSid, PSID, SID_AND_ATTRIBUTES, TOKEN_DEFAULT_DACL, TOKEN_GROUPS,
        TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_USER, WinAuthenticatedUserSid, WinBuiltinUsersSid,
        WinWorldSid, SECURITY_MAX_SID_SIZE,
    },
    Security::Authentication::Identity::{
        LSA_SECPKG_FUNCTION_TABLE, LSA_TOKEN_INFORMATION_V1,
    },
    System::SystemServices::{
        SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY,
    },
};

use crate::lsa::account::ResolvedAccount;

const DEFAULT_GROUP_ATTRIBUTES: u32 =
    (SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED) as u32;

pub unsafe fn allocate_token_information_v1(
    lsa: &LSA_SECPKG_FUNCTION_TABLE,
    account: &ResolvedAccount,
    token_information: *mut *mut c_void,
) -> NTSTATUS {
    if token_information.is_null() || account.sid.is_empty() {
        return STATUS_INVALID_PARAMETER;
    }

    let Some(allocate_lsa_heap) = lsa.AllocateLsaHeap else {
        return STATUS_INVALID_PARAMETER;
    };

    let token_info = unsafe { allocate_lsa_heap(size_of::<LSA_TOKEN_INFORMATION_V1>() as u32) }
        as *mut LSA_TOKEN_INFORMATION_V1;
    if token_info.is_null() {
        return STATUS_NO_MEMORY;
    }

    let user_sid = unsafe { copy_sid_to_lsa_heap(lsa, &account.sid) };
    if user_sid.is_invalid() {
        return STATUS_NO_MEMORY;
    }

    let world_sid = unsafe { allocate_well_known_sid(lsa, WinWorldSid) };
    let authenticated_users_sid = unsafe { allocate_well_known_sid(lsa, WinAuthenticatedUserSid) };
    let builtin_users_sid = unsafe { allocate_well_known_sid(lsa, WinBuiltinUsersSid) };
    if world_sid.is_invalid() || authenticated_users_sid.is_invalid() || builtin_users_sid.is_invalid() {
        return STATUS_NO_MEMORY;
    }

    let group_sids = [world_sid, authenticated_users_sid, builtin_users_sid];
    let groups = unsafe { allocate_token_groups(lsa, &group_sids) };
    if groups.is_null() {
        return STATUS_NO_MEMORY;
    }

    unsafe {
        *token_info = LSA_TOKEN_INFORMATION_V1 {
            ExpirationTime: i64::MAX,
            User: TOKEN_USER {
                User: SID_AND_ATTRIBUTES {
                    Sid: user_sid,
                    Attributes: 0,
                },
            },
            Groups: groups,
            PrimaryGroup: TOKEN_PRIMARY_GROUP {
                PrimaryGroup: builtin_users_sid,
            },
            Privileges: std::ptr::null_mut(),
            Owner: TOKEN_OWNER { Owner: user_sid },
            DefaultDacl: TOKEN_DEFAULT_DACL {
                DefaultDacl: std::ptr::null_mut(),
            },
        };
        *token_information = token_info as *mut c_void;
    }

    STATUS_SUCCESS
}

unsafe fn allocate_token_groups(
    lsa: &LSA_SECPKG_FUNCTION_TABLE,
    group_sids: &[PSID],
) -> *mut TOKEN_GROUPS {
    let Some(allocate_lsa_heap) = lsa.AllocateLsaHeap else {
        return std::ptr::null_mut();
    };

    if group_sids.is_empty() {
        return std::ptr::null_mut();
    }

    let size = size_of::<TOKEN_GROUPS>() + (group_sids.len() - 1) * size_of::<SID_AND_ATTRIBUTES>();
    let groups = unsafe { allocate_lsa_heap(size as u32) } as *mut TOKEN_GROUPS;
    if groups.is_null() {
        return std::ptr::null_mut();
    }

    unsafe {
        (*groups).GroupCount = group_sids.len() as u32;
        let first_group = (*groups).Groups.as_mut_ptr();
        for (index, sid) in group_sids.iter().enumerate() {
            *first_group.add(index) = SID_AND_ATTRIBUTES {
                Sid: *sid,
                Attributes: DEFAULT_GROUP_ATTRIBUTES,
            };
        }
    }

    groups
}

unsafe fn allocate_well_known_sid(
    lsa: &LSA_SECPKG_FUNCTION_TABLE,
    sid_type: windows::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> PSID {
    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_len = sid.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            sid_type,
            None,
            Some(PSID(sid.as_mut_ptr() as *mut c_void)),
            &mut sid_len,
        )
    }
    .is_err()
    {
        return PSID::default();
    }

    sid.truncate(sid_len as usize);
    unsafe { copy_sid_to_lsa_heap(lsa, &sid) }
}

unsafe fn copy_sid_to_lsa_heap(lsa: &LSA_SECPKG_FUNCTION_TABLE, sid: &[u8]) -> PSID {
    let Some(allocate_lsa_heap) = lsa.AllocateLsaHeap else {
        return PSID::default();
    };

    if sid.is_empty() {
        return PSID::default();
    }

    let ptr = unsafe { allocate_lsa_heap(sid.len() as u32) } as *mut u8;
    if ptr.is_null() {
        return PSID::default();
    }

    unsafe {
        std::ptr::copy_nonoverlapping(sid.as_ptr(), ptr, sid.len());
    }

    PSID(ptr as *mut c_void)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_group_attributes_enable_basic_groups() {
        assert_eq!(DEFAULT_GROUP_ATTRIBUTES & SE_GROUP_MANDATORY as u32, 1);
        assert_eq!(DEFAULT_GROUP_ATTRIBUTES & SE_GROUP_ENABLED_BY_DEFAULT as u32, 2);
        assert_eq!(DEFAULT_GROUP_ATTRIBUTES & SE_GROUP_ENABLED as u32, 4);
    }
}
