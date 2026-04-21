use std::ffi::c_void;

use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};
use windows_core::{PCWSTR, PWSTR};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAccount {
    pub account_name: String,
    pub referenced_domain: String,
    pub sid: Vec<u8>,
    pub sid_name_use: SID_NAME_USE,
}

pub fn resolve_account_sid(domain: &str, username: &str) -> windows_core::Result<ResolvedAccount> {
    let account_name = format_account_name(domain, username);
    let account_wide = to_wide(&account_name);

    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_name_use = SID_NAME_USE::default();

    let _ = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account_wide.as_ptr()),
            None,
            &mut sid_len,
            None,
            &mut domain_len,
            &mut sid_name_use,
        )
    };

    let mut sid = vec![0u8; sid_len as usize];
    let mut referenced_domain = vec![0u16; domain_len as usize];

    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account_wide.as_ptr()),
            Some(PSID(sid.as_mut_ptr() as *mut c_void)),
            &mut sid_len,
            Some(PWSTR(referenced_domain.as_mut_ptr())),
            &mut domain_len,
            &mut sid_name_use,
        )?;
    }

    sid.truncate(sid_len as usize);

    Ok(ResolvedAccount {
        account_name,
        referenced_domain: String::from_utf16_lossy(
            &referenced_domain[..domain_len.saturating_sub(1) as usize],
        ),
        sid,
        sid_name_use,
    })
}

fn format_account_name(domain: &str, username: &str) -> String {
    if domain.trim().is_empty() || domain == "." {
        username.to_string()
    } else {
        format!("{domain}\\{username}")
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_domain_uses_bare_username() {
        assert_eq!(format_account_name(".", "alice"), "alice");
        assert_eq!(format_account_name("", "alice"), "alice");
    }

    #[test]
    fn explicit_domain_uses_downlevel_name() {
        assert_eq!(format_account_name("EXAMPLE", "alice"), "EXAMPLE\\alice");
    }

    #[test]
    fn wide_conversion_appends_nul() {
        assert_eq!(to_wide("ab"), vec![97, 98, 0]);
    }
}
