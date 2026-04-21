use std::ffi::c_void;

use windows::Win32::{
    Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS},
    Security::Authentication::Identity::LSA_SECPKG_FUNCTION_TABLE,
};

use crate::auth::VerifiedLogon;

const PROFILE_MAGIC: &[u8; 8] = b"R2FAPRF\0";
const PROFILE_VERSION: u16 = 1;

pub fn build_profile_buffer(logon: &VerifiedLogon) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROFILE_MAGIC);
    bytes.extend_from_slice(&PROFILE_VERSION.to_le_bytes());
    append_utf16_field(&mut bytes, &logon.username);
    append_utf16_field(&mut bytes, &logon.domain);
    bytes
}

pub unsafe fn allocate_client_profile_buffer(
    lsa: &LSA_SECPKG_FUNCTION_TABLE,
    client_request: *const *const c_void,
    profile: &[u8],
    profile_buffer: *mut *mut c_void,
    profile_buffer_size: *mut u32,
) -> NTSTATUS {
    if client_request.is_null()
        || profile_buffer.is_null()
        || profile_buffer_size.is_null()
        || profile.is_empty()
    {
        return STATUS_INVALID_PARAMETER;
    }

    let Some(allocate_client_buffer) = lsa.AllocateClientBuffer else {
        return STATUS_INVALID_PARAMETER;
    };
    let Some(copy_to_client_buffer) = lsa.CopyToClientBuffer else {
        return STATUS_INVALID_PARAMETER;
    };

    let mut client_buffer = std::ptr::null_mut();
    let status = unsafe {
        allocate_client_buffer(
            client_request,
            profile.len() as u32,
            &mut client_buffer,
        )
    };
    if status != STATUS_SUCCESS {
        return status;
    }

    let status = unsafe {
        copy_to_client_buffer(
            client_request,
            profile.len() as u32,
            client_buffer,
            profile.as_ptr() as *const c_void,
        )
    };
    if status != STATUS_SUCCESS {
        return status;
    }

    unsafe {
        *profile_buffer = client_buffer;
        *profile_buffer_size = profile.len() as u32;
    }

    STATUS_SUCCESS
}

fn append_utf16_field(bytes: &mut Vec<u8>, value: &str) {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    bytes.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    for unit in utf16 {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_buffer_has_stable_header() {
        let buffer = build_profile_buffer(&VerifiedLogon {
            username: "alice".to_string(),
            domain: ".".to_string(),
        });

        assert_eq!(&buffer[0..8], PROFILE_MAGIC);
        assert_eq!(u16::from_le_bytes([buffer[8], buffer[9]]), PROFILE_VERSION);
    }

    #[test]
    fn profile_buffer_includes_username_and_domain_lengths() {
        let buffer = build_profile_buffer(&VerifiedLogon {
            username: "bob".to_string(),
            domain: "EXAMPLE".to_string(),
        });

        let username_len = u32::from_le_bytes([buffer[10], buffer[11], buffer[12], buffer[13]]);
        let domain_offset = 14 + (username_len as usize * 2);
        let domain_len = u32::from_le_bytes([
            buffer[domain_offset],
            buffer[domain_offset + 1],
            buffer[domain_offset + 2],
            buffer[domain_offset + 3],
        ]);

        assert_eq!(username_len, 3);
        assert_eq!(domain_len, 7);
    }
}
