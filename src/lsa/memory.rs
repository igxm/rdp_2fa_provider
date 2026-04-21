use windows::Win32::{
    Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY, STATUS_SUCCESS},
    Security::Authentication::Identity::{LSA_SECPKG_FUNCTION_TABLE, LSA_UNICODE_STRING},
};
use windows_core::PWSTR;

pub unsafe fn allocate_lsa_unicode_string(
    lsa: &LSA_SECPKG_FUNCTION_TABLE,
    value: &str,
    out: *mut *mut LSA_UNICODE_STRING,
) -> NTSTATUS {
    if out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let Some(allocate_lsa_heap) = lsa.AllocateLsaHeap else {
        return STATUS_INVALID_PARAMETER;
    };

    let string_ptr =
        unsafe { allocate_lsa_heap(size_of::<LSA_UNICODE_STRING>() as u32) } as *mut LSA_UNICODE_STRING;
    if string_ptr.is_null() {
        return STATUS_NO_MEMORY;
    }

    let utf16 = to_utf16_null_terminated(value);
    let byte_len = (utf16.len() - 1) * 2;
    let max_byte_len = utf16.len() * 2;
    let buffer_ptr = if utf16.len() > 1 {
        let ptr = unsafe { allocate_lsa_heap(max_byte_len as u32) } as *mut u16;
        if ptr.is_null() {
            return STATUS_NO_MEMORY;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
        }
        ptr
    } else {
        std::ptr::null_mut()
    };

    unsafe {
        *string_ptr = LSA_UNICODE_STRING {
            Length: byte_len as u16,
            MaximumLength: max_byte_len as u16,
            Buffer: PWSTR(buffer_ptr),
        };
        *out = string_ptr;
    }

    STATUS_SUCCESS
}

fn to_utf16_null_terminated(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_conversion_appends_single_nul() {
        let units = to_utf16_null_terminated("abc");

        assert_eq!(units, vec![97, 98, 99, 0]);
    }

    #[test]
    fn utf16_conversion_keeps_empty_string_allocatable() {
        let units = to_utf16_null_terminated("");

        assert_eq!(units, vec![0]);
    }
}
