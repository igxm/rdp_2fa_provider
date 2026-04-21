use crate::auth::AuthMode;

pub const DEFAULT_AUTH_PACKAGE_NAME: &str = "Rdp2FaAuthPackage";
const SERIALIZATION_MAGIC: &[u8; 8] = b"RDP2FA\0\0";
const SERIALIZATION_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomAuthSerialization {
    pub mode: AuthMode,
    pub username: String,
    pub domain: String,
    pub sms_code: String,
    pub secondary_password: String,
}

impl CustomAuthSerialization {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SERIALIZATION_MAGIC);
        bytes.extend_from_slice(&SERIALIZATION_VERSION.to_le_bytes());
        bytes.extend_from_slice(&mode_tag(self.mode).to_le_bytes());
        append_utf16_field(&mut bytes, &self.username);
        append_utf16_field(&mut bytes, &self.domain);
        append_utf16_field(&mut bytes, &self.sms_code);
        append_utf16_field(&mut bytes, &self.secondary_password);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CustomAuthSerializationError> {
        let mut cursor = Cursor::new(bytes);
        let magic = cursor.take(SERIALIZATION_MAGIC.len())?;
        if magic != SERIALIZATION_MAGIC {
            return Err(CustomAuthSerializationError::InvalidMagic);
        }

        let version = cursor.read_u16()?;
        if version != SERIALIZATION_VERSION {
            return Err(CustomAuthSerializationError::UnsupportedVersion(version));
        }

        let mode = match cursor.read_u16()? {
            1 => AuthMode::SmsCode,
            2 => AuthMode::SecondaryPassword,
            tag => return Err(CustomAuthSerializationError::UnsupportedMode(tag)),
        };

        let submission = Self {
            mode,
            username: cursor.read_utf16_field()?,
            domain: cursor.read_utf16_field()?,
            sms_code: cursor.read_utf16_field()?,
            secondary_password: cursor.read_utf16_field()?,
        };

        if !cursor.is_done() {
            return Err(CustomAuthSerializationError::TrailingBytes);
        }

        Ok(submission)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustomAuthSerializationError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u16),
    UnsupportedMode(u16),
    InvalidUtf16,
    TrailingBytes,
}

fn mode_tag(mode: AuthMode) -> u16 {
    match mode {
        AuthMode::SmsCode => 1,
        AuthMode::SecondaryPassword => 2,
    }
}

fn append_utf16_field(bytes: &mut Vec<u8>, value: &str) {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    bytes.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    for unit in utf16 {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CustomAuthSerializationError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CustomAuthSerializationError::Truncated)?;
        if end > self.bytes.len() {
            return Err(CustomAuthSerializationError::Truncated);
        }

        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, CustomAuthSerializationError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, CustomAuthSerializationError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_utf16_field(&mut self) -> Result<String, CustomAuthSerializationError> {
        let code_units = self.read_u32()? as usize;
        let byte_len = code_units
            .checked_mul(2)
            .ok_or(CustomAuthSerializationError::Truncated)?;
        let bytes = self.take(byte_len)?;
        let utf16: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        String::from_utf16(&utf16).map_err(|_| CustomAuthSerializationError::InvalidUtf16)
    }

    fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_has_stable_header_and_fields() {
        let payload = CustomAuthSerialization {
            mode: AuthMode::SmsCode,
            username: "alice".to_string(),
            domain: ".".to_string(),
            sms_code: "123456".to_string(),
            secondary_password: String::new(),
        }
        .to_bytes();

        assert_eq!(&payload[0..8], SERIALIZATION_MAGIC);
        assert_eq!(
            u16::from_le_bytes([payload[8], payload[9]]),
            SERIALIZATION_VERSION
        );
        assert_eq!(u16::from_le_bytes([payload[10], payload[11]]), 1);
    }

    #[test]
    fn serialization_round_trips() {
        let expected = CustomAuthSerialization {
            mode: AuthMode::SecondaryPassword,
            username: "bob".to_string(),
            domain: "EXAMPLE".to_string(),
            sms_code: String::new(),
            secondary_password: "secret".to_string(),
        };

        let actual = CustomAuthSerialization::from_bytes(&expected.to_bytes()).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut payload = CustomAuthSerialization {
            mode: AuthMode::SmsCode,
            username: "alice".to_string(),
            domain: ".".to_string(),
            sms_code: "123456".to_string(),
            secondary_password: String::new(),
        }
        .to_bytes();
        payload[0] = b'X';

        let error = CustomAuthSerialization::from_bytes(&payload).unwrap_err();

        assert_eq!(error, CustomAuthSerializationError::InvalidMagic);
    }

    #[test]
    fn rejects_unsupported_mode() {
        let mut payload = Vec::new();
        payload.extend_from_slice(SERIALIZATION_MAGIC);
        payload.extend_from_slice(&SERIALIZATION_VERSION.to_le_bytes());
        payload.extend_from_slice(&99u16.to_le_bytes());

        let error = CustomAuthSerialization::from_bytes(&payload).unwrap_err();

        assert_eq!(error, CustomAuthSerializationError::UnsupportedMode(99));
    }

    #[test]
    fn rejects_truncated_utf16_field() {
        let mut payload = Vec::new();
        payload.extend_from_slice(SERIALIZATION_MAGIC);
        payload.extend_from_slice(&SERIALIZATION_VERSION.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&b'a'.to_le_bytes());

        let error = CustomAuthSerialization::from_bytes(&payload).unwrap_err();

        assert_eq!(error, CustomAuthSerializationError::Truncated);
    }

    #[test]
    fn rejects_invalid_utf16() {
        let mut payload = Vec::new();
        payload.extend_from_slice(SERIALIZATION_MAGIC);
        payload.extend_from_slice(&SERIALIZATION_VERSION.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&0xD800u16.to_le_bytes());

        let error = CustomAuthSerialization::from_bytes(&payload).unwrap_err();

        assert_eq!(error, CustomAuthSerializationError::InvalidUtf16);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut payload = CustomAuthSerialization {
            mode: AuthMode::SmsCode,
            username: "alice".to_string(),
            domain: ".".to_string(),
            sms_code: "123456".to_string(),
            secondary_password: String::new(),
        }
        .to_bytes();
        payload.push(0);

        let error = CustomAuthSerialization::from_bytes(&payload).unwrap_err();

        assert_eq!(error, CustomAuthSerializationError::TrailingBytes);
    }
}
