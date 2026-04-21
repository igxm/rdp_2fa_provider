use crate::auth::{
    AuthMode, CustomAuthSerialization, CustomAuthSerializationError, MockSmsService,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLogon {
    pub username: String,
    pub domain: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthVerificationError {
    InvalidPayload(CustomAuthSerializationError),
    MissingUsername,
    MissingSecondaryPassword,
    SmsCodeInvalid(String),
}

pub fn verify_custom_auth_payload(payload: &[u8]) -> Result<VerifiedLogon, AuthVerificationError> {
    let submission = CustomAuthSerialization::from_bytes(payload)
        .map_err(AuthVerificationError::InvalidPayload)?;

    if submission.username.trim().is_empty() {
        return Err(AuthVerificationError::MissingUsername);
    }

    match submission.mode {
        AuthMode::SmsCode => {
            MockSmsService::verify_code(&submission.sms_code)
                .map_err(|message| AuthVerificationError::SmsCodeInvalid(message.to_string()))?;
        }
        AuthMode::SecondaryPassword => {
            if submission.secondary_password.is_empty() {
                return Err(AuthVerificationError::MissingSecondaryPassword);
            }
        }
    }

    Ok(VerifiedLogon {
        username: submission.username,
        domain: submission.domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::MOCK_SMS_CODE;

    #[test]
    fn verifies_sms_payload() {
        let payload = CustomAuthSerialization {
            mode: AuthMode::SmsCode,
            username: "alice".to_string(),
            domain: ".".to_string(),
            sms_code: MOCK_SMS_CODE.to_string(),
            secondary_password: String::new(),
        }
        .to_bytes();

        let verified = verify_custom_auth_payload(&payload).unwrap();

        assert_eq!(verified.username, "alice");
        assert_eq!(verified.domain, ".");
    }

    #[test]
    fn rejects_empty_secondary_password() {
        let payload = CustomAuthSerialization {
            mode: AuthMode::SecondaryPassword,
            username: "alice".to_string(),
            domain: ".".to_string(),
            sms_code: String::new(),
            secondary_password: String::new(),
        }
        .to_bytes();

        let error = verify_custom_auth_payload(&payload).unwrap_err();

        assert_eq!(error, AuthVerificationError::MissingSecondaryPassword);
    }

    #[test]
    fn rejects_missing_username() {
        let payload = CustomAuthSerialization {
            mode: AuthMode::SmsCode,
            username: "   ".to_string(),
            domain: ".".to_string(),
            sms_code: MOCK_SMS_CODE.to_string(),
            secondary_password: String::new(),
        }
        .to_bytes();

        let error = verify_custom_auth_payload(&payload).unwrap_err();

        assert_eq!(error, AuthVerificationError::MissingUsername);
    }

    #[test]
    fn rejects_invalid_sms_code() {
        let payload = CustomAuthSerialization {
            mode: AuthMode::SmsCode,
            username: "alice".to_string(),
            domain: ".".to_string(),
            sms_code: "000000".to_string(),
            secondary_password: String::new(),
        }
        .to_bytes();

        let error = verify_custom_auth_payload(&payload).unwrap_err();

        assert!(matches!(
            error,
            AuthVerificationError::SmsCodeInvalid(message)
                if message.contains("验证码错误") && message.contains(MOCK_SMS_CODE)
        ));
    }

    #[test]
    fn rejects_invalid_payload() {
        let error = verify_custom_auth_payload(b"not-rdp2fa").unwrap_err();

        assert_eq!(
            error,
            AuthVerificationError::InvalidPayload(CustomAuthSerializationError::InvalidMagic)
        );
    }
}
