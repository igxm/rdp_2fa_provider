use super::{FieldDisplayState, FieldId};
use crate::auth::{AuthMode, AuthSession, AuthStatus, SubmissionReadiness};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialViewState {
    pub mode: AuthMode,
    pub status_text: String,
}

impl CredentialViewState {
    pub fn from_session(session: &AuthSession) -> Self {
        let status_text = if let Some(message) = session.error_message() {
            message.to_string()
        } else {
            match session.status() {
                AuthStatus::Idle => String::from("请输入登录信息"),
                AuthStatus::Editing => String::from("请补全认证信息"),
                AuthStatus::SendingSmsCode => String::from("正在发送验证码"),
                AuthStatus::SmsCodeSent => String::from("验证码已发送"),
                AuthStatus::ReadyToSubmit => String::from("可以提交认证"),
                AuthStatus::Authenticating => String::from("正在认证"),
                AuthStatus::Authenticated => String::from("认证成功"),
                AuthStatus::Failed => String::from("认证失败"),
            }
        };

        Self {
            mode: session.mode(),
            status_text,
        }
    }

    pub fn field_state(&self, field: FieldId, session: &AuthSession) -> FieldDisplayState {
        match field {
            FieldId::TileImage | FieldId::LargeText | FieldId::StatusText => {
                FieldDisplayState::DISPLAY_ONLY
            }
            FieldId::Username | FieldId::SwitchAuthModeLink => FieldDisplayState::EDITABLE,
            FieldId::SubmitButton => FieldDisplayState::EDITABLE,
            FieldId::SmsCode => {
                if self.mode == AuthMode::SmsCode {
                    FieldDisplayState::EDITABLE
                } else {
                    FieldDisplayState::HIDDEN
                }
            }
            FieldId::SendSmsCodeButton => {
                if self.mode == AuthMode::SmsCode {
                    // Keep the button visible during cooldown so the user understands why resend is unavailable.
                    if session.is_sms_send_available() {
                        FieldDisplayState::EDITABLE
                    } else {
                        FieldDisplayState {
                            visible: true,
                            interactive: false,
                        }
                    }
                } else {
                    FieldDisplayState::HIDDEN
                }
            }
            FieldId::SecondaryPassword => {
                if self.mode == AuthMode::SecondaryPassword {
                    FieldDisplayState::EDITABLE
                } else {
                    FieldDisplayState::HIDDEN
                }
            }
        }
    }

    pub fn label(&self, field: FieldId, session: &AuthSession) -> String {
        match field {
            FieldId::TileImage => String::new(),
            FieldId::LargeText => String::from("自定义认证登录"),
            FieldId::Username => String::from("用户名"),
            FieldId::SmsCode => String::from("验证码"),
            FieldId::SecondaryPassword => String::from("二次密码"),
            FieldId::SendSmsCodeButton => {
                // Reuse the same button field for both the initial send and resend countdown states.
                if session.sms_countdown_remaining() > 0 {
                    format!("重新发送({}s)", session.sms_countdown_remaining())
                } else {
                    String::from("发送验证码")
                }
            }
            FieldId::SwitchAuthModeLink => match self.mode {
                AuthMode::SmsCode => String::from("使用二次密码登录"),
                AuthMode::SecondaryPassword => String::from("使用验证码登录"),
            },
            FieldId::SubmitButton => String::from("登录"),
            FieldId::StatusText => String::new(),
        }
    }

    pub fn can_submit(&self, session: &AuthSession) -> bool {
        matches!(session.submission_readiness(), SubmissionReadiness::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthAction;

    #[test]
    fn sms_mode_hides_secondary_password_field() {
        let session = AuthSession::new();
        let view = CredentialViewState::from_session(&session);

        assert_eq!(
            view.field_state(FieldId::SmsCode, &session),
            FieldDisplayState::EDITABLE
        );
        assert_eq!(
            view.field_state(FieldId::SecondaryPassword, &session),
            FieldDisplayState::HIDDEN
        );
    }

    #[test]
    fn password_mode_hides_sms_fields() {
        let mut session = AuthSession::new();
        session.apply(AuthAction::SwitchMode(AuthMode::SecondaryPassword));
        let view = CredentialViewState::from_session(&session);

        assert_eq!(
            view.field_state(FieldId::SecondaryPassword, &session),
            FieldDisplayState::EDITABLE
        );
        assert_eq!(
            view.field_state(FieldId::SmsCode, &session),
            FieldDisplayState::HIDDEN
        );
        assert_eq!(
            view.field_state(FieldId::SendSmsCodeButton, &session),
            FieldDisplayState::HIDDEN
        );
    }

    #[test]
    fn submit_availability_tracks_session_readiness() {
        let mut session = AuthSession::new();
        let view = CredentialViewState::from_session(&session);
        assert!(!view.can_submit(&session));

        session.apply(AuthAction::UpdateUsername("alice".into()));
        session.apply(AuthAction::MarkSmsCodeSent("sent".into(), 30));
        session.apply(AuthAction::UpdateSmsCode("123456".into()));
        let view = CredentialViewState::from_session(&session);

        assert!(view.can_submit(&session));
    }

    #[test]
    fn resend_button_shows_countdown_and_is_disabled() {
        let mut session = AuthSession::new();
        session.apply(AuthAction::UpdateUsername("alice".into()));
        session.apply(AuthAction::MarkSmsCodeSent("sent".into(), 30));
        let view = CredentialViewState::from_session(&session);

        assert_eq!(
            view.field_state(FieldId::SendSmsCodeButton, &session),
            FieldDisplayState {
                visible: true,
                interactive: false,
            }
        );
        assert_eq!(view.label(FieldId::SendSmsCodeButton, &session), "重新发送(30s)");
    }
}
