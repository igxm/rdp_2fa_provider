use super::{AuthAction, AuthError, AuthMode, AuthStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionReadiness {
    Ready,
    Blocked(AuthError),
}

#[derive(Debug, Clone, Default)]
pub struct AuthSession {
    mode: AuthMode,
    status: AuthStatus,
    username: String,
    sms_code: String,
    sms_code_sent: bool,
    sms_countdown_remaining: u32,
    secondary_password: String,
    error_message: Option<String>,
}

impl AuthSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    pub fn status(&self) -> &AuthStatus {
        &self.status
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn sms_code(&self) -> &str {
        &self.sms_code
    }

    pub fn sms_code_sent(&self) -> bool {
        self.sms_code_sent
    }

    pub fn sms_countdown_remaining(&self) -> u32 {
        self.sms_countdown_remaining
    }

    pub fn secondary_password(&self) -> &str {
        &self.secondary_password
    }

    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    pub fn is_sms_send_available(&self) -> bool {
        self.mode == AuthMode::SmsCode
            && !matches!(self.status, AuthStatus::SendingSmsCode)
            && self.sms_countdown_remaining == 0
    }

    pub fn apply(&mut self, action: AuthAction) {
        match action {
            AuthAction::SwitchMode(mode) => {
                self.mode = mode;
                self.status = AuthStatus::Idle;
                self.sms_code.clear();
                self.sms_code_sent = false;
                self.sms_countdown_remaining = 0;
                self.secondary_password.clear();
                self.error_message = None;
            }
            AuthAction::UpdateUsername(value) => {
                self.username = value;
                self.bump_editing_status();
            }
            AuthAction::UpdateSmsCode(value) => {
                self.sms_code = value;
                self.bump_editing_status();
            }
            AuthAction::UpdateSecondaryPassword(value) => {
                self.secondary_password = value;
                self.bump_editing_status();
            }
            AuthAction::BeginSmsCodeSend => {
                self.error_message = None;
                self.status = AuthStatus::SendingSmsCode;
            }
            AuthAction::MarkSmsCodeSent(message, countdown) => {
                self.sms_code_sent = true;
                self.sms_countdown_remaining = countdown;
                self.error_message = Some(message);
                self.status = AuthStatus::SmsCodeSent;
            }
            AuthAction::TickSmsCountdown => {
                if self.sms_countdown_remaining > 0 {
                    self.sms_countdown_remaining -= 1;
                }
            }
            AuthAction::FinishSmsCountdown => {
                self.sms_countdown_remaining = 0;
                if self.sms_code_sent {
                    self.error_message = Some(String::from("验证码已过期，可重新发送"));
                }
            }
            AuthAction::ClearError => {
                self.error_message = None;
                if self.status == AuthStatus::Failed {
                    self.status = AuthStatus::Idle;
                }
            }
            AuthAction::BeginAuthentication => {
                self.error_message = None;
                self.status = AuthStatus::Authenticating;
            }
            AuthAction::MarkAuthenticated => {
                self.error_message = None;
                self.status = AuthStatus::Authenticated;
            }
            AuthAction::MarkFailed(message) => {
                self.error_message = Some(message);
                self.status = AuthStatus::Failed;
            }
            AuthAction::Reset => {
                *self = Self::default();
            }
        }

        if matches!(self.status, AuthStatus::Idle | AuthStatus::Editing | AuthStatus::ReadyToSubmit)
        {
            self.status = match self.submission_readiness() {
                SubmissionReadiness::Ready => AuthStatus::ReadyToSubmit,
                SubmissionReadiness::Blocked(_) if self.is_any_input_present() => AuthStatus::Editing,
                SubmissionReadiness::Blocked(_) => AuthStatus::Idle,
            };
        }
    }

    pub fn toggle_mode(&mut self) {
        self.apply(AuthAction::SwitchMode(self.mode.toggle()));
    }

    pub fn submission_readiness(&self) -> SubmissionReadiness {
        if self.username.trim().is_empty() {
            return SubmissionReadiness::Blocked(AuthError::MissingUsername);
        }

        match self.mode {
            AuthMode::SmsCode => {
                if !self.sms_code_sent {
                    SubmissionReadiness::Blocked(AuthError::SmsCodeNotSent)
                } else if self.sms_code.trim().is_empty() {
                    SubmissionReadiness::Blocked(AuthError::MissingSmsCode)
                } else {
                    SubmissionReadiness::Ready
                }
            }
            AuthMode::SecondaryPassword => {
                if self.secondary_password.trim().is_empty() {
                    SubmissionReadiness::Blocked(AuthError::MissingSecondaryPassword)
                } else {
                    SubmissionReadiness::Ready
                }
            }
        }
    }

    fn bump_editing_status(&mut self) {
        if !matches!(
            self.status,
            AuthStatus::Authenticating | AuthStatus::Authenticated | AuthStatus::SendingSmsCode
        ) {
            self.status = AuthStatus::Editing;
        }
    }

    fn is_any_input_present(&self) -> bool {
        !self.username.is_empty() || !self.sms_code.is_empty() || !self.secondary_password.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggling_mode_clears_mode_specific_inputs() {
        let mut session = AuthSession::new();
        session.apply(AuthAction::UpdateUsername("alice".into()));
        session.apply(AuthAction::UpdateSmsCode("123456".into()));

        session.toggle_mode();

        assert_eq!(session.mode(), AuthMode::SecondaryPassword);
        assert_eq!(session.sms_code(), "");
        assert_eq!(session.secondary_password(), "");
    }

    #[test]
    fn readiness_requires_sms_code_in_sms_mode() {
        let mut session = AuthSession::new();
        session.apply(AuthAction::UpdateUsername("alice".into()));

        assert_eq!(
            session.submission_readiness(),
            SubmissionReadiness::Blocked(AuthError::SmsCodeNotSent)
        );

        session.apply(AuthAction::MarkSmsCodeSent("sent".into(), 30));
        assert_eq!(
            session.submission_readiness(),
            SubmissionReadiness::Blocked(AuthError::MissingSmsCode)
        );

        session.apply(AuthAction::UpdateSmsCode("123456".into()));
        assert_eq!(session.submission_readiness(), SubmissionReadiness::Ready);
    }

    #[test]
    fn readiness_requires_secondary_password_in_password_mode() {
        let mut session = AuthSession::new();
        session.apply(AuthAction::UpdateUsername("alice".into()));
        session.apply(AuthAction::SwitchMode(AuthMode::SecondaryPassword));

        assert_eq!(
            session.submission_readiness(),
            SubmissionReadiness::Blocked(AuthError::MissingSecondaryPassword)
        );

        session.apply(AuthAction::UpdateSecondaryPassword("secret".into()));
        assert_eq!(session.submission_readiness(), SubmissionReadiness::Ready);
    }

    #[test]
    fn switching_mode_resets_sms_send_state() {
        let mut session = AuthSession::new();
        session.apply(AuthAction::UpdateUsername("alice".into()));
        session.apply(AuthAction::MarkSmsCodeSent("sent".into(), 30));

        assert!(session.sms_code_sent());

        session.toggle_mode();
        session.toggle_mode();

        assert!(!session.sms_code_sent());
        assert_eq!(session.sms_countdown_remaining(), 0);
    }

    #[test]
    fn countdown_disables_resend_until_finished() {
        let mut session = AuthSession::new();
        session.apply(AuthAction::UpdateUsername("alice".into()));
        session.apply(AuthAction::MarkSmsCodeSent("sent".into(), 2));

        assert!(!session.is_sms_send_available());
        session.apply(AuthAction::TickSmsCountdown);
        assert_eq!(session.sms_countdown_remaining(), 1);
        assert!(!session.is_sms_send_available());

        session.apply(AuthAction::TickSmsCountdown);
        session.apply(AuthAction::FinishSmsCountdown);
        assert_eq!(session.sms_countdown_remaining(), 0);
        assert!(session.is_sms_send_available());
    }
}
