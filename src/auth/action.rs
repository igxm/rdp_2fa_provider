use super::AuthMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAction {
    SwitchMode(AuthMode),
    UpdateUsername(String),
    UpdateSmsCode(String),
    UpdateSecondaryPassword(String),
    BeginSmsCodeSend,
    MarkSmsCodeSent(String, u32),
    TickSmsCountdown,
    FinishSmsCountdown,
    ClearError,
    BeginAuthentication,
    MarkAuthenticated,
    MarkFailed(String),
    Reset,
}
