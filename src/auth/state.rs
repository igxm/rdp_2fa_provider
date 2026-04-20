#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthStatus {
    #[default]
    Idle,
    Editing,
    SendingSmsCode,
    SmsCodeSent,
    ReadyToSubmit,
    Authenticating,
    Authenticated,
    Failed,
}
