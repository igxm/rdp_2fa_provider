#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    MissingUsername,
    SmsCodeNotSent,
    MissingSmsCode,
    MissingSecondaryPassword,
}

impl AuthError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::MissingUsername => "用户名不能为空",
            Self::SmsCodeNotSent => "请先发送验证码",
            Self::MissingSmsCode => "验证码不能为空",
            Self::MissingSecondaryPassword => "二次密码不能为空",
        }
    }
}
