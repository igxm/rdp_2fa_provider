#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    #[default]
    SmsCode,
    SecondaryPassword,
}

impl AuthMode {
    pub fn toggle(self) -> Self {
        match self {
            Self::SmsCode => Self::SecondaryPassword,
            Self::SecondaryPassword => Self::SmsCode,
        }
    }
}
