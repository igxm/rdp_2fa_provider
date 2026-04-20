#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum FieldId {
    TileImage = 0,
    LargeText = 1,
    Username = 2,
    SmsCode = 3,
    SecondaryPassword = 4,
    SendSmsCodeButton = 5,
    SwitchAuthModeLink = 6,
    SubmitButton = 7,
    StatusText = 8,
}

impl FieldId {
    pub const ALL: [FieldId; 9] = [
        FieldId::TileImage,
        FieldId::LargeText,
        FieldId::Username,
        FieldId::SmsCode,
        FieldId::SecondaryPassword,
        FieldId::SendSmsCodeButton,
        FieldId::SwitchAuthModeLink,
        FieldId::SubmitButton,
        FieldId::StatusText,
    ];
}
