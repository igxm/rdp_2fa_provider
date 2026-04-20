#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDisplayState {
    pub visible: bool,
    pub interactive: bool,
}

impl FieldDisplayState {
    pub const HIDDEN: Self = Self {
        visible: false,
        interactive: false,
    };

    pub const DISPLAY_ONLY: Self = Self {
        visible: true,
        interactive: false,
    };

    pub const EDITABLE: Self = Self {
        visible: true,
        interactive: true,
    };
}
