use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use windows::Win32::{
    Foundation::{ERROR_NOT_READY, E_INVALIDARG, E_NOTIMPL, STATUS_SUCCESS},
    Graphics::Gdi::HBITMAP,
    Security::Credentials::{CredPackAuthenticationBufferW, CRED_PACK_FLAGS},
    System::Com::CoTaskMemAlloc,
    UI::Shell::{
        CPFIS_DISABLED, CPFIS_NONE, CPFIS_READONLY, CPFS_DISPLAY_IN_BOTH,
        CPFS_DISPLAY_IN_SELECTED_TILE, CPFS_HIDDEN, CPGSR_RETURN_CREDENTIAL_FINISHED,
        CPSI_ERROR, CPSI_NONE, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_STATUS_ICON,
        ICredentialProviderCredential, ICredentialProviderCredentialEvents,
        ICredentialProviderCredential_Impl,
    },
};
use windows_core::{implement, BOOL, IUnknownImpl, PCWSTR, PWSTR};

use crate::{
    auth::{AuthAction, AuthMode, MockSmsService, SubmissionReadiness},
    ui_model::{CredentialViewState, FieldDisplayState, FieldId},
    CLSID_SampleProvider, SharedCredentials,
};

const SMS_COUNTDOWN_SECONDS: u32 = 30;

#[derive(Clone)]
struct SendableCredentialEvents(ICredentialProviderCredentialEvents);
unsafe impl Send for SendableCredentialEvents {}
unsafe impl Sync for SendableCredentialEvents {}

#[derive(Clone)]
struct SendableCredential(ICredentialProviderCredential);
unsafe impl Send for SendableCredential {}
unsafe impl Sync for SendableCredential {}

#[implement(ICredentialProviderCredential)]
pub struct SampleCredential {
    events: Mutex<Option<ICredentialProviderCredentialEvents>>,
    shared_creds: Arc<Mutex<SharedCredentials>>,
    auth_package_id: u32,
}

impl SampleCredential {
    pub fn new(shared_creds: Arc<Mutex<SharedCredentials>>, auth_package_id: u32) -> Self {
        info!("SampleCredential::new - create credential");
        Self {
            events: Mutex::new(None),
            shared_creds,
            auth_package_id,
        }
    }
}

impl Drop for SampleCredential {
    fn drop(&mut self) {
        info!("SampleCredential::drop - destroy credential");
    }
}

impl ICredentialProviderCredential_Impl for SampleCredential_Impl {
    fn Advise(
        &self,
        pcpce: windows_core::Ref<ICredentialProviderCredentialEvents>,
    ) -> windows_core::Result<()> {
        info!("SampleCredential::Advise - register credential events");
        let mut events = self.events.lock().unwrap();
        *events = pcpce.clone();
        Ok(())
    }

    fn UnAdvise(&self) -> windows_core::Result<()> {
        info!("SampleCredential::UnAdvise - clear credential events");
        let mut events = self.events.lock().unwrap();
        *events = None;
        Ok(())
    }

    fn SetSelected(&self) -> windows_core::Result<BOOL> {
        info!("SampleCredential::SetSelected - selected");
        let mut shared = self.shared_creds.lock().unwrap();
        shared.auth_session.apply(AuthAction::ClearError);
        drop(shared);
        refresh_ui(self)?;
        Ok(true.into())
    }

    fn SetDeselected(&self) -> windows_core::Result<()> {
        info!("SampleCredential::SetDeselected - deselected");
        Ok(())
    }

    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows_core::Result<()> {
        let field_id = map_field_id(dwfieldid)?;
        let shared = self.shared_creds.lock().unwrap();
        let view_state = CredentialViewState::from_session(&shared.auth_session);
        let display_state = view_state.field_state(field_id, &shared.auth_session);

        unsafe {
            *pcpfs = to_cpfs(field_id, display_state);
            *pcpfis = to_cpfis(field_id, display_state, view_state.can_submit(&shared.auth_session));
        }

        Ok(())
    }

    fn GetStringValue(&self, dwfieldid: u32) -> windows_core::Result<PWSTR> {
        let field_id = map_field_id(dwfieldid)?;
        let shared = self.shared_creds.lock().unwrap();
        let view_state = CredentialViewState::from_session(&shared.auth_session);
        let value = field_string(&shared, &view_state, field_id);
        alloc_pwstr(&value)
    }

    fn GetBitmapValue(&self, _dwfieldid: u32) -> windows_core::Result<HBITMAP> {
        Ok(HBITMAP::default())
    }

    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> windows_core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetSubmitButtonValue(&self, dwfieldid: u32) -> windows_core::Result<u32> {
        if map_field_id(dwfieldid)? == FieldId::SubmitButton {
            Ok(FieldId::Username as u32)
        } else {
            Err(E_INVALIDARG.into())
        }
    }

    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32,
    ) -> windows_core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> windows_core::Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn SetStringValue(
        &self,
        dwfieldid: u32,
        psz: &windows_core::PCWSTR,
    ) -> windows_core::Result<()> {
        let field_id = map_field_id(dwfieldid)?;
        let value = unsafe { psz.to_string() }?;
        let mut shared = self.shared_creds.lock().unwrap();

        match field_id {
            FieldId::Username => {
                shared.auth_session.apply(AuthAction::UpdateUsername(value.clone()));
                shared.username = value;
            }
            FieldId::SmsCode => {
                shared.auth_session.apply(AuthAction::UpdateSmsCode(value));
            }
            FieldId::SecondaryPassword => {
                shared
                    .auth_session
                    .apply(AuthAction::UpdateSecondaryPassword(value.clone()));
                shared.password = value;
            }
            _ => return Err(E_INVALIDARG.into()),
        }

        drop(shared);
        refresh_ui(self)?;
        Ok(())
    }

    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> windows_core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn SetComboBoxSelectedValue(
        &self,
        _dwfieldid: u32,
        _dwselecteditem: u32,
    ) -> windows_core::Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn CommandLinkClicked(&self, dwfieldid: u32) -> windows_core::Result<()> {
        let field_id = map_field_id(dwfieldid)?;
        let credential: ICredentialProviderCredential = self.to_interface();
        let events = self.events.lock().unwrap().clone();

        let mut start_countdown = false;
        let mut shared = self.shared_creds.lock().unwrap();
        match field_id {
            FieldId::SwitchAuthModeLink => {
                shared.auth_session.toggle_mode();
                if shared.auth_session.mode() != AuthMode::SecondaryPassword {
                    shared.password.clear();
                }
                shared.is_ready = false;
            }
            FieldId::SendSmsCodeButton => {
                shared.auth_session.apply(AuthAction::BeginSmsCodeSend);
                let username = shared.auth_session.username().to_string();
                match MockSmsService::send_code(&username) {
                    Ok(code) => {
                        shared.auth_session.apply(AuthAction::MarkSmsCodeSent(
                            format!("验证码已发送，测试码为 {code}"),
                            SMS_COUNTDOWN_SECONDS,
                        ));
                        start_countdown = true;
                    }
                    Err(message) => {
                        shared.auth_session.apply(AuthAction::MarkFailed(message.to_string()));
                    }
                }
            }
            _ => return Err(E_INVALIDARG.into()),
        }

        drop(shared);
        refresh_ui(self)?;

        if start_countdown {
            if let Some(events) = events {
                spawn_sms_countdown(
                    self.shared_creds.clone(),
                    SendableCredentialEvents(events),
                    SendableCredential(credential),
                );
            }
        }

        Ok(())
    }

    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows_core::Result<()> {
        {
            let mut creds = self.shared_creds.lock().unwrap();
            if creds.auth_session.mode() == AuthMode::SmsCode {
                creds.auth_session.apply(AuthAction::BeginAuthentication);
                match creds.auth_session.submission_readiness() {
                    SubmissionReadiness::Ready => {
                        let code = creds.auth_session.sms_code().to_string();
                        match MockSmsService::verify_code(&code) {
                            Ok(()) => creds.auth_session.apply(AuthAction::MarkAuthenticated),
                            Err(message) => {
                                creds.auth_session.apply(AuthAction::MarkFailed(message.to_string()))
                            }
                        }
                    }
                    SubmissionReadiness::Blocked(error) => {
                        creds.auth_session.apply(AuthAction::MarkFailed(error.message().to_string()));
                    }
                }
                drop(creds);
                refresh_ui(self)?;
                return Err(ERROR_NOT_READY.into());
            }
        }

        unsafe {
            let creds = self.shared_creds.lock().unwrap();
            let mut username = creds.username.clone();
            let mut password = creds.password.clone();

            if !creds.is_ready {
                if creds.auth_session.mode() == AuthMode::SecondaryPassword
                    && matches!(creds.auth_session.submission_readiness(), SubmissionReadiness::Ready)
                {
                    username = creds.auth_session.username().to_string();
                    password = creds.auth_session.secondary_password().to_string();
                } else {
                    return Err(ERROR_NOT_READY.into());
                }
            }

            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

            let full_username = if creds.domain.is_empty() || creds.domain == "." {
                username
            } else {
                format!("{}\\{}", creds.domain, username)
            };

            let v_username = to_wide_vec(&full_username);
            let v_password = to_wide_vec(&password);
            let pwz_username = PCWSTR(v_username.as_ptr());
            let pwz_password = PCWSTR(v_password.as_ptr());

            let mut auth_buffer_size: u32 = 0;
            let _ = CredPackAuthenticationBufferW(
                CRED_PACK_FLAGS(0),
                pwz_username,
                pwz_password,
                None,
                &mut auth_buffer_size,
            );

            let out_buf = CoTaskMemAlloc(auth_buffer_size as usize) as *mut u8;

            CredPackAuthenticationBufferW(
                CRED_PACK_FLAGS(0),
                pwz_username,
                pwz_password,
                Some(out_buf),
                &mut auth_buffer_size,
            )?;

            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
            (*pcpcs).clsidCredentialProvider = CLSID_SampleProvider;
            (*pcpcs).cbSerialization = auth_buffer_size;
            (*pcpcs).rgbSerialization = out_buf;
            (*pcpcs).ulAuthenticationPackage = self.auth_package_id;
        }

        Ok(())
    }

    fn ReportResult(
        &self,
        ntsstatus: windows::Win32::Foundation::NTSTATUS,
        _ntssubstatus: windows::Win32::Foundation::NTSTATUS,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows_core::Result<()> {
        unsafe {
            if ntsstatus != STATUS_SUCCESS {
                let mut creds = self.shared_creds.lock().unwrap();
                creds.auth_session.apply(AuthAction::Reset);
                creds.username.clear();
                creds.password.clear();
                creds.is_ready = false;

                let error_text = "用户名或密码错误，请手动输入正确凭据";
                let utf16: Vec<u16> = error_text.encode_utf16().chain(Some(0)).collect();
                let ptr = windows::Win32::System::Com::CoTaskMemAlloc(utf16.len() * 2);
                if !ptr.is_null() {
                    std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr as *mut u16, utf16.len());
                    *ppszoptionalstatustext = PWSTR(ptr as *mut _);
                }

                *pcpsioptionalstatusicon = CPSI_ERROR;
            } else {
                *ppszoptionalstatustext = PWSTR(std::ptr::null_mut());
                *pcpsioptionalstatusicon = CPSI_NONE;
            }
        }

        Ok(())
    }
}

fn to_wide_vec(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn alloc_pwstr(value: &str) -> windows_core::Result<PWSTR> {
    unsafe {
        let utf16: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
        let ptr = windows::Win32::System::Com::CoTaskMemAlloc(utf16.len() * 2);
        if ptr.is_null() {
            return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
        }

        std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr as *mut u16, utf16.len());
        Ok(PWSTR(ptr as *mut _))
    }
}

fn map_field_id(field_id: u32) -> windows_core::Result<FieldId> {
    match field_id {
        0 => Ok(FieldId::TileImage),
        1 => Ok(FieldId::LargeText),
        2 => Ok(FieldId::Username),
        3 => Ok(FieldId::SmsCode),
        4 => Ok(FieldId::SecondaryPassword),
        5 => Ok(FieldId::SendSmsCodeButton),
        6 => Ok(FieldId::SwitchAuthModeLink),
        7 => Ok(FieldId::SubmitButton),
        8 => Ok(FieldId::StatusText),
        _ => Err(E_INVALIDARG.into()),
    }
}

fn to_cpfs(field_id: FieldId, display_state: FieldDisplayState) -> CREDENTIAL_PROVIDER_FIELD_STATE {
    if !display_state.visible {
        return CPFS_HIDDEN;
    }

    match field_id {
        FieldId::TileImage | FieldId::LargeText => CPFS_DISPLAY_IN_BOTH,
        _ => CPFS_DISPLAY_IN_SELECTED_TILE,
    }
}

fn to_cpfis(
    field_id: FieldId,
    display_state: FieldDisplayState,
    can_submit: bool,
) -> CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE {
    if !display_state.visible {
        return CPFIS_NONE;
    }

    if !display_state.interactive {
        return CPFIS_READONLY;
    }

    if field_id == FieldId::SubmitButton && !can_submit {
        CPFIS_DISABLED
    } else {
        CPFIS_NONE
    }
}

fn refresh_ui(credential_impl: &SampleCredential_Impl) -> windows_core::Result<()> {
    let events = credential_impl.events.lock().unwrap().clone();
    let Some(events) = events else {
        return Ok(());
    };

    let credential: ICredentialProviderCredential = credential_impl.to_interface();
    refresh_ui_components(
        &credential_impl.shared_creds,
        &SendableCredentialEvents(events),
        &SendableCredential(credential),
    )
}

fn refresh_ui_components(
    shared_creds: &Arc<Mutex<SharedCredentials>>,
    events: &SendableCredentialEvents,
    credential: &SendableCredential,
) -> windows_core::Result<()> {
    let shared = shared_creds.lock().unwrap();
    let view_state = CredentialViewState::from_session(&shared.auth_session);
    let can_submit = view_state.can_submit(&shared.auth_session);

    for field_id in FieldId::ALL {
        let display_state = view_state.field_state(field_id, &shared.auth_session);
        let cpfs = to_cpfs(field_id, display_state);
        let cpfis = to_cpfis(field_id, display_state, can_submit);
        let label = field_string(&shared, &view_state, field_id);
        let wide = to_wide_vec(&label);
        let wide_pcwstr = PCWSTR(wide.as_ptr());

        unsafe {
            events.0.SetFieldState(&credential.0, field_id as u32, cpfs)?;
            events
                .0
                .SetFieldInteractiveState(&credential.0, field_id as u32, cpfis)?;
            events
                .0
                .SetFieldString(&credential.0, field_id as u32, wide_pcwstr)?;
        }
    }

    Ok(())
}

fn spawn_sms_countdown(
    shared_creds: Arc<Mutex<SharedCredentials>>,
    events: SendableCredentialEvents,
    credential: SendableCredential,
) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));

        let should_continue = {
            let mut shared = shared_creds.lock().unwrap();
            if shared.auth_session.mode() != AuthMode::SmsCode {
                false
            } else if shared.auth_session.sms_countdown_remaining() > 0 {
                shared.auth_session.apply(AuthAction::TickSmsCountdown);
                if shared.auth_session.sms_countdown_remaining() == 0 {
                    shared.auth_session.apply(AuthAction::FinishSmsCountdown);
                    false
                } else {
                    true
                }
            } else {
                false
            }
        };

        let _ = refresh_ui_components(&shared_creds, &events, &credential);

        if !should_continue {
            break;
        }
    });
}

fn field_string(
    shared: &SharedCredentials,
    view_state: &CredentialViewState,
    field_id: FieldId,
) -> String {
    match field_id {
        FieldId::TileImage => String::new(),
        FieldId::LargeText => view_state.label(FieldId::LargeText, &shared.auth_session),
        FieldId::Username => shared.auth_session.username().to_string(),
        FieldId::SmsCode => shared.auth_session.sms_code().to_string(),
        FieldId::SecondaryPassword => shared.auth_session.secondary_password().to_string(),
        FieldId::SendSmsCodeButton => view_state.label(FieldId::SendSmsCodeButton, &shared.auth_session),
        FieldId::SwitchAuthModeLink => {
            view_state.label(FieldId::SwitchAuthModeLink, &shared.auth_session)
        }
        FieldId::SubmitButton => view_state.label(FieldId::SubmitButton, &shared.auth_session),
        FieldId::StatusText => view_state.status_text.clone(),
    }
}
