use std::sync::{atomic::Ordering, Arc, Mutex};

use windows::Win32::{
    Foundation::{HANDLE, STATUS_SUCCESS},
    Security::Authentication::Identity::{
        LsaConnectUntrusted, LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage,
        LSA_STRING,
    },
    UI::Shell::*,
};
use windows_core::{implement, BOOL, PSTR, PWSTR};

use crate::{
    auth::{AuthSession, DEFAULT_AUTH_PACKAGE_NAME},
    dll_add_ref, dll_release, read_facewinunlock_registry, CPipeListener::CPipeListener,
    CSampleCredential::SampleCredential, ui_model::FieldId, SharedCredentials,
};

#[implement(ICredentialProvider)]
pub struct SampleProvider {
    inner: Mutex<ProviderInner>,
}

struct ProviderInner {
    usage_scenario: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
    events: Option<ICredentialProviderEvents>,
    advise_context: usize,
    listener: Option<Arc<Mutex<CPipeListener>>>,
    pub shared_creds: Arc<Mutex<SharedCredentials>>,
    pub auth_package_id: u32,
    pub credential: Option<ICredentialProviderCredential>,
}

impl SampleProvider {
    pub fn new() -> Self {
        info!("SampleProvider::new - create provider");
        dll_add_ref();

        let shared = Arc::new(Mutex::new(SharedCredentials {
            auth_session: AuthSession::new(),
            username: String::new(),
            password: String::new(),
            domain: String::from("."),
            is_ready: false,
        }));

        let auth_id = match retrieve_custom_auth_package() {
            Ok(package_id) => package_id,
            Err(error) => {
                error!("custom authentication package lookup failed: {:?}", error);
                0
            }
        };

        Self {
            inner: Mutex::new(ProviderInner {
                usage_scenario: CPUS_LOGON,
                events: None,
                advise_context: 0,
                listener: None,
                shared_creds: shared,
                auth_package_id: auth_id,
                credential: None,
            }),
        }
    }
}

impl Drop for SampleProvider {
    fn drop(&mut self) {
        info!("SampleProvider::drop - destroy provider");
        dll_release();
    }
}

impl ICredentialProvider_Impl for SampleProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> windows_core::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.usage_scenario = cpus;
        Ok(())
    }

    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows_core::Result<()> {
        Ok(())
    }

    fn Advise(
        &self,
        pcpe: windows_core::Ref<ICredentialProviderEvents>,
        upadvisecontext: usize,
    ) -> windows_core::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.events = pcpe.clone();
        inner.advise_context = upadvisecontext;

        if let Some(events) = &inner.events {
            inner.listener = Some(CPipeListener::start(
                events.clone(),
                upadvisecontext,
                inner.shared_creds.clone(),
            ));
        }

        Ok(())
    }

    fn UnAdvise(&self) -> windows_core::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.events = None;
        inner.advise_context = 0;

        if let Some(listener) = inner.listener.take() {
            let mut listener = listener.lock().unwrap();
            listener.stop_and_join();
        }

        inner.listener = None;
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> windows_core::Result<u32> {
        Ok(FieldId::ALL.len() as u32)
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> windows_core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        let field_id = map_field_id(dwindex)?;
        let (field_type, label) = descriptor_for(field_id);

        unsafe {
            let descriptor_ptr = windows::Win32::System::Com::CoTaskMemAlloc(
                std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>(),
            ) as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;
            if descriptor_ptr.is_null() {
                return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
            }

            let label_ptr = alloc_label(label)?;
            (*descriptor_ptr) = CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
                dwFieldID: dwindex,
                cpft: field_type,
                pszLabel: PWSTR(label_ptr),
                guidFieldType: Default::default(),
            };

            Ok(descriptor_ptr)
        }
    }

    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut BOOL,
    ) -> windows_core::Result<()> {
        let inner = self.inner.lock().unwrap();
        let mut show_tile = true;
        if let Ok(result) = read_facewinunlock_registry("SHOW_TILE") {
            if result.as_str() == "0" {
                show_tile = false;
            }
        }

        unsafe {
            *pdwdefault = 0;
            *pbautologonwithdefault = BOOL::from(false);
            *pdwcount = if show_tile { 1 } else { 0 };

            if let Some(listener) = &inner.listener {
                let listener = listener.lock().unwrap();
                if listener.is_unlocked.load(Ordering::SeqCst) {
                    listener.is_unlocked.store(false, Ordering::SeqCst);
                    *pdwcount = 1;
                    *pdwdefault = 0;
                    *pbautologonwithdefault = BOOL::from(true);
                }
            }
        }

        Ok(())
    }

    fn GetCredentialAt(&self, dwindex: u32) -> windows_core::Result<ICredentialProviderCredential> {
        if dwindex != 0 {
            return Err(windows::core::Error::from_hresult(
                windows::Win32::Foundation::E_INVALIDARG,
            ));
        }

        let mut inner = self.inner.lock().unwrap();
        if let Some(ref credential) = inner.credential {
            return Ok(credential.clone());
        }

        let cred = SampleCredential::new(inner.shared_creds.clone(), inner.auth_package_id);
        let cred_interface: ICredentialProviderCredential = cred.into();
        inner.credential = Some(cred_interface.clone());
        Ok(cred_interface)
    }
}

pub fn retrieve_custom_auth_package() -> windows_core::Result<u32> {
    let package_name = read_facewinunlock_registry("CUSTOM_AUTH_PACKAGE_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_AUTH_PACKAGE_NAME.to_string());

    retrieve_auth_package_by_name(&package_name)
}

fn retrieve_auth_package_by_name(package_name_str: &str) -> windows_core::Result<u32> {
    let mut lsa_handle = HANDLE::default();
    let status = unsafe { LsaConnectUntrusted(&mut lsa_handle) };
    if status != STATUS_SUCCESS {
        return Err(status.into());
    }

    let name_bytes = package_name_str.as_bytes();
    let package_name = LSA_STRING {
        Buffer: PSTR(name_bytes.as_ptr() as *mut u8),
        Length: name_bytes.len() as u16,
        MaximumLength: (name_bytes.len() + 1) as u16,
    };

    let mut package_id = 0;
    let status = unsafe { LsaLookupAuthenticationPackage(lsa_handle, &package_name, &mut package_id) };
    let _ = unsafe { LsaDeregisterLogonProcess(lsa_handle) };

    if status == STATUS_SUCCESS {
        Ok(package_id)
    } else {
        Err(status.into())
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
        _ => Err(windows::Win32::Foundation::E_INVALIDARG.into()),
    }
}

fn descriptor_for(field_id: FieldId) -> (CREDENTIAL_PROVIDER_FIELD_TYPE, &'static str) {
    match field_id {
        FieldId::TileImage => (CPFT_TILE_IMAGE, ""),
        FieldId::LargeText => (CPFT_LARGE_TEXT, "自定义认证登录"),
        FieldId::Username => (CPFT_EDIT_TEXT, "用户名"),
        FieldId::SmsCode => (CPFT_EDIT_TEXT, "验证码"),
        FieldId::SecondaryPassword => (CPFT_PASSWORD_TEXT, "二次密码"),
        FieldId::SendSmsCodeButton => (CPFT_COMMAND_LINK, "发送验证码"),
        FieldId::SwitchAuthModeLink => (CPFT_COMMAND_LINK, "切换认证模式"),
        FieldId::SubmitButton => (CPFT_SUBMIT_BUTTON, "登录"),
        FieldId::StatusText => (CPFT_SMALL_TEXT, "状态"),
    }
}

fn alloc_label(label: &str) -> windows_core::Result<*mut u16> {
    unsafe {
        let label_u16: Vec<u16> = label.encode_utf16().chain(Some(0)).collect();
        let label_ptr =
            windows::Win32::System::Com::CoTaskMemAlloc(label_u16.len() * 2) as *mut u16;
        if label_ptr.is_null() {
            return Err(windows::Win32::Foundation::E_OUTOFMEMORY.into());
        }

        std::ptr::copy_nonoverlapping(label_u16.as_ptr(), label_ptr, label_u16.len());
        Ok(label_ptr)
    }
}
