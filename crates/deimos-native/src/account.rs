use std::collections::{HashMap, HashSet};
use std::fmt;
#[cfg(not(windows))]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use deimos_core::secret::{MAX_PASSWORD_BYTES, MAX_USERNAME_BYTES};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.deimos.wizard101.account";
#[cfg(target_os = "macos")]
const APPKIT_PROMPT_CLASSES: [&str; 8] = [
    "NSAlert",
    "NSApplication",
    "NSAutoreleasePool",
    "NSSecureTextField",
    "NSString",
    "NSTextField",
    "NSThread",
    "NSView",
];
#[cfg(windows)]
const WINDOWS_TARGET_PREFIX: &str = "Deimos/account/";
const MAX_NICKNAME_BYTES: usize = 128;
const MAX_ACCOUNTS: usize = 1024;
const METADATA_VERSION: u32 = 1;
static METADATA_LOCK: Mutex<()> = Mutex::new(());

#[cfg(target_os = "macos")]
#[link(name = "AppKit", kind = "framework")]
extern "C" {
    #[link_name = "NSApplicationLoad"]
    fn ns_application_load() -> std::ffi::c_schar;
}

pub struct StoredCredential {
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
}

impl StoredCredential {
    #[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
    pub fn new(username: Vec<u8>, password: Vec<u8>) -> Result<Self, AccountError> {
        let username = Zeroizing::new(username);
        let password = Zeroizing::new(password);
        validate_secret_fields(&username, &password)?;
        Ok(Self { username, password })
    }

    pub fn username(&self) -> &[u8] {
        &self.username
    }

    pub fn password(&self) -> &[u8] {
        &self.password
    }
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoredCredential([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountErrorKind {
    InvalidInput,
    #[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
    Cancelled,
    #[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
    NotFound,
    Storage,
    Metadata,
    #[cfg(not(any(target_os = "macos", windows)))]
    Unsupported,
}

#[derive(Debug)]
pub struct AccountError {
    pub kind: AccountErrorKind,
    pub message: String,
}

impl AccountError {
    fn new(kind: AccountErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for AccountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AccountError {}

#[derive(Debug, Deserialize, Serialize)]
struct AccountMetadata {
    version: u32,
    nicknames_order: Vec<String>,
    gid_map: HashMap<String, u64>,
}

impl Default for AccountMetadata {
    fn default() -> Self {
        Self {
            version: METADATA_VERSION,
            nicknames_order: Vec::new(),
            gid_map: HashMap::new(),
        }
    }
}

pub trait CredentialStore {
    fn save(&self, nickname: &str, credential: &StoredCredential) -> Result<(), AccountError>;
    fn read(&self, nickname: &str) -> Result<StoredCredential, AccountError>;
    fn delete(&self, nickname: &str) -> Result<(), AccountError>;
    fn contains(&self, nickname: &str) -> bool;

    fn list_nicknames(&self) -> Result<Option<Vec<String>>, AccountError> {
        Ok(None)
    }
}

pub trait CredentialPrompt {
    fn prompt(&self, nickname: &str) -> Result<StoredCredential, AccountError>;
}

pub struct AccountService<S, P> {
    store: S,
    prompt: P,
    metadata_path: PathBuf,
}

impl<S: CredentialStore, P: CredentialPrompt> AccountService<S, P> {
    pub fn new(store: S, prompt: P, metadata_path: PathBuf) -> Self {
        Self {
            store,
            prompt,
            metadata_path,
        }
    }

    pub fn prompt_save(&self, nickname: &str) -> Result<(), AccountError> {
        validate_nickname(nickname)?;
        let credential = self.prompt.prompt(nickname)?;
        let _metadata_guard = lock_metadata()?;
        let existed = self.store.contains(nickname);
        self.store.save(nickname, &credential)?;
        let metadata_result = (|| {
            let mut metadata = self.load_metadata()?;
            if !metadata
                .nicknames_order
                .iter()
                .any(|value| value == nickname)
            {
                metadata.nicknames_order.push(nickname.to_string());
            }
            self.save_metadata(&metadata)
        })();
        if let Err(error) = metadata_result {
            if !existed {
                let _ = self.store.delete(nickname);
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn read(&self, nickname: &str) -> Result<StoredCredential, AccountError> {
        validate_nickname(nickname)?;
        self.store.read(nickname)
    }

    pub fn delete(&self, nickname: &str) -> Result<(), AccountError> {
        validate_nickname(nickname)?;
        let _metadata_guard = lock_metadata()?;
        let credential = self.store.read(nickname)?;
        let mut metadata = self.load_metadata()?;
        self.store.delete(nickname)?;
        metadata.nicknames_order.retain(|value| value != nickname);
        metadata.gid_map.remove(nickname);
        if let Err(error) = self.save_metadata(&metadata) {
            if self.store.save(nickname, &credential).is_err() {
                return Err(AccountError::new(
                    AccountErrorKind::Storage,
                    "account deletion failed and the secure credential could not be restored",
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<String>, AccountError> {
        let _metadata_guard = lock_metadata()?;
        let metadata = self.load_metadata()?;
        if let Some(stored) = self.store.list_nicknames()? {
            let mut ordered = Vec::new();
            for nickname in metadata.nicknames_order {
                if stored.contains(&nickname) {
                    ordered.push(nickname);
                }
            }
            for nickname in stored {
                if !ordered.contains(&nickname) {
                    ordered.push(nickname);
                }
            }
            return Ok(ordered);
        }
        Ok(metadata
            .nicknames_order
            .into_iter()
            .filter(|nickname| self.store.contains(nickname))
            .collect())
    }

    pub fn reorder(&self, ordered: &[String]) -> Result<(), AccountError> {
        if ordered.len() > MAX_ACCOUNTS {
            return Err(AccountError::new(
                AccountErrorKind::InvalidInput,
                "account order contains too many entries",
            ));
        }
        let mut seen = HashSet::new();
        for nickname in ordered {
            validate_nickname(nickname)?;
            if !seen.insert(nickname) {
                return Err(AccountError::new(
                    AccountErrorKind::InvalidInput,
                    "account order contains a duplicate nickname",
                ));
            }
        }
        let _metadata_guard = lock_metadata()?;
        let mut metadata = self.load_metadata()?;
        metadata.nicknames_order = ordered.to_vec();
        self.save_metadata(&metadata)
    }

    pub fn contains(&self, nickname: &str) -> bool {
        validate_nickname(nickname).is_ok() && self.store.contains(nickname)
    }

    pub fn update_gid(&self, nickname: &str, gid: u64) -> Result<(), AccountError> {
        validate_nickname(nickname)?;
        let _metadata_guard = lock_metadata()?;
        let mut metadata = self.load_metadata()?;
        metadata.gid_map.insert(nickname.to_string(), gid);
        self.save_metadata(&metadata)
    }

    pub fn gid(&self, nickname: &str) -> Result<Option<u64>, AccountError> {
        validate_nickname(nickname)?;
        let _metadata_guard = lock_metadata()?;
        Ok(self.load_metadata()?.gid_map.get(nickname).copied())
    }

    pub fn nickname_for_gid(&self, gid: u64) -> Result<Option<String>, AccountError> {
        let _metadata_guard = lock_metadata()?;
        Ok(self
            .load_metadata()?
            .gid_map
            .into_iter()
            .find_map(|(nickname, value)| (value == gid).then_some(nickname)))
    }

    fn load_metadata(&self) -> Result<AccountMetadata, AccountError> {
        let metadata_file = match fs::symlink_metadata(&self.metadata_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(AccountMetadata::default())
            }
            Err(error) => return Err(metadata_io("inspect", error)),
        };
        if metadata_file.file_type().is_symlink() || !metadata_file.is_file() {
            return Err(AccountError::new(
                AccountErrorKind::Metadata,
                "account metadata must be a regular file, not a link",
            ));
        }
        let bytes = fs::read(&self.metadata_path).map_err(|error| metadata_io("read", error))?;
        if bytes.len() > 1024 * 1024 {
            return Err(AccountError::new(
                AccountErrorKind::Metadata,
                "account metadata exceeds the one-megabyte safety limit",
            ));
        }
        let metadata: AccountMetadata = serde_json::from_slice(&bytes).map_err(|_| {
            AccountError::new(
                AccountErrorKind::Metadata,
                "account metadata is not valid JSON; restore or remove the metadata file",
            )
        })?;
        validate_metadata(&metadata)?;
        Ok(metadata)
    }

    fn save_metadata(&self, metadata: &AccountMetadata) -> Result<(), AccountError> {
        validate_metadata(metadata)?;
        let parent = self.metadata_path.parent().ok_or_else(|| {
            AccountError::new(
                AccountErrorKind::Metadata,
                "account metadata path does not have a parent directory",
            )
        })?;
        reject_link(parent)?;
        fs::create_dir_all(parent).map_err(|error| metadata_io("create directory", error))?;
        let parent_metadata = fs::symlink_metadata(parent)
            .map_err(|error| metadata_io("inspect directory", error))?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(AccountError::new(
                AccountErrorKind::Metadata,
                "account metadata directory must be a real directory, not a link",
            ));
        }
        reject_link(&self.metadata_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| metadata_io("secure directory permissions", error))?;
        }
        let bytes = serde_json::to_vec_pretty(metadata).map_err(|_| {
            AccountError::new(
                AccountErrorKind::Metadata,
                "account metadata could not be serialized",
            )
        })?;
        let temporary = temporary_path(&self.metadata_path)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| metadata_io("create temporary file", error))?;
        let result = (|| {
            file.write_all(&bytes)
                .map_err(|error| metadata_io("write", error))?;
            file.sync_all()
                .map_err(|error| metadata_io("synchronize", error))?;
            drop(file);
            replace_metadata_file(&temporary, &self.metadata_path)?;
            sync_directory(parent).map_err(|error| metadata_io("synchronize directory", error))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformCredentialStore;

#[cfg(target_os = "macos")]
impl CredentialStore for PlatformCredentialStore {
    fn save(&self, nickname: &str, credential: &StoredCredential) -> Result<(), AccountError> {
        let encoded = encode_credential(credential)?;
        security_framework::passwords::set_generic_password(KEYCHAIN_SERVICE, nickname, &encoded)
            .map_err(|_| {
                AccountError::new(
                    AccountErrorKind::Storage,
                    "macOS Keychain could not save this account",
                )
            })
    }

    fn read(&self, nickname: &str) -> Result<StoredCredential, AccountError> {
        let encoded = Zeroizing::new(
            security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, nickname)
                .map_err(|_| {
                    AccountError::new(
                        AccountErrorKind::NotFound,
                        "the selected account was not found in macOS Keychain",
                    )
                })?,
        );
        decode_credential(&encoded)
    }

    fn delete(&self, nickname: &str) -> Result<(), AccountError> {
        security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, nickname).map_err(
            |_| {
                AccountError::new(
                    AccountErrorKind::NotFound,
                    "the selected account was not found in macOS Keychain",
                )
            },
        )
    }

    fn contains(&self, nickname: &str) -> bool {
        match security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, nickname) {
            Ok(bytes) => {
                let _bytes = Zeroizing::new(bytes);
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformCredentialStore;

#[cfg(windows)]
impl CredentialStore for PlatformCredentialStore {
    fn save(&self, nickname: &str, credential: &StoredCredential) -> Result<(), AccountError> {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::FILETIME;
        use windows::Win32::Security::Credentials::{
            CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
        };

        validate_secret_fields(credential.username(), credential.password())?;
        let username_text = Zeroizing::new(
            std::str::from_utf8(credential.username())
                .map_err(|_| invalid_stored_credential())?
                .to_string(),
        );
        let mut target = target_name(nickname);
        let mut username = Zeroizing::new(to_wide_null(&username_text));
        let entry = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target.as_mut_ptr()),
            Comment: PWSTR::null(),
            LastWritten: FILETIME::default(),
            CredentialBlobSize: u32::try_from(credential.password().len()).map_err(|_| {
                AccountError::new(
                    AccountErrorKind::InvalidInput,
                    "the account password exceeds Credential Manager limits",
                )
            })?,
            CredentialBlob: credential.password().as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR(username.as_mut_ptr()),
        };
        unsafe { CredWriteW(&entry, 0) }.map_err(|_| {
            AccountError::new(
                AccountErrorKind::Storage,
                "Windows Credential Manager could not save this account",
            )
        })
    }

    fn read(&self, nickname: &str) -> Result<StoredCredential, AccountError> {
        use std::ffi::c_void;
        use windows::Win32::Security::Credentials::{
            CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
        };

        let target = target_name(nickname);
        let mut pointer: *mut CREDENTIALW = std::ptr::null_mut();
        unsafe {
            CredReadW(
                windows::core::PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                0,
                &mut pointer,
            )
        }
        .map_err(|_| {
            AccountError::new(
                AccountErrorKind::NotFound,
                "the selected account was not found in Windows Credential Manager",
            )
        })?;
        if pointer.is_null() {
            return Err(AccountError::new(
                AccountErrorKind::Storage,
                "Windows Credential Manager returned an invalid account entry",
            ));
        }
        let entry = unsafe { &*pointer };
        let username = copy_wide_secret(entry.UserName.0);
        let password = if entry.CredentialBlobSize == 0 || entry.CredentialBlob.is_null() {
            Zeroizing::new(Vec::new())
        } else {
            Zeroizing::new(
                unsafe {
                    std::slice::from_raw_parts(
                        entry.CredentialBlob,
                        entry.CredentialBlobSize as usize,
                    )
                }
                .to_vec(),
            )
        };
        unsafe { CredFree(pointer.cast::<c_void>()) };
        let username = username?;
        StoredCredential::new(username.to_vec(), password.to_vec())
    }

    fn delete(&self, nickname: &str) -> Result<(), AccountError> {
        use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

        let target = target_name(nickname);
        unsafe { CredDeleteW(windows::core::PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0) }
            .map_err(|_| {
                AccountError::new(
                    AccountErrorKind::NotFound,
                    "the selected account was not found in Windows Credential Manager",
                )
            })
    }

    fn contains(&self, nickname: &str) -> bool {
        self.read(nickname).is_ok()
    }

    fn list_nicknames(&self) -> Result<Option<Vec<String>>, AccountError> {
        use std::ffi::c_void;
        use windows::Win32::Foundation::ERROR_NOT_FOUND;
        use windows::Win32::Security::Credentials::{
            CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_FLAGS,
        };

        let filter = to_wide_null(&format!("{WINDOWS_TARGET_PREFIX}*"));
        let mut count = 0u32;
        let mut entries: *mut *mut CREDENTIALW = std::ptr::null_mut();
        let result = unsafe {
            CredEnumerateW(
                windows::core::PCWSTR(filter.as_ptr()),
                CRED_ENUMERATE_FLAGS(0),
                &mut count,
                &mut entries,
            )
        };
        if let Err(error) = result {
            if error.code() == ERROR_NOT_FOUND.to_hresult() {
                return Ok(Some(Vec::new()));
            }
            return Err(AccountError::new(
                AccountErrorKind::Storage,
                "Windows Credential Manager could not list saved accounts",
            ));
        }
        if entries.is_null() {
            return Err(AccountError::new(
                AccountErrorKind::Storage,
                "Windows Credential Manager returned an invalid account list",
            ));
        }
        let list_result = (|| {
            let mut nicknames = Vec::with_capacity(count as usize);
            let slice = unsafe { std::slice::from_raw_parts(entries, count as usize) };
            for pointer in slice {
                if pointer.is_null() {
                    continue;
                }
                let target = copy_wide_text(unsafe { (**pointer).TargetName.0 })?;
                if let Some(nickname) = target.strip_prefix(WINDOWS_TARGET_PREFIX) {
                    if validate_nickname(nickname).is_ok() {
                        nicknames.push(nickname.to_string());
                    }
                }
            }
            Ok(nicknames)
        })();
        unsafe { CredFree(entries.cast::<c_void>()) };
        Ok(Some(list_result?))
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformCredentialStore;

#[cfg(not(any(target_os = "macos", windows)))]
impl CredentialStore for PlatformCredentialStore {
    fn save(&self, _nickname: &str, _credential: &StoredCredential) -> Result<(), AccountError> {
        Err(unsupported())
    }

    fn read(&self, _nickname: &str) -> Result<StoredCredential, AccountError> {
        Err(unsupported())
    }

    fn delete(&self, _nickname: &str) -> Result<(), AccountError> {
        Err(unsupported())
    }

    fn contains(&self, _nickname: &str) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformCredentialPrompt;

#[cfg(target_os = "macos")]
impl CredentialPrompt for PlatformCredentialPrompt {
    fn prompt(&self, nickname: &str) -> Result<StoredCredential, AccountError> {
        appkit_prompt(nickname)
    }
}

#[cfg(windows)]
impl CredentialPrompt for PlatformCredentialPrompt {
    fn prompt(&self, nickname: &str) -> Result<StoredCredential, AccountError> {
        use std::ffi::c_void;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Security::Credentials::{
            CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW, CREDUIWIN_GENERIC,
            CREDUI_INFOW, CRED_PACK_GENERIC_CREDENTIALS,
        };
        use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

        const ERROR_CANCELLED: u32 = 1223;
        const MAX_FIELD_UNITS: usize = 512;
        let caption = Zeroizing::new(to_wide_null("Deimos - Save Account"));
        let message = Zeroizing::new(to_wide_null(&format!(
            "Enter Wizard101 credentials for '{nickname}'."
        )));
        let info = CREDUI_INFOW {
            cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: unsafe { GetForegroundWindow() },
            pszMessageText: PCWSTR(message.as_ptr()),
            pszCaptionText: PCWSTR(caption.as_ptr()),
            hbmBanner: Default::default(),
        };
        let mut auth_package = 0u32;
        let mut output: *mut c_void = std::ptr::null_mut();
        let mut output_size = 0u32;
        let status = unsafe {
            CredUIPromptForWindowsCredentialsW(
                Some(&info),
                0,
                &mut auth_package,
                None,
                0,
                &mut output,
                &mut output_size,
                None,
                CREDUIWIN_GENERIC,
            )
        };
        if status == ERROR_CANCELLED {
            clear_windows_prompt_buffer(output, output_size);
            return Err(AccountError::new(
                AccountErrorKind::Cancelled,
                "account entry was cancelled",
            ));
        }
        if status != 0 || output.is_null() || output_size == 0 {
            clear_windows_prompt_buffer(output, output_size);
            return Err(AccountError::new(
                AccountErrorKind::Storage,
                "Windows could not open or complete the secure account prompt",
            ));
        }

        let mut username = Zeroizing::new(vec![0u16; MAX_FIELD_UNITS]);
        let mut domain = Zeroizing::new(vec![0u16; MAX_FIELD_UNITS]);
        let mut password = Zeroizing::new(vec![0u16; MAX_FIELD_UNITS]);
        let mut username_size = MAX_FIELD_UNITS as u32;
        let mut domain_size = MAX_FIELD_UNITS as u32;
        let mut password_size = MAX_FIELD_UNITS as u32;
        let unpacked = unsafe {
            CredUnPackAuthenticationBufferW(
                CRED_PACK_GENERIC_CREDENTIALS,
                output,
                output_size,
                PWSTR(username.as_mut_ptr()),
                &mut username_size,
                PWSTR(domain.as_mut_ptr()),
                Some(&mut domain_size),
                PWSTR(password.as_mut_ptr()),
                &mut password_size,
            )
        };
        let result = match unpacked {
            Ok(()) => {
                let username_end = username_size.saturating_sub(1) as usize;
                let password_end = password_size.saturating_sub(1) as usize;
                match (
                    String::from_utf16(&username[..username_end]),
                    String::from_utf16(&password[..password_end]),
                ) {
                    (Ok(username_text), Ok(password_text)) => {
                        let username_text = Zeroizing::new(username_text);
                        let password_text = Zeroizing::new(password_text);
                        StoredCredential::new(
                            username_text.as_bytes().to_vec(),
                            password_text.as_bytes().to_vec(),
                        )
                    }
                    _ => Err(AccountError::new(
                        AccountErrorKind::Storage,
                        "Windows returned invalid account text",
                    )),
                }
            }
            Err(_) => Err(AccountError::new(
                AccountErrorKind::Storage,
                "Windows returned an invalid secure account response",
            )),
        };
        clear_windows_prompt_buffer(output, output_size);
        result
    }
}

#[cfg(target_os = "macos")]
fn appkit_prompt(nickname: &str) -> Result<StoredCredential, AccountError> {
    use std::ffi::CStr;

    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Point {
        x: f64,
        y: f64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Size {
        width: f64,
        height: f64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Rect {
        origin: Point,
        size: Size,
    }

    unsafe fn nsstring(value: &str) -> *mut Object {
        const UTF8_ENCODING: usize = 4;
        let string: *mut Object = msg_send![class!(NSString), alloc];
        msg_send![string,
            initWithBytes: value.as_ptr()
            length: value.len()
            encoding: UTF8_ENCODING
        ]
    }

    unsafe fn field_bytes(
        field: *mut Object,
        maximum_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, AccountError> {
        const UTF8_ENCODING: usize = 4;
        let value: *mut Object = msg_send![field, stringValue];
        let length: usize = msg_send![value, lengthOfBytesUsingEncoding: UTF8_ENCODING];
        if length > maximum_bytes {
            return Err(AccountError::new(
                AccountErrorKind::InvalidInput,
                "the account username or password exceeds the supported length",
            ));
        }
        let pointer: *const std::ffi::c_char = msg_send![value, UTF8String];
        if pointer.is_null() {
            return Err(AccountError::new(
                AccountErrorKind::Storage,
                "macOS returned an invalid account field",
            ));
        }
        Ok(Zeroizing::new(CStr::from_ptr(pointer).to_bytes().to_vec()))
    }

    let is_main: bool = unsafe { msg_send![class!(NSThread), isMainThread] };
    if !is_main {
        return Err(AccountError::new(
            AccountErrorKind::Storage,
            "the account prompt must be opened from the main application thread",
        ));
    }
    ensure_appkit_loaded()?;

    unsafe {
        let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];
        let alert: *mut Object = msg_send![class!(NSAlert), new];
        let message = nsstring("Deimos - Save Account");
        let detail = nsstring(&format!(
            "Store Wizard101 credentials for '{nickname}' in macOS Keychain."
        ));
        let save = nsstring("Save");
        let cancel = nsstring("Cancel");
        let username_placeholder = nsstring("Wizard101 username");
        let password_placeholder = nsstring("Wizard101 password");
        let _: () = msg_send![alert, setMessageText: message];
        let _: () = msg_send![alert, setInformativeText: detail];
        let _: *mut Object = msg_send![alert, addButtonWithTitle: save];
        let _: *mut Object = msg_send![alert, addButtonWithTitle: cancel];

        let view: *mut Object = msg_send![class!(NSView), alloc];
        let view: *mut Object = msg_send![view, initWithFrame: Rect {
            origin: Point { x: 0.0, y: 0.0 },
            size: Size { width: 360.0, height: 64.0 },
        }];
        let username: *mut Object = msg_send![class!(NSTextField), alloc];
        let username: *mut Object = msg_send![username, initWithFrame: Rect {
            origin: Point { x: 0.0, y: 36.0 },
            size: Size { width: 360.0, height: 24.0 },
        }];
        let password: *mut Object = msg_send![class!(NSSecureTextField), alloc];
        let password: *mut Object = msg_send![password, initWithFrame: Rect {
            origin: Point { x: 0.0, y: 4.0 },
            size: Size { width: 360.0, height: 24.0 },
        }];
        let _: () = msg_send![username, setPlaceholderString: username_placeholder];
        let _: () = msg_send![password, setPlaceholderString: password_placeholder];
        let _: () = msg_send![view, addSubview: username];
        let _: () = msg_send![view, addSubview: password];
        let _: () = msg_send![alert, setAccessoryView: view];

        let application: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        let _: () = msg_send![application, activateIgnoringOtherApps: true];
        let response: isize = msg_send![alert, runModal];
        const FIRST_BUTTON: isize = 1000;
        let result = if response == FIRST_BUTTON {
            match (
                field_bytes(username, MAX_USERNAME_BYTES),
                field_bytes(password, MAX_PASSWORD_BYTES),
            ) {
                (Ok(username_bytes), Ok(password_bytes)) => {
                    StoredCredential::new(username_bytes.to_vec(), password_bytes.to_vec())
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        } else {
            Err(AccountError::new(
                AccountErrorKind::Cancelled,
                "account entry was cancelled",
            ))
        };

        let empty = nsstring("");
        let _: () = msg_send![username, setStringValue: empty];
        let _: () = msg_send![password, setStringValue: empty];
        let _: () = msg_send![username, release];
        let _: () = msg_send![password, release];
        let _: () = msg_send![view, release];
        let _: () = msg_send![alert, release];
        let _: () = msg_send![message, release];
        let _: () = msg_send![detail, release];
        let _: () = msg_send![save, release];
        let _: () = msg_send![cancel, release];
        let _: () = msg_send![username_placeholder, release];
        let _: () = msg_send![password_placeholder, release];
        let _: () = msg_send![empty, release];
        let _: () = msg_send![pool, drain];
        result
    }
}

#[cfg(target_os = "macos")]
fn ensure_appkit_loaded() -> Result<(), AccountError> {
    unsafe {
        let _ = ns_application_load();
    }
    if let Some(class_name) = APPKIT_PROMPT_CLASSES
        .iter()
        .find(|class_name| objc::runtime::Class::get(class_name).is_none())
    {
        return Err(AccountError::new(
            AccountErrorKind::Storage,
            format!("macOS could not initialize the secure account dialog ({class_name})"),
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", windows)))]
impl CredentialPrompt for PlatformCredentialPrompt {
    fn prompt(&self, _nickname: &str) -> Result<StoredCredential, AccountError> {
        Err(unsupported())
    }
}

pub type PlatformAccountService = AccountService<PlatformCredentialStore, PlatformCredentialPrompt>;

pub fn platform_service() -> Result<PlatformAccountService, AccountError> {
    Ok(AccountService::new(
        PlatformCredentialStore,
        PlatformCredentialPrompt,
        metadata_path()?,
    ))
}

#[cfg(target_os = "macos")]
fn metadata_path() -> Result<PathBuf, AccountError> {
    let root = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| {
        AccountError::new(
            AccountErrorKind::Metadata,
            "the macOS home directory is unavailable",
        )
    })?)
    .join("Library/Application Support");
    Ok(root.join("Deimos/account_metadata.json"))
}

#[cfg(windows)]
fn metadata_path() -> Result<PathBuf, AccountError> {
    let root = PathBuf::from(std::env::var_os("APPDATA").ok_or_else(|| {
        AccountError::new(
            AccountErrorKind::Metadata,
            "the Windows application-data directory is unavailable",
        )
    })?);
    Ok(root.join("Deimos/account_metadata.json"))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn metadata_path() -> Result<PathBuf, AccountError> {
    Err(unsupported())
}

fn lock_metadata() -> Result<MutexGuard<'static, ()>, AccountError> {
    METADATA_LOCK.lock().map_err(|_| {
        AccountError::new(
            AccountErrorKind::Metadata,
            "account metadata is temporarily unavailable",
        )
    })
}

fn validate_metadata(metadata: &AccountMetadata) -> Result<(), AccountError> {
    if metadata.version != METADATA_VERSION {
        return Err(AccountError::new(
            AccountErrorKind::Metadata,
            "account metadata uses an unsupported version",
        ));
    }
    if metadata.nicknames_order.len() > MAX_ACCOUNTS || metadata.gid_map.len() > MAX_ACCOUNTS {
        return Err(AccountError::new(
            AccountErrorKind::Metadata,
            "account metadata contains too many accounts",
        ));
    }
    let mut seen = HashSet::new();
    if metadata
        .nicknames_order
        .iter()
        .any(|nickname| validate_nickname(nickname).is_err() || !seen.insert(nickname))
        || metadata
            .gid_map
            .keys()
            .any(|nickname| validate_nickname(nickname).is_err())
    {
        return Err(AccountError::new(
            AccountErrorKind::Metadata,
            "account metadata contains an invalid or duplicate nickname",
        ));
    }
    Ok(())
}

fn reject_link(path: &Path) -> Result<(), AccountError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AccountError::new(
            AccountErrorKind::Metadata,
            "account metadata paths cannot use symbolic links",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(metadata_io("inspect path", error)),
    }
}

fn validate_nickname(nickname: &str) -> Result<(), AccountError> {
    if nickname.trim().is_empty()
        || nickname.len() > MAX_NICKNAME_BYTES
        || nickname.chars().any(char::is_control)
    {
        return Err(AccountError::new(
            AccountErrorKind::InvalidInput,
            format!("account nickname must contain 1..={MAX_NICKNAME_BYTES} visible bytes"),
        ));
    }
    Ok(())
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn validate_secret_fields(username: &[u8], password: &[u8]) -> Result<(), AccountError> {
    let valid_text = std::str::from_utf8(username)
        .ok()
        .zip(std::str::from_utf8(password).ok())
        .is_some_and(|(username, password)| {
            !username.chars().any(char::is_control) && !password.chars().any(char::is_control)
        });
    if username.is_empty()
        || username.len() > MAX_USERNAME_BYTES
        || password.is_empty()
        || password.len() > MAX_PASSWORD_BYTES
        || username.contains(&0)
        || password.contains(&0)
        || !valid_text
    {
        return Err(AccountError::new(
            AccountErrorKind::InvalidInput,
            "the account username or password does not meet the supported length requirements",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn encode_credential(credential: &StoredCredential) -> Result<Zeroizing<Vec<u8>>, AccountError> {
    validate_secret_fields(credential.username(), credential.password())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        4 + credential.username().len() + credential.password().len(),
    ));
    bytes.extend_from_slice(&(credential.username().len() as u16).to_le_bytes());
    bytes.extend_from_slice(credential.username());
    bytes.extend_from_slice(&(credential.password().len() as u16).to_le_bytes());
    bytes.extend_from_slice(credential.password());
    Ok(bytes)
}

#[cfg(target_os = "macos")]
fn decode_credential(bytes: &[u8]) -> Result<StoredCredential, AccountError> {
    if bytes.len() < 4 {
        return Err(invalid_stored_credential());
    }
    let username_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    let username_end = 2usize
        .checked_add(username_len)
        .filter(|end| end.checked_add(2).is_some_and(|next| next <= bytes.len()))
        .ok_or_else(invalid_stored_credential)?;
    let password_len = usize::from(u16::from_le_bytes([
        bytes[username_end],
        bytes[username_end + 1],
    ]));
    let password_start = username_end + 2;
    let password_end = password_start
        .checked_add(password_len)
        .filter(|end| *end == bytes.len())
        .ok_or_else(invalid_stored_credential)?;
    StoredCredential::new(
        bytes[2..username_end].to_vec(),
        bytes[password_start..password_end].to_vec(),
    )
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn invalid_stored_credential() -> AccountError {
    AccountError::new(
        AccountErrorKind::Storage,
        "the stored account entry is invalid; delete and add the account again",
    )
}

#[cfg(not(any(target_os = "macos", windows)))]
fn unsupported() -> AccountError {
    AccountError::new(
        AccountErrorKind::Unsupported,
        "secure account storage is not available on this host platform",
    )
}

fn metadata_io(action: &str, error: io::Error) -> AccountError {
    AccountError::new(
        AccountErrorKind::Metadata,
        format!("account metadata could not {action}: {error}"),
    )
}

fn temporary_path(path: &Path) -> Result<PathBuf, AccountError> {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random).map_err(|_| {
        AccountError::new(
            AccountErrorKind::Metadata,
            "account metadata could not create a secure temporary name",
        )
    })?;
    Ok(path.with_extension(format!("tmp-{}", u64::from_le_bytes(random))))
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn replace_metadata_file(source: &Path, destination: &Path) -> Result<(), AccountError> {
    fs::rename(source, destination).map_err(|error| metadata_io("replace", error))
}

#[cfg(windows)]
fn replace_metadata_file(source: &Path, destination: &Path) -> Result<(), AccountError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    unsafe {
        MoveFileExW(
            windows::core::PCWSTR(source.as_ptr()),
            windows::core::PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| {
        AccountError::new(
            AccountErrorKind::Metadata,
            format!("account metadata could not replace: {error}"),
        )
    })
}

#[cfg(windows)]
fn target_name(nickname: &str) -> Vec<u16> {
    to_wide_null(&format!("{WINDOWS_TARGET_PREFIX}{nickname}"))
}

#[cfg(windows)]
fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn copy_wide_text(pointer: *const u16) -> Result<String, AccountError> {
    if pointer.is_null() {
        return Err(invalid_stored_credential());
    }
    const MAX_TARGET_UNITS: usize = 512;
    for length in 0..MAX_TARGET_UNITS {
        if unsafe { *pointer.add(length) } == 0 {
            return String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
                .map_err(|_| invalid_stored_credential());
        }
    }
    Err(invalid_stored_credential())
}

#[cfg(windows)]
fn copy_wide_secret(pointer: *const u16) -> Result<Zeroizing<Vec<u8>>, AccountError> {
    if pointer.is_null() {
        return Err(invalid_stored_credential());
    }
    for length in 0..=MAX_USERNAME_BYTES {
        if unsafe { *pointer.add(length) } == 0 {
            let units =
                Zeroizing::new(unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec());
            let text = Zeroizing::new(
                String::from_utf16(&units).map_err(|_| invalid_stored_credential())?,
            );
            return Ok(Zeroizing::new(text.as_bytes().to_vec()));
        }
    }
    Err(invalid_stored_credential())
}

#[cfg(windows)]
fn clear_windows_prompt_buffer(pointer: *mut std::ffi::c_void, size: u32) {
    if pointer.is_null() {
        return;
    }
    unsafe {
        std::ptr::write_bytes(pointer.cast::<u8>(), 0, size as usize);
        windows::Win32::System::Com::CoTaskMemFree(Some(pointer));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountError, AccountErrorKind, AccountService, CredentialPrompt, CredentialStore,
        StoredCredential,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    type MemoryCredentials = HashMap<String, (Vec<u8>, Vec<u8>)>;

    #[derive(Default)]
    struct MemoryStore(Mutex<MemoryCredentials>);

    impl CredentialStore for MemoryStore {
        fn save(&self, nickname: &str, credential: &StoredCredential) -> Result<(), AccountError> {
            self.0.lock().unwrap().insert(
                nickname.to_string(),
                (
                    credential.username().to_vec(),
                    credential.password().to_vec(),
                ),
            );
            Ok(())
        }

        fn read(&self, nickname: &str) -> Result<StoredCredential, AccountError> {
            let values = self
                .0
                .lock()
                .unwrap()
                .get(nickname)
                .cloned()
                .ok_or_else(|| {
                    AccountError::new(AccountErrorKind::NotFound, "account not found")
                })?;
            StoredCredential::new(values.0, values.1)
        }

        fn delete(&self, nickname: &str) -> Result<(), AccountError> {
            self.0.lock().unwrap().remove(nickname);
            Ok(())
        }

        fn contains(&self, nickname: &str) -> bool {
            self.0.lock().unwrap().contains_key(nickname)
        }
    }

    struct FixedPrompt;

    impl CredentialPrompt for FixedPrompt {
        fn prompt(&self, _nickname: &str) -> Result<StoredCredential, AccountError> {
            StoredCredential::new(b"wizard@example.com".to_vec(), b"secret-value".to_vec())
        }
    }

    struct CancelledPrompt;

    impl CredentialPrompt for CancelledPrompt {
        fn prompt(&self, _nickname: &str) -> Result<StoredCredential, AccountError> {
            Err(AccountError::new(
                AccountErrorKind::Cancelled,
                "account entry was cancelled",
            ))
        }
    }

    #[test]
    fn ordering_deletion_and_gid_metadata_remain_compatible() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).expect("random test directory");
        let directory = std::env::temp_dir().join(format!(
            "deimos-account-test-{}",
            u64::from_le_bytes(random)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let service = AccountService::new(
            MemoryStore::default(),
            FixedPrompt,
            directory.join("account_metadata.json"),
        );
        service.prompt_save("second").expect("save second");
        service.prompt_save("first").expect("save first");
        service
            .reorder(&["first".to_string(), "second".to_string()])
            .expect("reorder");
        service.update_gid("first", 42).expect("gid");
        assert_eq!(service.list().expect("list"), vec!["first", "second"]);
        assert_eq!(service.gid("first").expect("gid"), Some(42));
        assert_eq!(
            service.nickname_for_gid(42).expect("reverse"),
            Some("first".to_string())
        );
        service.delete("first").expect("delete");
        assert_eq!(service.list().expect("list"), vec!["second"]);
        assert_eq!(service.gid("first").expect("gid"), None);
        let metadata =
            std::fs::read_to_string(directory.join("account_metadata.json")).expect("metadata");
        assert!(!metadata.contains("wizard@example.com"));
        assert!(!metadata.contains("secret-value"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(directory.join("account_metadata.json"))
                .expect("metadata permissions")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn cancellation_does_not_create_a_credential_or_metadata_entry() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).expect("random test directory");
        let directory = std::env::temp_dir().join(format!(
            "deimos-account-cancel-test-{}",
            u64::from_le_bytes(random)
        ));
        let service = AccountService::new(
            MemoryStore::default(),
            CancelledPrompt,
            directory.join("account_metadata.json"),
        );
        let error = service.prompt_save("cancelled").unwrap_err();
        assert_eq!(error.kind, AccountErrorKind::Cancelled);
        assert!(!service.store.contains("cancelled"));
        assert!(!directory.exists());
    }

    #[test]
    fn stored_credentials_are_redacted_and_bounded() {
        let credential =
            StoredCredential::new(b"user".to_vec(), b"secret-value".to_vec()).expect("credential");
        assert_eq!(format!("{credential:?}"), "StoredCredential([REDACTED])");
        let error = StoredCredential::new(Vec::new(), b"secret-value".to_vec()).unwrap_err();
        assert!(!error.to_string().contains("secret-value"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn appkit_prompt_classes_are_linked_into_the_native_library() {
        for class_name in super::APPKIT_PROMPT_CLASSES {
            assert!(
                objc::runtime::Class::get(class_name).is_some(),
                "{class_name} should be available"
            );
        }
    }
}
