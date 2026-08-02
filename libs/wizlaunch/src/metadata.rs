use crate::errors::VaultError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_ACCOUNTS: usize = 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountMetadata {
    pub version: u32,
    pub nicknames_order: Vec<String>,
    pub gid_map: HashMap<String, u64>,
}

impl Default for AccountMetadata {
    fn default() -> Self {
        Self {
            version: 1,
            nicknames_order: Vec::new(),
            gid_map: HashMap::new(),
        }
    }
}

fn metadata_path() -> Result<PathBuf, VaultError> {
    let appdata = std::env::var("APPDATA")
        .map_err(|_| VaultError::MetadataIo("APPDATA not set".to_string()))?;
    let dir = PathBuf::from(appdata).join("Deimos");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("account_metadata.json"))
}

pub fn load() -> Result<AccountMetadata, VaultError> {
    let path = metadata_path()?;
    if !path.exists() {
        return Ok(AccountMetadata::default());
    }
    let data = fs::read(&path)?;
    if data.len() > MAX_METADATA_BYTES {
        return Err(VaultError::MetadataIo(
            "account metadata exceeds the one-megabyte safety limit".to_string(),
        ));
    }
    let meta: AccountMetadata = serde_json::from_slice(&data)?;
    Ok(meta)
}

pub fn save(meta: &AccountMetadata) -> Result<(), VaultError> {
    if meta.nicknames_order.len() > MAX_ACCOUNTS {
        return Err(VaultError::MetadataIo(
            "account metadata contains too many accounts".to_string(),
        ));
    }
    let path = metadata_path()?;
    let data = serde_json::to_string_pretty(meta)?;
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random).map_err(|error| {
        VaultError::MetadataIo(format!("could not create temporary metadata name: {error}"))
    })?;
    let temporary = path.with_extension(format!("tmp-{}", u64::from_le_bytes(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(data.as_bytes())?;
        file.sync_all()?;
        drop(file);
        let source = to_wide_null(&temporary.to_string_lossy());
        let destination = to_wide_null(&path.to_string_lossy());
        unsafe {
            MoveFileExW(
                PCWSTR(source.as_ptr()),
                PCWSTR(destination.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|error| VaultError::MetadataIo(format!("could not replace metadata: {error}")))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Ensure a nickname is in the order list (appended if missing).
pub fn ensure_nickname(nickname: &str) -> Result<(), VaultError> {
    let mut meta = load()?;
    if !meta.nicknames_order.contains(&nickname.to_string()) {
        meta.nicknames_order.push(nickname.to_string());
        save(&meta)?;
    }
    Ok(())
}

/// Remove a nickname from the order list and GID map.
pub fn remove_nickname(nickname: &str) -> Result<(), VaultError> {
    let mut meta = load()?;
    meta.nicknames_order.retain(|n| n != nickname);
    meta.gid_map.remove(nickname);
    save(&meta)?;
    Ok(())
}

/// Reorder nicknames. Only keeps nicknames that exist in the provided list.
pub fn reorder(ordered: &[String]) -> Result<(), VaultError> {
    let mut meta = load()?;
    meta.nicknames_order = ordered.to_vec();
    save(&meta)?;
    Ok(())
}

/// Get nicknames in stored order, falling back to credential store order.
pub fn get_ordered_nicknames(cred_nicknames: &[String]) -> Result<Vec<String>, VaultError> {
    let meta = load()?;
    if meta.nicknames_order.is_empty() {
        return Ok(cred_nicknames.to_vec());
    }
    // Return ordered nicknames that exist in credential store, then any new ones
    let mut result = Vec::new();
    for nick in &meta.nicknames_order {
        if cred_nicknames.contains(nick) {
            result.push(nick.clone());
        }
    }
    for nick in cred_nicknames {
        if !result.contains(nick) {
            result.push(nick.clone());
        }
    }
    Ok(result)
}

pub fn update_gid(nickname: &str, gid: u64) -> Result<(), VaultError> {
    let mut meta = load()?;
    meta.gid_map.insert(nickname.to_string(), gid);
    save(&meta)?;
    Ok(())
}

pub fn get_gid(nickname: &str) -> Result<Option<u64>, VaultError> {
    let meta = load()?;
    Ok(meta.gid_map.get(nickname).copied())
}

pub fn get_nickname_by_gid(gid: u64) -> Result<Option<String>, VaultError> {
    let meta = load()?;
    for (nick, &stored_gid) in &meta.gid_map {
        if stored_gid == gid {
            return Ok(Some(nick.clone()));
        }
    }
    Ok(None)
}
