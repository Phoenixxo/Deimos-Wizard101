use std::fmt;

pub mod client;
pub mod game;
pub mod lifecycle;
pub mod memory;
pub mod process;
pub mod rpc;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_SCHEMA_VERSION: u32 = 1;
pub const BUILD_ID: &str = env!("DEIMOS_BUILD_ID_EMBEDDED");
pub const DEFAULT_TARGET_PROCESS: &str = "WizardGraphicalClient.exe";
pub const PROCESS_READ_ACCESS: &str = "PROCESS_QUERY_INFORMATION | PROCESS_VM_READ";
pub const WINDOWS_AGENT_TARGET: &str = "x86_64-pc-windows-msvc";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProbeRequest {
    pub schema_version: u32,
    pub target_process: String,
    pub target_module: String,
}

impl ProbeRequest {
    pub fn new(target_process: impl Into<String>) -> Self {
        let target_process = target_process.into();
        Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            target_module: target_process.clone(),
            target_process,
        }
    }
}

impl Default for ProbeRequest {
    fn default() -> Self {
        Self::new(DEFAULT_TARGET_PROCESS)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProbeReport {
    pub schema_version: u32,
    pub target_process: String,
    pub access_mode: String,
    pub success: bool,
    pub candidates: Vec<ProcessReport>,
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_target: Option<String>,
}

impl ProbeReport {
    pub fn new(request: &ProbeRequest) -> Self {
        Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            target_process: request.target_process.clone(),
            access_mode: PROCESS_READ_ACCESS.to_string(),
            success: false,
            candidates: Vec::new(),
            errors: Vec::new(),
            build_target: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProcessReport {
    pub pid: u32,
    pub process_name: String,
    pub process_opened: bool,
    pub module: Option<ModuleReport>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ModuleReport {
    pub module_name: String,
    pub executable_path: String,
    pub module_base: String,
    pub module_size: u32,
    pub bytes_read: usize,
    pub pe: PeHeaderSummary,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PeHeaderSummary {
    pub dos_signature: String,
    pub pe_signature: String,
    pub machine: String,
    pub machine_code: String,
    pub number_of_sections: u16,
    pub optional_header_magic: String,
    pub preferred_image_base: String,
    pub entry_point_rva: String,
    pub size_of_image: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeimosError {
    ProcessEnumeration(String),
    ProcessAccess(String),
    ModuleEnumeration(String),
    MemoryRead(String),
    PeParse(String),
    Serialization(String),
}

impl DeimosError {
    pub fn process_enumeration(message: impl Into<String>) -> Self {
        Self::ProcessEnumeration(message.into())
    }

    pub fn process_access(message: impl Into<String>) -> Self {
        Self::ProcessAccess(message.into())
    }

    pub fn module_enumeration(message: impl Into<String>) -> Self {
        Self::ModuleEnumeration(message.into())
    }

    pub fn memory_read(message: impl Into<String>) -> Self {
        Self::MemoryRead(message.into())
    }

    pub fn pe_parse(message: impl Into<String>) -> Self {
        Self::PeParse(message.into())
    }

    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization(message.into())
    }
}

impl fmt::Display for DeimosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ProcessEnumeration(message)
            | Self::ProcessAccess(message)
            | Self::ModuleEnumeration(message)
            | Self::MemoryRead(message)
            | Self::PeParse(message)
            | Self::Serialization(message) => message,
        };
        f.write_str(message)
    }
}

impl std::error::Error for DeimosError {}

pub fn parse_pe_headers(bytes: &[u8]) -> Result<PeHeaderSummary, DeimosError> {
    if bytes.len() < 0x40 {
        return Err(DeimosError::pe_parse(format!(
            "buffer is too small for a DOS header: {} bytes",
            bytes.len()
        )));
    }

    if &bytes[0..2] != b"MZ" {
        return Err(DeimosError::pe_parse("DOS signature is not MZ"));
    }

    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    let coff_offset = pe_offset
        .checked_add(4)
        .ok_or_else(|| DeimosError::pe_parse("PE header offset overflowed"))?;
    let optional_offset = coff_offset
        .checked_add(20)
        .ok_or_else(|| DeimosError::pe_parse("optional header offset overflowed"))?;

    let pe_signature = slice(bytes, pe_offset, 4)?;
    if pe_signature != b"PE\0\0" {
        return Err(DeimosError::pe_parse(format!(
            "PE signature is invalid at offset {pe_offset:#x}"
        )));
    }

    let machine_code = read_u16(bytes, coff_offset)?;
    let number_of_sections = read_u16(bytes, coff_offset + 2)?;
    let optional_header_size = read_u16(bytes, coff_offset + 16)? as usize;
    if optional_header_size < 60 {
        return Err(DeimosError::pe_parse(format!(
            "optional header is unexpectedly small: {optional_header_size} bytes"
        )));
    }
    slice(bytes, optional_offset, optional_header_size)?;

    let optional_magic = read_u16(bytes, optional_offset)?;
    let entry_point_rva = read_u32(bytes, optional_offset + 16)?;
    let (optional_header_magic, preferred_image_base) = match optional_magic {
        0x10b => (
            "PE32".to_string(),
            u64::from(read_u32(bytes, optional_offset + 28)?),
        ),
        0x20b => ("PE32+".to_string(), read_u64(bytes, optional_offset + 24)?),
        other => {
            return Err(DeimosError::pe_parse(format!(
                "unsupported optional header magic: {other:#06x}"
            )))
        }
    };
    let size_of_image = read_u32(bytes, optional_offset + 56)?;

    Ok(PeHeaderSummary {
        dos_signature: "MZ".to_string(),
        pe_signature: "PE\\0\\0".to_string(),
        machine: machine_name(machine_code).to_string(),
        machine_code: format!("{machine_code:#06x}"),
        number_of_sections,
        optional_header_magic,
        preferred_image_base: format!("{preferred_image_base:#x}"),
        entry_point_rva: format!("{entry_point_rva:#x}"),
        size_of_image,
    })
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x8664 => "x86_64",
        0xaa64 => "arm64",
        0xa641 => "arm64ec",
        _ => "unknown",
    }
}

fn slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], DeimosError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| DeimosError::pe_parse("header range overflowed"))?;
    bytes.get(offset..end).ok_or_else(|| {
        DeimosError::pe_parse(format!(
            "header range {offset:#x}..{end:#x} exceeds the read buffer"
        ))
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, DeimosError> {
    let raw: [u8; 2] = slice(bytes, offset, 2)?
        .try_into()
        .map_err(|_| DeimosError::pe_parse("failed to read u16"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, DeimosError> {
    let raw: [u8; 4] = slice(bytes, offset, 4)?
        .try_into()
        .map_err(|_| DeimosError::pe_parse("failed to read u32"))?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, DeimosError> {
    let raw: [u8; 8] = slice(bytes, offset, 8)?
        .try_into()
        .map_err(|_| DeimosError::pe_parse("failed to read u64"))?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::{parse_pe_headers, DeimosError};

    fn minimal_pe64() -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&(0x8664u16).to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&(7u16).to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&(0xf0u16).to_le_bytes());

        let optional = coff + 20;
        bytes[optional..optional + 2].copy_from_slice(&(0x20bu16).to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&(0x1234u32).to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&(0x140000000u64).to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&(0x450000u32).to_le_bytes());
        bytes
    }

    #[test]
    fn parses_a_pe32_plus_header() {
        let summary = parse_pe_headers(&minimal_pe64()).expect("header should parse");

        assert_eq!(summary.machine, "x86_64");
        assert_eq!(summary.optional_header_magic, "PE32+");
        assert_eq!(summary.preferred_image_base, "0x140000000");
        assert_eq!(summary.entry_point_rva, "0x1234");
        assert_eq!(summary.size_of_image, 0x450000);
    }

    #[test]
    fn rejects_a_non_pe_buffer() {
        let error = parse_pe_headers(&vec![0u8; 512]).expect_err("header should fail");

        assert_eq!(
            error,
            DeimosError::PeParse("DOS signature is not MZ".to_string())
        );
    }

    #[test]
    fn rejects_a_truncated_buffer() {
        let error = parse_pe_headers(b"MZ").expect_err("header should fail");

        assert!(error.to_string().contains("too small"));
    }
}
