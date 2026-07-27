use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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

pub fn parse_pe_headers(bytes: &[u8]) -> Result<PeHeaderSummary, String> {
    if bytes.len() < 0x40 {
        return Err(format!(
            "buffer is too small for a DOS header: {} bytes",
            bytes.len()
        ));
    }

    if &bytes[0..2] != b"MZ" {
        return Err("DOS signature is not MZ".to_string());
    }

    let pe_offset = read_u32(bytes, 0x3c)? as usize;
    let coff_offset = pe_offset
        .checked_add(4)
        .ok_or_else(|| "PE header offset overflowed".to_string())?;
    let optional_offset = coff_offset
        .checked_add(20)
        .ok_or_else(|| "optional header offset overflowed".to_string())?;

    let pe_signature = slice(bytes, pe_offset, 4)?;
    if pe_signature != b"PE\0\0" {
        return Err(format!("PE signature is invalid at offset {pe_offset:#x}"));
    }

    let machine_code = read_u16(bytes, coff_offset)?;
    let number_of_sections = read_u16(bytes, coff_offset + 2)?;
    let optional_header_size = read_u16(bytes, coff_offset + 16)? as usize;
    if optional_header_size < 60 {
        return Err(format!(
            "optional header is unexpectedly small: {optional_header_size} bytes"
        ));
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
        other => return Err(format!("unsupported optional header magic: {other:#06x}")),
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

fn slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "header range overflowed".to_string())?;
    bytes
        .get(offset..end)
        .ok_or_else(|| format!("header range {offset:#x}..{end:#x} exceeds the read buffer"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let raw: [u8; 2] = slice(bytes, offset, 2)?
        .try_into()
        .map_err(|_| "failed to read u16".to_string())?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let raw: [u8; 4] = slice(bytes, offset, 4)?
        .try_into()
        .map_err(|_| "failed to read u32".to_string())?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let raw: [u8; 8] = slice(bytes, offset, 8)?
        .try_into()
        .map_err(|_| "failed to read u64".to_string())?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::parse_pe_headers;

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

        assert_eq!(error, "DOS signature is not MZ");
    }

    #[test]
    fn rejects_a_truncated_buffer() {
        let error = parse_pe_headers(b"MZ").expect_err("header should fail");

        assert!(error.contains("too small"));
    }
}
