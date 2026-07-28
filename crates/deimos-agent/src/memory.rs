use std::collections::BTreeMap;

use deimos_core::memory::{
    ByteOrder, MemoryBatchReadRequest, MemoryBatchReadResponse, MemoryItemError,
    MemoryItemErrorCode, MemoryPointerChainRequest, MemoryPointerChainResponse,
    MemoryReadItemResult, MemoryReadRequest, MemoryReadResponse, MemoryRegionsResponse,
    MemoryScanRegionError, MemoryScanRequest, MemoryScanResponse, MemoryScanScope,
    MemorySessionRequest, MemoryValueType, TypedMemoryReadRequest, TypedMemoryReadResponse,
    TypedMemoryValue, MAX_BATCH_BYTES, MAX_BATCH_ITEMS, MAX_MEMORY_READ_BYTES, MAX_POINTER_OFFSETS,
    MAX_SCAN_ERRORS, MAX_SCAN_MATCHES, MAX_SIGNATURE_BYTES,
};
use deimos_core::process::{ProcessDescriptor, ProcessIdentity};
use deimos_core::rpc::{RpcError, RpcErrorCode};

use crate::process::{MemoryBackend, ProcessApiError, ProcessBackendError, ProcessSessionRegistry};

const SCAN_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub enum MemoryApiError {
    Process(ProcessApiError),
    Request {
        code: RpcErrorCode,
        message: String,
        details: BTreeMap<String, String>,
    },
}

impl From<ProcessApiError> for MemoryApiError {
    fn from(error: ProcessApiError) -> Self {
        Self::Process(error)
    }
}

impl From<ProcessBackendError> for MemoryApiError {
    fn from(error: ProcessBackendError) -> Self {
        Self::Request {
            code: RpcErrorCode::MemoryReadFailed,
            message: error.message,
            details: error
                .native_code
                .map(|code| BTreeMap::from([("native_code".to_string(), code.to_string())]))
                .unwrap_or_default(),
        }
    }
}

impl MemoryApiError {
    fn request(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self::Request {
            code,
            message: message.into(),
            details: BTreeMap::new(),
        }
    }

    fn with_detail(mut self, name: &str, value: impl Into<String>) -> Self {
        if let Self::Request { details, .. } = &mut self {
            details.insert(name.to_string(), value.into());
        }
        self
    }

    pub fn into_rpc_error(self, request_id: u64, operation: &str) -> RpcError {
        match self {
            Self::Process(error) => error.into_rpc_error(request_id, operation),
            Self::Request {
                code,
                message,
                details,
            } => {
                let mut error = RpcError::new(code, message, request_id, operation, None);
                error.details = details;
                error
            }
        }
    }
}

pub fn regions<B: MemoryBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    request: &MemorySessionRequest,
) -> Result<MemoryRegionsResponse, MemoryApiError> {
    sessions.with_live_session(backend, &request.session_id, |backend, handle, process| {
        let identity = process_identity(process)?;
        let mut regions = backend
            .enumerate_memory_regions(handle, identity)
            .map_err(MemoryApiError::from)?;
        regions.sort_by_key(|region| parse_address(&region.base_address).unwrap_or(usize::MAX));
        if regions.len() > deimos_core::memory::MAX_SCAN_REGIONS {
            return Err(MemoryApiError::request(
                RpcErrorCode::MemoryLimitExceeded,
                "readable region result exceeds the protocol limit",
            ));
        }
        Ok(MemoryRegionsResponse {
            session_id: request.session_id.clone(),
            regions,
        })
    })
}

pub fn read<B: MemoryBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    request: &MemoryReadRequest,
) -> Result<MemoryReadResponse, MemoryApiError> {
    let address = validate_range(&request.address, request.size)?;
    let bytes =
        sessions.with_live_session(backend, &request.session_id, |backend, handle, _| {
            backend
                .read_memory(handle, address, request.size)
                .map_err(MemoryApiError::from)
        })?;
    Ok(MemoryReadResponse {
        session_id: request.session_id.clone(),
        address: format_address(address),
        bytes,
    })
}

pub fn read_batch<B: MemoryBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    request: &MemoryBatchReadRequest,
) -> Result<MemoryBatchReadResponse, MemoryApiError> {
    if request.reads.is_empty() || request.reads.len() > MAX_BATCH_ITEMS {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("batch must contain between 1 and {MAX_BATCH_ITEMS} reads"),
        ));
    }
    let total = request.reads.iter().try_fold(0usize, |total, item| {
        if item.size == 0 || item.size > MAX_MEMORY_READ_BYTES {
            return Err(MemoryApiError::request(
                RpcErrorCode::MemoryLimitExceeded,
                format!("batch item size must be between 1 and {MAX_MEMORY_READ_BYTES}"),
            ));
        }
        total.checked_add(item.size).ok_or_else(|| {
            MemoryApiError::request(
                RpcErrorCode::MemoryLimitExceeded,
                "batch byte count overflowed",
            )
        })
    })?;
    if total > MAX_BATCH_BYTES {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("batch requests {total} bytes; maximum is {MAX_BATCH_BYTES}"),
        ));
    }

    let results =
        sessions.with_live_session(backend, &request.session_id, |backend, handle, _| {
            let mut results = Vec::with_capacity(request.reads.len());
            for item in &request.reads {
                let parsed = validate_range_for_item(&item.address, item.size);
                let result = match parsed {
                    Ok(address) => match backend.read_memory(handle, address, item.size) {
                        Ok(bytes) => MemoryReadItemResult {
                            address: format_address(address),
                            requested_size: item.size,
                            bytes: Some(bytes),
                            error: None,
                        },
                        Err(error) => MemoryReadItemResult {
                            address: item.address.clone(),
                            requested_size: item.size,
                            bytes: None,
                            error: Some(MemoryItemError {
                                code: MemoryItemErrorCode::ReadFailed,
                                message: error.message,
                            }),
                        },
                    },
                    Err(item_error) => MemoryReadItemResult {
                        address: item.address.clone(),
                        requested_size: item.size,
                        bytes: None,
                        error: Some(item_error),
                    },
                };
                results.push(result);
            }
            Ok::<_, MemoryApiError>(results)
        })?;
    Ok(MemoryBatchReadResponse {
        session_id: request.session_id.clone(),
        results,
    })
}

pub fn read_typed<B: MemoryBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    request: &TypedMemoryReadRequest,
) -> Result<TypedMemoryReadResponse, MemoryApiError> {
    let size = request.value_type.size();
    let address = validate_range(&request.address, size)?;
    let raw_bytes =
        sessions.with_live_session(backend, &request.session_id, |backend, handle, _| {
            backend
                .read_memory(handle, address, size)
                .map_err(MemoryApiError::from)
        })?;
    let value = decode_typed(request.value_type, request.byte_order, &raw_bytes)?;
    Ok(TypedMemoryReadResponse {
        session_id: request.session_id.clone(),
        address: format_address(address),
        value_type: request.value_type,
        byte_order: request.byte_order,
        raw_bytes,
        value,
    })
}

pub fn scan<B: MemoryBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    request: &MemoryScanRequest,
) -> Result<MemoryScanResponse, MemoryApiError> {
    let signature = parse_signature(&request.signature)?;
    validate_scan_limits(request.max_matches)?;
    let collected =
        sessions.with_live_session(backend, &request.session_id, |backend, handle, process| {
            scan_for_addresses(
                backend,
                handle,
                process,
                &request.scope,
                &signature,
                request.max_matches,
                request.unique,
            )
        })?;
    finish_scan(request, collected)
}

pub fn pointer_chain<B: MemoryBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    request: &MemoryPointerChainRequest,
) -> Result<MemoryPointerChainResponse, MemoryApiError> {
    let signature = parse_signature(&request.signature)?;
    validate_scan_limits(2)?;
    if request.offsets.len() != request.dereference_count.saturating_add(1)
        || request.offsets.is_empty()
        || request.offsets.len() > MAX_POINTER_OFFSETS
    {
        return Err(MemoryApiError::request(
            RpcErrorCode::InvalidRequest,
            "pointer-chain offsets must contain dereference_count + 1 entries",
        ));
    }
    if !matches!(request.pointer_width, 4 | 8) {
        return Err(MemoryApiError::request(
            RpcErrorCode::InvalidRequest,
            "pointer width must be 4 or 8 bytes",
        ));
    }
    let response =
        sessions.with_live_session(backend, &request.session_id, |backend, handle, process| {
            let collected = scan_for_addresses(
                backend,
                handle,
                process,
                &request.scope,
                &signature,
                2,
                true,
            )?;
            let root = match collected.matches.as_slice() {
                [] => {
                    return Err(MemoryApiError::request(
                        RpcErrorCode::MemoryRequiredMatchNotFound,
                        "pointer-chain signature did not match",
                    ))
                }
                [root] => *root,
                _ => unreachable!("unique scan returns at most one match"),
            };
            let mut address = root;
            for offset in &request.offsets[..request.dereference_count] {
                address = address.checked_add(u64_to_usize(*offset)?).ok_or_else(|| {
                    MemoryApiError::request(
                        RpcErrorCode::MemoryInvalidAddress,
                        "pointer-chain address overflowed",
                    )
                })?;
                let bytes = backend
                    .read_memory(handle, address, usize::from(request.pointer_width))
                    .map_err(MemoryApiError::from)?;
                address = decode_pointer(request.pointer_width, request.byte_order, &bytes)?;
            }
            address = address
                .checked_add(u64_to_usize(
                    *request.offsets.last().expect("offsets non-empty"),
                )?)
                .ok_or_else(|| {
                    MemoryApiError::request(
                        RpcErrorCode::MemoryInvalidAddress,
                        "pointer-chain target address overflowed",
                    )
                })?;
            let raw_bytes = backend
                .read_memory(handle, address, request.value_type.size())
                .map_err(MemoryApiError::from)?;
            let value = decode_typed(request.value_type, request.byte_order, &raw_bytes)?;
            Ok(MemoryPointerChainResponse {
                session_id: request.session_id.clone(),
                root_match: format_address(root),
                target_address: format_address(address),
                value_type: request.value_type,
                byte_order: request.byte_order,
                raw_bytes,
                value,
            })
        })?;
    Ok(response)
}

struct ScanCollected {
    matches: Vec<usize>,
    scanned_regions: usize,
    skipped_regions: usize,
    errors: Vec<MemoryScanRegionError>,
}

#[derive(Clone, Copy)]
struct ScanOptions<'a> {
    signature: &'a [Option<u8>],
    max_matches: usize,
    unique: bool,
}

fn scan_for_addresses<B: MemoryBackend>(
    backend: &B,
    handle: &B::Handle,
    process: &ProcessDescriptor,
    scope: &MemoryScanScope,
    signature: &[Option<u8>],
    max_matches: usize,
    unique: bool,
) -> Result<ScanCollected, MemoryApiError> {
    let identity = process_identity(process)?;
    let mut regions = backend
        .enumerate_memory_regions(handle, identity)
        .map_err(MemoryApiError::from)?;
    regions.sort_by_key(|region| parse_address(&region.base_address).unwrap_or(usize::MAX));
    if regions.len() > deimos_core::memory::MAX_SCAN_REGIONS {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            "scan region count exceeds the protocol limit",
        ));
    }
    let bounds = match scope {
        MemoryScanScope::Process => None,
        MemoryScanScope::Module { name } => Some(module_bounds(backend, handle, identity, name)?),
    };
    let mut collected = ScanCollected {
        matches: Vec::new(),
        scanned_regions: 0,
        skipped_regions: 0,
        errors: Vec::new(),
    };
    for region in regions {
        let start = parse_address(&region.base_address)?;
        let end = start.checked_add(region.size).ok_or_else(|| {
            MemoryApiError::request(
                RpcErrorCode::MemoryInvalidAddress,
                "memory region address range overflowed",
            )
        })?;
        let (scan_start, scan_end) = match bounds {
            Some((module_start, module_end)) => (start.max(module_start), end.min(module_end)),
            None => (start, end),
        };
        if scan_start >= scan_end || scan_end - scan_start < signature.len() {
            continue;
        }
        collected.scanned_regions += 1;
        scan_region(
            backend,
            handle,
            scan_start,
            scan_end - scan_start,
            ScanOptions {
                signature,
                max_matches,
                unique,
            },
            &mut collected,
        )?;
        if unique && collected.matches.len() > 1 {
            return Err(MemoryApiError::request(
                RpcErrorCode::MemoryAmbiguousMatch,
                "signature matched more than one address",
            )
            .with_detail("match_count", collected.matches.len().to_string()));
        }
    }
    collected.matches.sort_unstable();
    Ok(collected)
}

fn scan_region<B: MemoryBackend>(
    backend: &B,
    handle: &B::Handle,
    start: usize,
    size: usize,
    options: ScanOptions<'_>,
    collected: &mut ScanCollected,
) -> Result<(), MemoryApiError> {
    let overlap = options.signature.len().saturating_sub(1);
    let mut offset = 0usize;
    let mut previous = Vec::new();
    while offset < size {
        let request_size = (size - offset).min(SCAN_CHUNK_SIZE);
        let address = start.checked_add(offset).ok_or_else(|| {
            MemoryApiError::request(
                RpcErrorCode::MemoryInvalidAddress,
                "scan address overflowed",
            )
        })?;
        let bytes = match backend.read_memory(handle, address, request_size) {
            Ok(bytes) => bytes,
            Err(error) => {
                collected.skipped_regions += 1;
                if collected.errors.len() < MAX_SCAN_ERRORS {
                    collected.errors.push(MemoryScanRegionError {
                        base_address: format_address(start),
                        message: error.message,
                    });
                }
                return Ok(());
            }
        };
        let old_end = offset;
        let mut combined = previous;
        combined.extend_from_slice(&bytes);
        let combined_start = address.saturating_sub(combined.len() - bytes.len());
        for (match_offset, window) in combined.windows(options.signature.len()).enumerate() {
            let candidate = combined_start.checked_add(match_offset).ok_or_else(|| {
                MemoryApiError::request(
                    RpcErrorCode::MemoryInvalidAddress,
                    "scan match address overflowed",
                )
            })?;
            let previous_end = start.checked_add(old_end).ok_or_else(|| {
                MemoryApiError::request(
                    RpcErrorCode::MemoryInvalidAddress,
                    "scan previous-chunk boundary overflowed",
                )
            })?;
            let candidate_end =
                candidate
                    .checked_add(options.signature.len())
                    .ok_or_else(|| {
                        MemoryApiError::request(
                            RpcErrorCode::MemoryInvalidAddress,
                            "scan match range overflowed",
                        )
                    })?;
            // Suppress only a candidate whose complete signature was already
            // contained in the preceding chunk. A candidate whose end crosses
            // the boundary is newly observable in this combined overlap.
            if candidate_end <= previous_end
                || !window
                    .iter()
                    .zip(options.signature)
                    .all(|(actual, expected)| expected.is_none_or(|expected| *actual == expected))
            {
                continue;
            }
            collected.matches.push(candidate);
            if options.unique && collected.matches.len() > 1 {
                return Ok(());
            }
            if collected.matches.len() > options.max_matches {
                return Err(MemoryApiError::request(
                    RpcErrorCode::MemoryLimitExceeded,
                    "scan match count exceeds the requested limit",
                ));
            }
        }
        offset += bytes.len();
        if bytes.len() < request_size {
            collected.skipped_regions += 1;
            return Ok(());
        }
        previous = combined.into_iter().rev().take(overlap).collect::<Vec<_>>();
        previous.reverse();
    }
    Ok(())
}

fn finish_scan(
    request: &MemoryScanRequest,
    collected: ScanCollected,
) -> Result<MemoryScanResponse, MemoryApiError> {
    if request.required && collected.matches.is_empty() {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryRequiredMatchNotFound,
            "required signature did not match any readable address",
        ));
    }
    if request.unique && collected.matches.len() > 1 {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryAmbiguousMatch,
            "signature matched more than one address",
        )
        .with_detail("match_count", collected.matches.len().to_string()));
    }
    Ok(MemoryScanResponse {
        session_id: request.session_id.clone(),
        matches: collected.matches.into_iter().map(format_address).collect(),
        scanned_regions: collected.scanned_regions,
        skipped_regions: collected.skipped_regions,
        errors: collected.errors,
    })
}

fn module_bounds<B: MemoryBackend>(
    backend: &B,
    handle: &B::Handle,
    identity: &ProcessIdentity,
    name: &str,
) -> Result<(usize, usize), MemoryApiError> {
    let mut modules = backend
        .enumerate_modules(handle, identity)
        .map_err(MemoryApiError::from)?;
    modules.retain(|module| module.name.eq_ignore_ascii_case(name));
    if modules.is_empty() {
        return Err(MemoryApiError::request(
            RpcErrorCode::InvalidRequest,
            format!("module {name:?} was not found in the process session"),
        ));
    }
    if modules.len() > 1 {
        return Err(MemoryApiError::request(
            RpcErrorCode::InvalidRequest,
            format!("module {name:?} is ambiguous"),
        ));
    }
    let module = &modules[0];
    let start = parse_address(&module.base_address)?;
    let end = start.checked_add(module.size as usize).ok_or_else(|| {
        MemoryApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "module address range overflowed",
        )
    })?;
    Ok((start, end))
}

fn parse_signature(value: &str) -> Result<Vec<Option<u8>>, MemoryApiError> {
    let tokens: Vec<_> = value.split_whitespace().collect();
    if tokens.is_empty() || tokens.len() > MAX_SIGNATURE_BYTES {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryPatternInvalid,
            format!("signature must contain 1..={MAX_SIGNATURE_BYTES} bytes"),
        ));
    }
    tokens
        .into_iter()
        .map(|token| {
            if token == "??" {
                Ok(None)
            } else if token.len() == 2 {
                u8::from_str_radix(token, 16).map(Some).map_err(|_| {
                    MemoryApiError::request(
                        RpcErrorCode::MemoryPatternInvalid,
                        format!("invalid signature byte {token:?}"),
                    )
                })
            } else {
                Err(MemoryApiError::request(
                    RpcErrorCode::MemoryPatternInvalid,
                    format!("signature token {token:?} must be two hex digits or ??"),
                ))
            }
        })
        .collect()
}

fn validate_scan_limits(max_matches: usize) -> Result<(), MemoryApiError> {
    if max_matches == 0 || max_matches > MAX_SCAN_MATCHES {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("max_matches must be between 1 and {MAX_SCAN_MATCHES}"),
        ));
    }
    Ok(())
}

fn validate_range(value: &str, size: usize) -> Result<usize, MemoryApiError> {
    if size == 0 || size > MAX_MEMORY_READ_BYTES {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("read size must be between 1 and {MAX_MEMORY_READ_BYTES}"),
        ));
    }
    let address = parse_address(value)?;
    address.checked_add(size).ok_or_else(|| {
        MemoryApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "address plus size overflowed",
        )
    })?;
    Ok(address)
}

fn validate_range_for_item(value: &str, size: usize) -> Result<usize, MemoryItemError> {
    if size == 0 || size > MAX_MEMORY_READ_BYTES {
        return Err(MemoryItemError {
            code: MemoryItemErrorCode::InvalidSize,
            message: format!("read size must be between 1 and {MAX_MEMORY_READ_BYTES}"),
        });
    }
    let address = parse_address(value).map_err(|error| MemoryItemError {
        code: MemoryItemErrorCode::InvalidAddress,
        message: error_message(error),
    })?;
    address.checked_add(size).ok_or_else(|| MemoryItemError {
        code: MemoryItemErrorCode::InvalidAddress,
        message: "address plus size overflowed".to_string(),
    })?;
    Ok(address)
}

fn parse_address(value: &str) -> Result<usize, MemoryApiError> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| {
            MemoryApiError::request(
                RpcErrorCode::MemoryInvalidAddress,
                format!("address {value:?} must use 0x hexadecimal notation"),
            )
        })?;
    if digits.is_empty() {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "address contains no hexadecimal digits",
        ));
    }
    usize::from_str_radix(digits, 16).map_err(|_| {
        MemoryApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            format!("address {value:?} is not representable on this agent"),
        )
    })
}

fn process_identity(process: &ProcessDescriptor) -> Result<&ProcessIdentity, MemoryApiError> {
    process.identity.as_ref().ok_or_else(|| {
        MemoryApiError::request(
            RpcErrorCode::Internal,
            "process session did not retain a stable identity",
        )
    })
}

fn u64_to_usize(value: u64) -> Result<usize, MemoryApiError> {
    usize::try_from(value).map_err(|_| {
        MemoryApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "pointer-chain offset does not fit the agent address width",
        )
    })
}

fn decode_pointer(width: u8, order: ByteOrder, bytes: &[u8]) -> Result<usize, MemoryApiError> {
    match (width, order) {
        (4, ByteOrder::LittleEndian) => Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
            MemoryApiError::request(RpcErrorCode::MemoryReadFailed, "pointer read size mismatch")
        })?) as usize),
        (4, ByteOrder::BigEndian) => Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            MemoryApiError::request(RpcErrorCode::MemoryReadFailed, "pointer read size mismatch")
        })?) as usize),
        (8, ByteOrder::LittleEndian) => {
            u64_to_usize(u64::from_le_bytes(bytes.try_into().map_err(|_| {
                MemoryApiError::request(
                    RpcErrorCode::MemoryReadFailed,
                    "pointer read size mismatch",
                )
            })?))
        }
        (8, ByteOrder::BigEndian) => {
            u64_to_usize(u64::from_be_bytes(bytes.try_into().map_err(|_| {
                MemoryApiError::request(
                    RpcErrorCode::MemoryReadFailed,
                    "pointer read size mismatch",
                )
            })?))
        }
        _ => Err(MemoryApiError::request(
            RpcErrorCode::InvalidRequest,
            "pointer width must be 4 or 8 bytes",
        )),
    }
}

fn decode_typed(
    value_type: MemoryValueType,
    order: ByteOrder,
    bytes: &[u8],
) -> Result<TypedMemoryValue, MemoryApiError> {
    let invalid =
        || MemoryApiError::request(RpcErrorCode::MemoryReadFailed, "typed read size mismatch");
    Ok(match (value_type, order) {
        (MemoryValueType::U8, _) => TypedMemoryValue::U8 {
            value: *bytes.first().ok_or_else(invalid)?,
        },
        (MemoryValueType::I32, ByteOrder::LittleEndian) => TypedMemoryValue::I32 {
            value: i32::from_le_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::I32, ByteOrder::BigEndian) => TypedMemoryValue::I32 {
            value: i32::from_be_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::U32, ByteOrder::LittleEndian) => TypedMemoryValue::U32 {
            value: u32::from_le_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::U32, ByteOrder::BigEndian) => TypedMemoryValue::U32 {
            value: u32::from_be_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::U64, ByteOrder::LittleEndian) => TypedMemoryValue::U64 {
            value: u64::from_le_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::U64, ByteOrder::BigEndian) => TypedMemoryValue::U64 {
            value: u64::from_be_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::F32, ByteOrder::LittleEndian) => TypedMemoryValue::F32 {
            value: f32::from_le_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::F32, ByteOrder::BigEndian) => TypedMemoryValue::F32 {
            value: f32::from_be_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::F64, ByteOrder::LittleEndian) => TypedMemoryValue::F64 {
            value: f64::from_le_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
        (MemoryValueType::F64, ByteOrder::BigEndian) => TypedMemoryValue::F64 {
            value: f64::from_be_bytes(bytes.try_into().map_err(|_| invalid())?),
        },
    })
}

fn format_address(address: usize) -> String {
    format!("{address:#x}")
}

fn error_message(error: MemoryApiError) -> String {
    match error {
        MemoryApiError::Process(_) => "process session is no longer usable".to_string(),
        MemoryApiError::Request { message, .. } => message,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use deimos_core::memory::{
        ByteOrder, MemoryBatchReadRequest, MemoryReadItem, MemoryReadRequest, MemoryScanRequest,
        MemoryScanScope, MemoryValueType, TypedMemoryReadRequest,
    };
    use deimos_core::process::{
        classify_process, ModuleDescriptor, OpenProcessRequest, ProcessDescriptor, ProcessIdentity,
        WIZARD101_EXECUTABLE,
    };
    use deimos_core::rpc::RpcErrorCode;

    use crate::process::{
        MemoryBackend, OpenedProcess, ProcessBackend, ProcessBackendError, ProcessBackendErrorKind,
        ProcessSessionRegistry,
    };

    use super::{parse_signature, validate_range};

    #[test]
    fn signature_parser_accepts_exact_and_wildcard_bytes() {
        assert_eq!(
            parse_signature("A5 ?? 0f").expect("signature"),
            vec![Some(0xa5), None, Some(0x0f)]
        );
    }

    #[test]
    fn signature_parser_rejects_malformed_tokens() {
        for input in ["", "A", "AAA", "GG", "?"] {
            assert_eq!(
                parse_signature(input)
                    .expect_err("invalid signature")
                    .into_code(),
                RpcErrorCode::MemoryPatternInvalid
            );
        }
    }

    #[test]
    fn address_validation_rejects_overflow_and_non_hex() {
        assert_eq!(validate_range("0x100", 4).expect("address"), 0x100);
        assert_eq!(
            validate_range("100", 4).expect_err("notation").into_code(),
            RpcErrorCode::MemoryInvalidAddress
        );
        assert_eq!(
            validate_range("0xffffffffffffffff", 2)
                .expect_err("overflow")
                .into_code(),
            RpcErrorCode::MemoryInvalidAddress
        );
    }

    #[derive(Clone)]
    struct MockMemoryBackend {
        stale_after_read: Arc<AtomicBool>,
        stale: Arc<AtomicBool>,
        large_memory: Option<Arc<Vec<u8>>>,
    }

    #[derive(Clone, Copy)]
    struct MockHandle;

    fn mock_process() -> ProcessDescriptor {
        let path = format!(r"C:\Wizard101\{WIZARD101_EXECUTABLE}");
        ProcessDescriptor {
            pid: 336,
            name: WIZARD101_EXECUTABLE.to_string(),
            kind: classify_process(WIZARD101_EXECUTABLE),
            executable_path: Some(path.clone()),
            identity: Some(ProcessIdentity {
                pid: 336,
                creation_time_100ns: "1000".to_string(),
                executable_path: path,
            }),
        }
    }

    impl ProcessBackend for MockMemoryBackend {
        type Handle = MockHandle;

        fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
            Ok(vec![mock_process()])
        }

        fn open_process(
            &self,
            pid: u32,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            if pid != 336 {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::NotFound,
                    "mock process not found",
                ));
            }
            Ok(OpenedProcess {
                handle: MockHandle,
                process: mock_process(),
            })
        }

        fn validate_process(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<(), ProcessBackendError> {
            if self.stale.load(Ordering::SeqCst) {
                Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::IdentityMismatch,
                    "mock process identity changed",
                ))
            } else {
                Ok(())
            }
        }

        fn enumerate_modules(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<Vec<ModuleDescriptor>, ProcessBackendError> {
            Ok(vec![ModuleDescriptor {
                name: "WizardGraphicalClient.exe".to_string(),
                executable_path: r"C:\Wizard101\WizardGraphicalClient.exe".to_string(),
                base_address: "0x1000".to_string(),
                size: 0x20,
            }])
        }
    }

    impl MemoryBackend for MockMemoryBackend {
        fn enumerate_memory_regions(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<Vec<deimos_core::memory::MemoryRegionDescriptor>, ProcessBackendError> {
            if let Some(memory) = &self.large_memory {
                return Ok(vec![deimos_core::memory::MemoryRegionDescriptor {
                    base_address: "0x1000".to_string(),
                    size: memory.len(),
                    protection: deimos_core::memory::MemoryProtection::ReadWrite,
                }]);
            }
            Ok(vec![
                deimos_core::memory::MemoryRegionDescriptor {
                    base_address: "0x1000".to_string(),
                    size: 0x40,
                    protection: deimos_core::memory::MemoryProtection::ReadWrite,
                },
                deimos_core::memory::MemoryRegionDescriptor {
                    base_address: "0x2000".to_string(),
                    size: 0x10,
                    protection: deimos_core::memory::MemoryProtection::ReadOnly,
                },
            ])
        }

        fn read_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
            size: usize,
        ) -> Result<Vec<u8>, ProcessBackendError> {
            if let Some(memory) = &self.large_memory {
                let offset = address.checked_sub(0x1000).ok_or_else(|| {
                    ProcessBackendError::new(
                        ProcessBackendErrorKind::Native,
                        "mock address underflow",
                    )
                })?;
                let end = offset.checked_add(size).ok_or_else(|| {
                    ProcessBackendError::new(ProcessBackendErrorKind::Native, "mock read overflow")
                })?;
                if end > memory.len() {
                    return Err(ProcessBackendError::new(
                        ProcessBackendErrorKind::Native,
                        "mock partial read",
                    ));
                }
                if self.stale_after_read.load(Ordering::SeqCst) {
                    self.stale.store(true, Ordering::SeqCst);
                }
                return Ok(memory[offset..end].to_vec());
            }
            if address >= 0x2000 {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    "mock inaccessible region",
                ));
            }
            let mut memory = [0u8; 0x40];
            memory[0..4].copy_from_slice(&[0xa5, 0x11, 0x22, 0x33]);
            memory[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            memory[8..12].copy_from_slice(&42i32.to_le_bytes());
            memory[0x10..0x18].copy_from_slice(&(0x1018u64).to_le_bytes());
            memory[0x18..0x20].copy_from_slice(&(0x1020u64).to_le_bytes());
            memory[0x20..0x28].copy_from_slice(&0xcafe_babe_1020_3040u64.to_le_bytes());
            let offset = address.checked_sub(0x1000).ok_or_else(|| {
                ProcessBackendError::new(ProcessBackendErrorKind::Native, "mock address underflow")
            })?;
            let end = offset.checked_add(size).ok_or_else(|| {
                ProcessBackendError::new(ProcessBackendErrorKind::Native, "mock read overflow")
            })?;
            if end > memory.len() {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    "mock partial read",
                ));
            }
            if self.stale_after_read.load(Ordering::SeqCst) {
                self.stale.store(true, Ordering::SeqCst);
            }
            Ok(memory[offset..end].to_vec())
        }
    }

    fn mock_registry(
        stale_after_read: bool,
    ) -> (
        MockMemoryBackend,
        ProcessSessionRegistry<MockHandle>,
        String,
    ) {
        let backend = MockMemoryBackend {
            stale_after_read: Arc::new(AtomicBool::new(stale_after_read)),
            stale: Arc::new(AtomicBool::new(false)),
            large_memory: None,
        };
        let mut registry = ProcessSessionRegistry::new();
        let session = registry
            .open(
                &backend,
                &OpenProcessRequest {
                    pid: 336,
                    expected_identity: None,
                },
            )
            .expect("mock process should open");
        (backend, registry, session.session_id.0)
    }

    #[test]
    fn scan_detects_signatures_spanning_chunks_without_duplicate_prior_matches() {
        let signature = [0xa1, 0xb2, 0xc3, 0xd4];
        let cross_chunk_offset = super::SCAN_CHUNK_SIZE - 2;
        let mut memory = vec![0u8; super::SCAN_CHUNK_SIZE + 32];
        memory[0x80..0x84].copy_from_slice(&signature);
        memory[cross_chunk_offset..cross_chunk_offset + signature.len()]
            .copy_from_slice(&signature);
        let backend = MockMemoryBackend {
            stale_after_read: Arc::new(AtomicBool::new(false)),
            stale: Arc::new(AtomicBool::new(false)),
            large_memory: Some(Arc::new(memory)),
        };
        let mut registry = ProcessSessionRegistry::new();
        let session = registry
            .open(
                &backend,
                &OpenProcessRequest {
                    pid: 336,
                    expected_identity: None,
                },
            )
            .expect("mock process should open");
        let response = super::scan(
            &mut registry,
            &backend,
            &MemoryScanRequest {
                session_id: session.session_id,
                signature: "A1 B2 C3 D4".to_string(),
                required: true,
                unique: false,
                max_matches: 8,
                scope: MemoryScanScope::Process,
            },
        )
        .expect("cross-chunk signature should be found");
        assert_eq!(
            response.matches,
            vec![
                "0x1080".to_string(),
                format!("{:#x}", 0x1000 + cross_chunk_offset),
            ]
        );
    }

    #[test]
    fn mock_backend_covers_typed_batch_scan_pointer_and_partial_reads() {
        let (backend, mut registry, session_id) = mock_registry(false);
        let session = deimos_core::process::ProcessSessionId(session_id.clone());
        let typed = super::read_typed(
            &mut registry,
            &backend,
            &TypedMemoryReadRequest {
                session_id: session.clone(),
                address: "0x1008".to_string(),
                value_type: MemoryValueType::I32,
                byte_order: ByteOrder::LittleEndian,
            },
        )
        .expect("typed mock read should work");
        assert_eq!(typed.raw_bytes, 42i32.to_le_bytes());

        let batch = super::read_batch(
            &mut registry,
            &backend,
            &MemoryBatchReadRequest {
                session_id: session.clone(),
                reads: vec![
                    MemoryReadItem {
                        address: "0x1008".to_string(),
                        size: 4,
                    },
                    MemoryReadItem {
                        address: "not-an-address".to_string(),
                        size: 4,
                    },
                ],
            },
        )
        .expect("batch should preserve per-item errors");
        assert_eq!(
            batch.results[0].bytes.as_deref(),
            Some(&42i32.to_le_bytes()[..])
        );
        assert_eq!(
            batch.results[1].error.as_ref().map(|error| error.code),
            Some(deimos_core::memory::MemoryItemErrorCode::InvalidAddress)
        );

        let scan = super::scan(
            &mut registry,
            &backend,
            &MemoryScanRequest {
                session_id: session.clone(),
                signature: "A5 ?? 22 ??".to_string(),
                required: true,
                unique: true,
                max_matches: 4,
                scope: MemoryScanScope::Process,
            },
        )
        .expect("mock exact/wildcard scan should work");
        assert_eq!(scan.matches, vec!["0x1000"]);
        assert!(scan.skipped_regions > 0);

        let resolved = super::pointer_chain(
            &mut registry,
            &backend,
            &deimos_core::memory::MemoryPointerChainRequest {
                session_id: session,
                signature: "A5 11 22 33".to_string(),
                offsets: vec![0x10, 0, 0],
                dereference_count: 2,
                pointer_width: 8,
                byte_order: ByteOrder::LittleEndian,
                value_type: MemoryValueType::U64,
                scope: MemoryScanScope::Module {
                    name: "WizardGraphicalClient.exe".to_string(),
                },
            },
        )
        .expect("mock pointer chain should resolve");
        assert_eq!(resolved.target_address, "0x1020");
        assert_eq!(resolved.raw_bytes, 0xcafe_babe_1020_3040u64.to_le_bytes());
    }

    #[test]
    fn memory_operation_revalidates_after_read_and_returns_stale_session_error() {
        let (backend, mut registry, session_id) = mock_registry(true);
        let error = super::read(
            &mut registry,
            &backend,
            &MemoryReadRequest {
                session_id: deimos_core::process::ProcessSessionId(session_id),
                address: "0x1000".to_string(),
                size: 1,
            },
        )
        .expect_err("post-read identity change must invalidate the session");
        assert_eq!(
            error.into_rpc_error(7, "memory.read").code,
            RpcErrorCode::ProcessExited
        );
    }

    #[test]
    fn memory_limits_reject_oversized_batches() {
        let (backend, mut registry, session_id) = mock_registry(false);
        let error = validate_range("0x1000", super::MAX_MEMORY_READ_BYTES + 1)
            .expect_err("oversized read should be rejected");
        assert_eq!(error.into_code(), RpcErrorCode::MemoryLimitExceeded);

        let session = deimos_core::process::ProcessSessionId(session_id);
        registry
            .close(&backend, &session)
            .expect("mock session should close");
        let error = super::read(
            &mut registry,
            &backend,
            &MemoryReadRequest {
                session_id: session,
                address: "0x1000".to_string(),
                size: 1,
            },
        )
        .expect_err("closed sessions must not read memory");
        assert_eq!(
            error.into_rpc_error(8, "memory.read").code,
            RpcErrorCode::InvalidRequest
        );
    }

    trait ErrorCode {
        fn into_code(self) -> RpcErrorCode;
    }

    impl ErrorCode for super::MemoryApiError {
        fn into_code(self) -> RpcErrorCode {
            match self {
                super::MemoryApiError::Request { code, .. } => code,
                super::MemoryApiError::Process(_) => RpcErrorCode::Internal,
            }
        }
    }
}
