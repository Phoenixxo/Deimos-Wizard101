use std::collections::BTreeMap;
use std::time::{Duration, Instant};

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
use serde_json::json;

use crate::diagnostics::HookTimingSpan;
use crate::process::{MemoryBackend, ProcessApiError, ProcessBackendError, ProcessSessionRegistry};

const SCAN_CHUNK_SIZE: usize = 1024 * 1024;
const MIN_SCAN_CHUNK_SIZE: usize = 64 * 1024;

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
    let timing = HookTimingSpan::new("memory.scan", "total");
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
    let response = finish_scan(request, collected)?;
    timing.finish(
        "ok",
        json!({
            "signature_count": 1,
            "match_count": response.matches.len(),
            "scanned_regions": response.scanned_regions,
            "skipped_regions": response.skipped_regions,
            "scope": scan_scope_name(&request.scope),
        }),
    );
    Ok(response)
}

pub(crate) fn scan_optional_unique_signatures<B: MemoryBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &deimos_core::process::ProcessSessionId,
    scope: &MemoryScanScope,
    signatures: &[&str],
) -> Result<Vec<Option<usize>>, MemoryApiError> {
    let timing = HookTimingSpan::new("memory.scan_batch", "total");
    let parsed = signatures
        .iter()
        .map(|signature| parse_signature(signature))
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.is_empty() {
        timing.finish(
            "ok",
            json!({"signature_count": 0, "match_count": 0, "scope": scan_scope_name(scope)}),
        );
        return Ok(Vec::new());
    }

    let resolved =
        sessions.with_live_session(backend, session_id, |backend, handle, process| {
            scan_for_optional_unique_signatures(backend, handle, process, scope, &parsed)
        })?;
    timing.finish(
        "ok",
        json!({
            "signature_count": signatures.len(),
            "match_count": resolved.iter().flatten().count(),
            "scope": scan_scope_name(scope),
        }),
    );
    Ok(resolved)
}

fn scan_scope_name(scope: &MemoryScanScope) -> &'static str {
    match scope {
        MemoryScanScope::Process => "process",
        MemoryScanScope::Module { .. } => "module",
    }
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
    let enumerate_timing = HookTimingSpan::new("memory.scan", "enumerate_regions");
    let mut regions = backend
        .enumerate_memory_regions(handle, identity)
        .map_err(MemoryApiError::from)?;
    enumerate_timing.finish("ok", json!({"region_count": regions.len()}));
    regions.sort_by_key(|region| parse_address(&region.base_address).unwrap_or(usize::MAX));
    if regions.len() > deimos_core::memory::MAX_SCAN_REGIONS {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            "scan region count exceeds the protocol limit",
        ));
    }
    let bounds_timing = HookTimingSpan::new("memory.scan", "resolve_scope_bounds");
    let bounds = match scope {
        MemoryScanScope::Process => None,
        MemoryScanScope::Module { name } => Some(module_bounds(backend, handle, identity, name)?),
    };
    bounds_timing.finish("ok", json!({"scope": scan_scope_name(scope)}));
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

fn scan_for_optional_unique_signatures<B: MemoryBackend>(
    backend: &B,
    handle: &B::Handle,
    process: &ProcessDescriptor,
    scope: &MemoryScanScope,
    signatures: &[Vec<Option<u8>>],
) -> Result<Vec<Option<usize>>, MemoryApiError> {
    let identity = process_identity(process)?;
    let enumerate_timing = HookTimingSpan::new("memory.scan_batch", "enumerate_regions");
    let mut regions = backend
        .enumerate_memory_regions(handle, identity)
        .map_err(MemoryApiError::from)?;
    enumerate_timing.finish("ok", json!({"region_count": regions.len()}));
    regions.sort_by_key(|region| parse_address(&region.base_address).unwrap_or(usize::MAX));
    if regions.len() > deimos_core::memory::MAX_SCAN_REGIONS {
        return Err(MemoryApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            "scan region count exceeds the protocol limit",
        ));
    }
    let bounds_timing = HookTimingSpan::new("memory.scan_batch", "resolve_scope_bounds");
    let bounds = match scope {
        MemoryScanScope::Process => None,
        MemoryScanScope::Module { name } => Some(module_bounds(backend, handle, identity, name)?),
    };
    bounds_timing.finish("ok", json!({"scope": scan_scope_name(scope)}));
    let mut matches = vec![Vec::new(); signatures.len()];
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
        if scan_start >= scan_end
            || signatures
                .iter()
                .all(|signature| scan_end - scan_start < signature.len())
        {
            continue;
        }
        scan_region_for_unique_signatures(
            backend,
            handle,
            scan_start,
            scan_end - scan_start,
            signatures,
            &mut matches,
        )?;
    }

    matches
        .into_iter()
        .enumerate()
        .map(|(index, addresses)| match addresses.as_slice() {
            [] => Ok(None),
            [address] => Ok(Some(*address)),
            _ => Err(MemoryApiError::request(
                RpcErrorCode::MemoryAmbiguousMatch,
                format!("signature at index {index} matched more than one address"),
            )
            .with_detail("match_count", addresses.len().to_string())),
        })
        .collect()
}

fn scan_region_for_unique_signatures<B: MemoryBackend>(
    backend: &B,
    handle: &B::Handle,
    start: usize,
    size: usize,
    signatures: &[Vec<Option<u8>>],
    matches: &mut [Vec<usize>],
) -> Result<(), MemoryApiError> {
    let timing = HookTimingSpan::new("memory.scan_batch", "scan_region");
    let mut read_elapsed = Duration::ZERO;
    let mut match_elapsed = Duration::ZERO;
    let mut chunk_count = 0usize;
    let mut read_attempts = 0usize;
    let mut bytes_read = 0usize;
    let overlap = signatures
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or_default()
        .saturating_sub(1);
    let mut offset = 0usize;
    let mut chunk_size = SCAN_CHUNK_SIZE;
    let mut previous = Vec::new();
    while offset < size {
        let request_size = (size - offset).min(chunk_size);
        let address = start.checked_add(offset).ok_or_else(|| {
            MemoryApiError::request(
                RpcErrorCode::MemoryInvalidAddress,
                "scan address overflowed",
            )
        })?;
        let read_started = Instant::now();
        let (bytes, actual_request_size, attempts) =
            match read_scan_chunk(backend, handle, address, request_size) {
                Ok(result) => result,
                Err(_) => {
                    read_elapsed += read_started.elapsed();
                    timing.finish(
                        "skipped",
                        json!({
                            "region_size": size,
                            "chunk_count": chunk_count,
                            "read_attempts": read_attempts,
                            "bytes_read": bytes_read,
                            "read_ms": read_elapsed.as_secs_f64() * 1000.0,
                            "match_ms": match_elapsed.as_secs_f64() * 1000.0,
                        }),
                    );
                    return Ok(());
                }
            };
        read_elapsed += read_started.elapsed();
        chunk_count += 1;
        read_attempts += attempts;
        bytes_read += bytes.len();
        chunk_size = actual_request_size;
        let previous_end = start.checked_add(offset).ok_or_else(|| {
            MemoryApiError::request(
                RpcErrorCode::MemoryInvalidAddress,
                "scan previous-chunk boundary overflowed",
            )
        })?;
        let mut combined = previous;
        combined.extend_from_slice(&bytes);
        let combined_start = address.saturating_sub(combined.len() - bytes.len());
        let match_started = Instant::now();
        for (signature_index, signature) in signatures.iter().enumerate() {
            if matches[signature_index].len() > 1 || signature.len() > combined.len() {
                continue;
            }
            visit_signature_matches(&combined, signature, |match_offset| {
                let candidate = combined_start.checked_add(match_offset).ok_or_else(|| {
                    MemoryApiError::request(
                        RpcErrorCode::MemoryInvalidAddress,
                        "scan match address overflowed",
                    )
                })?;
                let candidate_end = candidate.checked_add(signature.len()).ok_or_else(|| {
                    MemoryApiError::request(
                        RpcErrorCode::MemoryInvalidAddress,
                        "scan match range overflowed",
                    )
                })?;
                if candidate_end <= previous_end {
                    return Ok(true);
                }
                matches[signature_index].push(candidate);
                Ok(matches[signature_index].len() <= 1)
            })?;
        }
        match_elapsed += match_started.elapsed();
        offset += bytes.len();
        if bytes.len() < actual_request_size {
            timing.finish(
                "partial",
                json!({
                    "region_size": size,
                    "signature_count": signatures.len(),
                    "chunk_count": chunk_count,
                    "read_attempts": read_attempts,
                    "fallback_attempts": read_attempts.saturating_sub(chunk_count),
                    "bytes_read": bytes_read,
                    "read_ms": read_elapsed.as_secs_f64() * 1000.0,
                    "match_ms": match_elapsed.as_secs_f64() * 1000.0,
                }),
            );
            return Ok(());
        }
        previous = combined.into_iter().rev().take(overlap).collect::<Vec<_>>();
        previous.reverse();
    }
    timing.finish(
        "ok",
        json!({
            "region_size": size,
            "signature_count": signatures.len(),
            "chunk_count": chunk_count,
            "read_attempts": read_attempts,
            "fallback_attempts": read_attempts.saturating_sub(chunk_count),
            "bytes_read": bytes_read,
            "read_ms": read_elapsed.as_secs_f64() * 1000.0,
            "match_ms": match_elapsed.as_secs_f64() * 1000.0,
        }),
    );
    Ok(())
}

fn scan_region<B: MemoryBackend>(
    backend: &B,
    handle: &B::Handle,
    start: usize,
    size: usize,
    options: ScanOptions<'_>,
    collected: &mut ScanCollected,
) -> Result<(), MemoryApiError> {
    let timing = HookTimingSpan::new("memory.scan", "scan_region");
    let mut read_elapsed = Duration::ZERO;
    let mut match_elapsed = Duration::ZERO;
    let mut chunk_count = 0usize;
    let mut read_attempts = 0usize;
    let mut bytes_read = 0usize;
    let overlap = options.signature.len().saturating_sub(1);
    let mut offset = 0usize;
    let mut chunk_size = SCAN_CHUNK_SIZE;
    let mut previous = Vec::new();
    while offset < size {
        let request_size = (size - offset).min(chunk_size);
        let address = start.checked_add(offset).ok_or_else(|| {
            MemoryApiError::request(
                RpcErrorCode::MemoryInvalidAddress,
                "scan address overflowed",
            )
        })?;
        let read_started = Instant::now();
        let (bytes, actual_request_size, attempts) =
            match read_scan_chunk(backend, handle, address, request_size) {
                Ok(result) => result,
                Err(error) => {
                    read_elapsed += read_started.elapsed();
                    collected.skipped_regions += 1;
                    if collected.errors.len() < MAX_SCAN_ERRORS {
                        collected.errors.push(MemoryScanRegionError {
                            base_address: format_address(start),
                            message: error.message,
                        });
                    }
                    timing.finish(
                        "skipped",
                        json!({
                            "region_size": size,
                            "chunk_count": chunk_count,
                            "read_attempts": read_attempts,
                            "bytes_read": bytes_read,
                            "read_ms": read_elapsed.as_secs_f64() * 1000.0,
                            "match_ms": match_elapsed.as_secs_f64() * 1000.0,
                        }),
                    );
                    return Ok(());
                }
            };
        read_elapsed += read_started.elapsed();
        chunk_count += 1;
        read_attempts += attempts;
        bytes_read += bytes.len();
        chunk_size = actual_request_size;
        let old_end = offset;
        let mut combined = previous;
        combined.extend_from_slice(&bytes);
        let combined_start = address.saturating_sub(combined.len() - bytes.len());
        let match_started = Instant::now();
        visit_signature_matches(&combined, options.signature, |match_offset| {
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
            if candidate_end <= previous_end {
                return Ok(true);
            }
            collected.matches.push(candidate);
            if options.unique && collected.matches.len() > 1 {
                return Ok(false);
            }
            if collected.matches.len() > options.max_matches {
                return Err(MemoryApiError::request(
                    RpcErrorCode::MemoryLimitExceeded,
                    "scan match count exceeds the requested limit",
                ));
            }
            Ok(true)
        })?;
        match_elapsed += match_started.elapsed();
        if options.unique && collected.matches.len() > 1 {
            timing.finish(
                "short_circuit",
                json!({
                    "region_size": size,
                    "signature_count": 1,
                    "match_count": collected.matches.len(),
                    "chunk_count": chunk_count,
                    "read_attempts": read_attempts,
                    "fallback_attempts": read_attempts.saturating_sub(chunk_count),
                    "bytes_read": bytes_read,
                    "read_ms": read_elapsed.as_secs_f64() * 1000.0,
                    "match_ms": match_elapsed.as_secs_f64() * 1000.0,
                }),
            );
            return Ok(());
        }
        offset += bytes.len();
        if bytes.len() < actual_request_size {
            collected.skipped_regions += 1;
            timing.finish(
                "partial",
                json!({
                    "region_size": size,
                    "signature_count": 1,
                    "chunk_count": chunk_count,
                    "read_attempts": read_attempts,
                    "fallback_attempts": read_attempts.saturating_sub(chunk_count),
                    "bytes_read": bytes_read,
                    "read_ms": read_elapsed.as_secs_f64() * 1000.0,
                    "match_ms": match_elapsed.as_secs_f64() * 1000.0,
                }),
            );
            return Ok(());
        }
        previous = combined.into_iter().rev().take(overlap).collect::<Vec<_>>();
        previous.reverse();
    }
    timing.finish(
        "ok",
        json!({
            "region_size": size,
            "signature_count": 1,
            "chunk_count": chunk_count,
            "read_attempts": read_attempts,
            "fallback_attempts": read_attempts.saturating_sub(chunk_count),
            "bytes_read": bytes_read,
            "read_ms": read_elapsed.as_secs_f64() * 1000.0,
            "match_ms": match_elapsed.as_secs_f64() * 1000.0,
        }),
    );
    Ok(())
}

fn read_scan_chunk<B: MemoryBackend>(
    backend: &B,
    handle: &B::Handle,
    address: usize,
    preferred_size: usize,
) -> Result<(Vec<u8>, usize, usize), ProcessBackendError> {
    let mut request_size = preferred_size;
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        match backend.read_memory(handle, address, request_size) {
            Ok(bytes) => return Ok((bytes, request_size, attempts)),
            Err(_) if request_size > MIN_SCAN_CHUNK_SIZE => {
                request_size = (request_size / 2).max(MIN_SCAN_CHUNK_SIZE);
            }
            Err(error) => return Err(error),
        }
    }
}

fn visit_signature_matches(
    bytes: &[u8],
    signature: &[Option<u8>],
    mut visitor: impl FnMut(usize) -> Result<bool, MemoryApiError>,
) -> Result<(), MemoryApiError> {
    if signature.is_empty() || signature.len() > bytes.len() {
        return Ok(());
    }
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut run_start = 0usize;
    let mut run_len = 0usize;
    for (index, expected) in signature.iter().enumerate() {
        if expected.is_some() {
            if run_len == 0 {
                run_start = index;
            }
            run_len += 1;
            if run_len > best_len {
                best_start = run_start;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }

    let last_offset = bytes.len() - signature.len();
    if best_len == 0 {
        for offset in 0..=last_offset {
            if !visitor(offset)? {
                break;
            }
        }
        return Ok(());
    }

    let anchor_byte = signature[best_start].expect("the anchor contains only exact bytes");
    let anchor_haystack = &bytes[best_start..=last_offset + best_start];
    for offset in memchr::memchr_iter(anchor_byte, anchor_haystack) {
        if !bytes[offset + best_start..offset + best_start + best_len]
            .iter()
            .zip(&signature[best_start..best_start + best_len])
            .all(|(actual, expected)| expected.as_ref() == Some(actual))
        {
            continue;
        }
        if best_len != signature.len()
            && !bytes[offset..offset + signature.len()]
                .iter()
                .zip(signature)
                .all(|(actual, expected)| expected.is_none() || expected.as_ref() == Some(actual))
        {
            continue;
        }
        if !visitor(offset)? {
            break;
        }
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

pub(crate) fn parse_signature(value: &str) -> Result<Vec<Option<u8>>, MemoryApiError> {
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
        max_read_size: Option<usize>,
        read_count: Arc<AtomicUsize>,
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
            self.read_count.fetch_add(1, Ordering::SeqCst);
            if self.max_read_size.is_some_and(|maximum| size > maximum) {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    "mock read exceeds its supported size",
                ));
            }
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
            max_read_size: None,
            read_count: Arc::new(AtomicUsize::new(0)),
        };
        let mut registry = ProcessSessionRegistry::new();
        let session = registry
            .open(
                &backend,
                &OpenProcessRequest {
                    pid: 336,
                    expected_identity: None,
                    access_mode: deimos_core::process::ProcessAccessMode::ReadOnly,
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
            max_read_size: None,
            read_count: Arc::new(AtomicUsize::new(0)),
        };
        let mut registry = ProcessSessionRegistry::new();
        let session = registry
            .open(
                &backend,
                &OpenProcessRequest {
                    pid: 336,
                    expected_identity: None,
                    access_mode: deimos_core::process::ProcessAccessMode::ReadOnly,
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
        assert_eq!(backend.read_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn scan_falls_back_to_smaller_reads_when_a_large_chunk_is_unavailable() {
        let signature = [0xa1, 0xb2, 0xc3, 0xd4];
        let match_offset = super::MIN_SCAN_CHUNK_SIZE - 2;
        let mut memory = vec![0u8; super::MIN_SCAN_CHUNK_SIZE + 32];
        memory[match_offset..match_offset + signature.len()].copy_from_slice(&signature);
        let backend = MockMemoryBackend {
            stale_after_read: Arc::new(AtomicBool::new(false)),
            stale: Arc::new(AtomicBool::new(false)),
            large_memory: Some(Arc::new(memory)),
            max_read_size: Some(super::MIN_SCAN_CHUNK_SIZE),
            read_count: Arc::new(AtomicUsize::new(0)),
        };
        let mut registry = ProcessSessionRegistry::new();
        let session = registry
            .open(
                &backend,
                &OpenProcessRequest {
                    pid: 336,
                    expected_identity: None,
                    access_mode: deimos_core::process::ProcessAccessMode::ReadOnly,
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
                unique: true,
                max_matches: 2,
                scope: MemoryScanScope::Process,
            },
        )
        .expect("fallback scan should preserve cross-chunk matches");

        assert_eq!(
            response.matches,
            vec![format!("{:#x}", 0x1000 + match_offset)]
        );
        assert_eq!(backend.read_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn unique_signature_batch_reads_each_region_once() {
        let (backend, mut registry, session_id) = mock_registry(false);
        let addresses = super::scan_optional_unique_signatures(
            &mut registry,
            &backend,
            &deimos_core::process::ProcessSessionId(session_id),
            &MemoryScanScope::Process,
            &["A5 11 22 33", "DE AD BE EF"],
        )
        .expect("both signatures should resolve in one scan");

        assert_eq!(addresses, vec![Some(0x1000), Some(0x1004)]);
        assert_eq!(backend.read_count.load(Ordering::SeqCst), 2);
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
