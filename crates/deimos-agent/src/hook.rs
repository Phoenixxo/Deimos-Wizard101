//! Agent-owned x64 detours.  Hooks never escape the mutation session that
//! created them and retain their allocation until original bytes are restored.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use deimos_core::memory::{
    HookActivateRequest, HookActivateResponse, HookDeactivateRequest, HookDeactivateResponse,
    HookHeartbeatRequest, HookHeartbeatResponse, MemoryAllocateRequest, MemoryFreeRequest,
    MemoryProtectRequest, MemoryProtection, MemoryReadRequest, MemoryScanRequest, MemoryScanScope,
    MemoryWriteRequest, MAX_ALLOCATION_BYTES, MAX_HOOK_PAYLOAD_BYTES, MIN_HOOK_SIGNATURE_BYTES,
};
use deimos_core::process::ProcessSessionId;
use deimos_core::rpc::{RpcError, RpcErrorCode};

use crate::memory::{self, MemoryApiError};
use crate::mutation::{self, MutationApiError, MutationState};
use crate::process::{MutationBackend, ProcessSessionRegistry};

pub const HOOK_LEASE: Duration = Duration::from_secs(30);
const ABSOLUTE_JUMP_BYTES: usize = 14;
const MAX_HOOK_KEY_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
struct HookSpec {
    signature: String,
    scope: MemoryScanScope,
    payload: Vec<u8>,
    target_offset: usize,
    overwrite_size: Option<usize>,
}

#[derive(Clone, Debug)]
struct HookRecord {
    spec: HookSpec,
    target_address: usize,
    original_bytes: Vec<u8>,
    allocation_id: String,
    allocation_address: usize,
    original_protection: Option<MemoryProtection>,
    target_may_be_modified: bool,
    activation_complete: bool,
    lease_deadline: Instant,
}

#[derive(Default)]
pub struct HookState {
    hooks: HashMap<ProcessSessionId, BTreeMap<String, HookRecord>>,
}

impl HookState {
    pub fn tracked_count(&self, session_id: &ProcessSessionId) -> usize {
        self.hooks.get(session_id).map_or(0, BTreeMap::len)
    }

    fn get(&self, session_id: &ProcessSessionId, hook_key: &str) -> Option<&HookRecord> {
        self.hooks.get(session_id)?.get(hook_key)
    }

    fn insert(&mut self, session_id: ProcessSessionId, hook_key: String, hook: HookRecord) {
        self.hooks
            .entry(session_id)
            .or_default()
            .insert(hook_key, hook);
    }

    fn remove(&mut self, session_id: &ProcessSessionId, hook_key: &str) {
        if let Some(hooks) = self.hooks.get_mut(session_id) {
            hooks.remove(hook_key);
            if hooks.is_empty() {
                self.hooks.remove(session_id);
            }
        }
    }

    pub(crate) fn allocation_address(
        &self,
        session_id: &ProcessSessionId,
        hook_key: &str,
    ) -> Option<usize> {
        self.get(session_id, hook_key)
            .filter(|record| record.activation_complete)
            .map(|record| record.allocation_address)
    }
}

#[derive(Debug)]
pub enum HookApiError {
    Memory(MemoryApiError),
    Mutation(MutationApiError),
    Request { code: RpcErrorCode, message: String },
}

impl From<MemoryApiError> for HookApiError {
    fn from(error: MemoryApiError) -> Self {
        Self::Memory(error)
    }
}

impl From<MutationApiError> for HookApiError {
    fn from(error: MutationApiError) -> Self {
        Self::Mutation(error)
    }
}

impl HookApiError {
    pub(crate) fn request(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self::Request {
            code,
            message: message.into(),
        }
    }

    pub fn into_rpc_error(self, request_id: u64, operation: &str) -> RpcError {
        match self {
            Self::Memory(error) => error.into_rpc_error(request_id, operation),
            Self::Mutation(error) => error.into_rpc_error(request_id, operation),
            Self::Request { code, message } => {
                RpcError::new(code, message, request_id, operation, None)
            }
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::Memory(error) => format!("{error:?}"),
            Self::Mutation(error) => format!("{error:?}"),
            Self::Request { message, .. } => message.clone(),
        }
    }
}

pub fn activate<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &HookActivateRequest,
    now: Instant,
) -> Result<HookActivateResponse, HookApiError> {
    activate_template(sessions, backend, mutations, hooks, request, 0, None, now)
}

/// Installs a built-in hook with a verified target and overwrite span.
#[allow(clippy::too_many_arguments)]
pub(crate) fn activate_template<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &HookActivateRequest,
    target_offset: usize,
    overwrite_size: Option<usize>,
    now: Instant,
) -> Result<HookActivateResponse, HookApiError> {
    validate_hook_key(&request.hook_key)?;
    let signature = memory::parse_signature(&request.signature)?;
    if signature.len() < MIN_HOOK_SIGNATURE_BYTES {
        return Err(HookApiError::request(
            RpcErrorCode::MemoryPatternInvalid,
            format!(
                "hook signatures must span at least {MIN_HOOK_SIGNATURE_BYTES} bytes for an x64 absolute detour"
            ),
        ));
    }
    if request.payload.len() > MAX_HOOK_PAYLOAD_BYTES {
        return Err(HookApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("hook payload must not exceed {MAX_HOOK_PAYLOAD_BYTES} bytes"),
        ));
    }
    let spec = HookSpec {
        signature: request.signature.clone(),
        scope: request.scope.clone(),
        payload: request.payload.clone(),
        target_offset,
        overwrite_size,
    };
    if let Some(existing) = hooks.get(&request.session_id, &request.hook_key) {
        if existing.spec != spec {
            return Err(HookApiError::request(
                RpcErrorCode::InvalidRequest,
                format!(
                    "hook key {:?} is already active with a different specification",
                    request.hook_key
                ),
            ));
        }
        if !existing.activation_complete {
            return Err(HookApiError::request(
                RpcErrorCode::InvalidRequest,
                "a prior hook activation failed and its recovery ownership is retained; deactivate it before retrying",
            ));
        }
        let response = activation_response(request, existing);
        hooks
            .hooks
            .get_mut(&request.session_id)
            .and_then(|entries| entries.get_mut(&request.hook_key))
            .expect("existing hook record must remain present")
            .lease_deadline = now + HOOK_LEASE;
        return Ok(response);
    }

    // Scan and read are completed before allocation or protection changes.
    let scan = memory::scan(
        sessions,
        backend,
        &MemoryScanRequest {
            session_id: request.session_id.clone(),
            signature: request.signature.clone(),
            required: true,
            unique: true,
            max_matches: 2,
            scope: request.scope.clone(),
        },
    )?;
    let match_address = parse_address(
        scan.matches
            .first()
            .expect("required unique scan must return one address"),
    )?;
    let target_address = match_address.checked_add(target_offset).ok_or_else(|| {
        HookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "core hook target offset overflowed the agent address width",
        )
    })?;
    let available_size = signature.len().checked_sub(target_offset).ok_or_else(|| {
        HookApiError::request(
            RpcErrorCode::InvalidRequest,
            "hook target offset extends beyond its verified signature",
        )
    })?;
    let overwrite_size = match overwrite_size {
        Some(0) => {
            let candidate = memory::read(
                sessions,
                backend,
                &MemoryReadRequest {
                    session_id: request.session_id.clone(),
                    address: format_address(target_address),
                    size: available_size,
                },
            )?
            .bytes;
            if !signature_matches(&candidate, &signature[target_offset..]) {
                return Err(HookApiError::request(
                    RpcErrorCode::MemoryRequiredMatchNotFound,
                    "hook signature changed after scanning and before mutation",
                ));
            }
            relocatable_prefix_len(&candidate, ABSOLUTE_JUMP_BYTES)?
        }
        Some(size) => size,
        None => signature.len(),
    };
    if overwrite_size < ABSOLUTE_JUMP_BYTES {
        return Err(HookApiError::request(
            RpcErrorCode::InvalidRequest,
            format!("hook overwrite must span at least {ABSOLUTE_JUMP_BYTES} complete x64 bytes"),
        ));
    }
    let overwrite_end = target_offset.checked_add(overwrite_size);
    if !matches!(overwrite_end, Some(end) if end <= signature.len()) {
        return Err(HookApiError::request(
            RpcErrorCode::InvalidRequest,
            "hook overwrite extends beyond its verified signature",
        ));
    }
    let original_bytes = memory::read(
        sessions,
        backend,
        &MemoryReadRequest {
            session_id: request.session_id.clone(),
            address: format_address(target_address),
            size: overwrite_size,
        },
    )?
    .bytes;
    if !signature_matches(
        &original_bytes,
        &signature[target_offset..target_offset + overwrite_size],
    ) {
        return Err(HookApiError::request(
            RpcErrorCode::MemoryRequiredMatchNotFound,
            "hook signature changed after scanning and before mutation",
        ));
    }
    validate_relocatable_x64(&original_bytes)?;
    let trampoline_size = request
        .payload
        .len()
        .checked_add(original_bytes.len())
        .and_then(|size| size.checked_add(ABSOLUTE_JUMP_BYTES))
        .ok_or_else(|| {
            HookApiError::request(
                RpcErrorCode::MemoryLimitExceeded,
                "hook trampoline size overflowed",
            )
        })?;
    if trampoline_size > MAX_ALLOCATION_BYTES {
        return Err(HookApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            "hook trampoline exceeds the remote allocation limit",
        ));
    }

    let allocation = mutation::allocate(
        sessions,
        backend,
        mutations,
        &MemoryAllocateRequest {
            session_id: request.session_id.clone(),
            size: trampoline_size,
            protection: MemoryProtection::ExecuteReadWrite,
        },
    )?;
    let allocation_address = parse_agent_address(&allocation.address);
    let record = HookRecord {
        spec,
        target_address,
        original_bytes,
        allocation_id: allocation.allocation_id,
        allocation_address,
        original_protection: None,
        target_may_be_modified: false,
        activation_complete: false,
        lease_deadline: now + HOOK_LEASE,
    };
    hooks.insert(request.session_id.clone(), request.hook_key.clone(), record);
    let trampoline = build_trampoline(
        &request.payload,
        &hooks
            .get(&request.session_id, &request.hook_key)
            .expect("new hook record must be tracked")
            .original_bytes,
        target_address.checked_add(overwrite_size).ok_or_else(|| {
            HookApiError::request(
                RpcErrorCode::MemoryInvalidAddress,
                "hook continuation address overflowed",
            )
        })?,
    );
    if let Err(error) = mutation::write(
        sessions,
        backend,
        &MemoryWriteRequest {
            session_id: request.session_id.clone(),
            address: allocation.address.clone(),
            bytes: trampoline,
        },
    ) {
        return activation_failure(sessions, backend, mutations, hooks, request, error.into());
    }
    if let Err(error) = mutation::flush_instruction_cache(
        sessions,
        backend,
        &request.session_id,
        &allocation.address,
        trampoline_size,
    ) {
        return activation_failure(sessions, backend, mutations, hooks, request, error.into());
    }

    let target_address_text = format_address(target_address);
    let protection = match mutation::protect(
        sessions,
        backend,
        &MemoryProtectRequest {
            session_id: request.session_id.clone(),
            address: target_address_text.clone(),
            size: overwrite_size,
            protection: MemoryProtection::ExecuteReadWrite,
        },
    ) {
        Ok(protection) => protection,
        Err(error) => {
            return activation_failure(sessions, backend, mutations, hooks, request, error.into());
        }
    };
    {
        let record = hooks
            .hooks
            .get_mut(&request.session_id)
            .and_then(|records| records.get_mut(&request.hook_key))
            .expect("provisional hook record must remain tracked");
        record.original_protection = Some(protection.previous_protection);
        record.target_may_be_modified = true;
    }
    let detour = build_detour(allocation_address, overwrite_size);
    if let Err(error) = mutation::write(
        sessions,
        backend,
        &MemoryWriteRequest {
            session_id: request.session_id.clone(),
            address: target_address_text.clone(),
            bytes: detour,
        },
    ) {
        return activation_failure(sessions, backend, mutations, hooks, request, error.into());
    }
    if let Err(error) = mutation::flush_instruction_cache(
        sessions,
        backend,
        &request.session_id,
        &target_address_text,
        overwrite_size,
    ) {
        return activation_failure(sessions, backend, mutations, hooks, request, error.into());
    }
    if let Err(error) = mutation::protect(
        sessions,
        backend,
        &MemoryProtectRequest {
            session_id: request.session_id.clone(),
            address: target_address_text,
            size: overwrite_size,
            protection: protection.previous_protection,
        },
    ) {
        return activation_failure(sessions, backend, mutations, hooks, request, error.into());
    }
    let record = hooks
        .hooks
        .get_mut(&request.session_id)
        .and_then(|records| records.get_mut(&request.hook_key))
        .expect("active hook record must remain tracked");
    record.activation_complete = true;
    let response = activation_response(request, record);
    Ok(response)
}

pub fn deactivate<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &HookDeactivateRequest,
) -> Result<HookDeactivateResponse, HookApiError> {
    validate_hook_key(&request.hook_key)?;
    if hooks.get(&request.session_id, &request.hook_key).is_none() {
        return Ok(HookDeactivateResponse {
            session_id: request.session_id.clone(),
            hook_key: request.hook_key.clone(),
            deactivated: false,
            allocation_released: false,
        });
    }
    cleanup_one(
        sessions,
        backend,
        mutations,
        hooks,
        &request.session_id,
        &request.hook_key,
    )?;
    Ok(HookDeactivateResponse {
        session_id: request.session_id.clone(),
        hook_key: request.hook_key.clone(),
        deactivated: true,
        allocation_released: true,
    })
}

pub fn heartbeat(
    hooks: &mut HookState,
    request: &HookHeartbeatRequest,
    now: Instant,
) -> Result<HookHeartbeatResponse, HookApiError> {
    validate_hook_key(&request.hook_key)?;
    let record = hooks
        .hooks
        .get_mut(&request.session_id)
        .and_then(|records| records.get_mut(&request.hook_key))
        .ok_or_else(|| {
            HookApiError::request(
                RpcErrorCode::InvalidRequest,
                format!("hook key {:?} is not active", request.hook_key),
            )
        })?;
    record.lease_deadline = now + HOOK_LEASE;
    Ok(HookHeartbeatResponse {
        session_id: request.session_id.clone(),
        hook_key: request.hook_key.clone(),
        active: true,
    })
}

pub fn cleanup_session<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    session_id: &ProcessSessionId,
) -> Result<(), HookApiError> {
    let keys = hooks
        .hooks
        .get(session_id)
        .map(|records| records.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let mut failures = Vec::new();
    for key in keys {
        if let Err(error) = cleanup_one(sessions, backend, mutations, hooks, session_id, &key) {
            failures.push(format!("hook {key:?}: {}", error.summary()));
        }
    }
    cleanup_failures("session", Some(session_id), failures)
}

pub fn cleanup_all<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
) -> Result<(), HookApiError> {
    let session_ids = hooks.hooks.keys().cloned().collect::<Vec<_>>();
    let mut failures = Vec::new();
    for session_id in session_ids {
        if let Err(error) = cleanup_session(sessions, backend, mutations, hooks, &session_id) {
            failures.push(format!("session {}: {}", session_id.0, error.summary()));
        }
    }
    cleanup_failures("agent", None, failures)
}

/// The listener calls this with its monotonic clock, making expiry tests
/// deterministic without sleeping for the production lease duration.
pub fn expire_at<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    now: Instant,
) -> Result<usize, HookApiError> {
    let expired = hooks
        .hooks
        .iter()
        .flat_map(|(session_id, records)| {
            records
                .iter()
                .filter(move |(_, record)| record.lease_deadline <= now)
                .map(move |(key, _)| (session_id.clone(), key.clone()))
        })
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    let mut cleaned = 0;
    for (session_id, key) in &expired {
        match cleanup_one(sessions, backend, mutations, hooks, session_id, key) {
            Ok(()) => cleaned += 1,
            Err(error) => failures.push(format!(
                "expired hook {key:?} in session {}: {}",
                session_id.0,
                error.summary()
            )),
        }
    }
    cleanup_failures("lease expiry", None, failures)?;
    Ok(cleaned)
}

fn cleanup_failures(
    context: &str,
    session_id: Option<&ProcessSessionId>,
    failures: Vec<String>,
) -> Result<(), HookApiError> {
    if failures.is_empty() {
        return Ok(());
    }
    let session = session_id
        .map(|session_id| format!(" for session {}", session_id.0))
        .unwrap_or_default();
    Err(HookApiError::request(
        RpcErrorCode::MemoryWriteFailed,
        format!(
            "hook cleanup {context}{session} failed for {} record(s); failed records remain tracked for retry: {}",
            failures.len(),
            failures.join("; ")
        ),
    ))
}

fn cleanup_one<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    session_id: &ProcessSessionId,
    hook_key: &str,
) -> Result<(), HookApiError> {
    let record = hooks
        .get(session_id, hook_key)
        .cloned()
        .expect("cleanup only runs for a tracked hook");
    if record.target_may_be_modified {
        let original_protection = record
            .original_protection
            .expect("modified target must retain its original protection");
        let address = format_address(record.target_address);
        mutation::protect(
            sessions,
            backend,
            &MemoryProtectRequest {
                session_id: session_id.clone(),
                address: address.clone(),
                size: record.original_bytes.len(),
                protection: MemoryProtection::ExecuteReadWrite,
            },
        )?;
        mutation::write(
            sessions,
            backend,
            &MemoryWriteRequest {
                session_id: session_id.clone(),
                address: address.clone(),
                bytes: record.original_bytes.clone(),
            },
        )?;
        // Do not free the trampoline until the target's original code is
        // confirmed visible to instruction fetch.
        mutation::flush_instruction_cache(
            sessions,
            backend,
            session_id,
            &address,
            record.original_bytes.len(),
        )?;
        mutation::protect(
            sessions,
            backend,
            &MemoryProtectRequest {
                session_id: session_id.clone(),
                address,
                size: record.original_bytes.len(),
                protection: original_protection,
            },
        )?;
    }
    mutation::free(
        sessions,
        backend,
        mutations,
        &MemoryFreeRequest {
            session_id: session_id.clone(),
            allocation_id: record.allocation_id.clone(),
        },
    )?;
    hooks.remove(session_id, hook_key);
    Ok(())
}

fn activation_failure<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    mutations: &mut MutationState<B::ThreadHandle>,
    hooks: &mut HookState,
    request: &HookActivateRequest,
    activation_error: HookApiError,
) -> Result<HookActivateResponse, HookApiError> {
    match cleanup_one(
        sessions,
        backend,
        mutations,
        hooks,
        &request.session_id,
        &request.hook_key,
    ) {
        Ok(()) => Err(activation_error),
        Err(_) => Err(HookApiError::request(
            RpcErrorCode::MemoryWriteFailed,
            "hook activation failed and cleanup could not be verified; recovery ownership is retained and deactivation may be retried",
        )),
    }
}

fn activation_response(request: &HookActivateRequest, record: &HookRecord) -> HookActivateResponse {
    HookActivateResponse {
        session_id: request.session_id.clone(),
        hook_key: request.hook_key.clone(),
        target_address: format_address(record.target_address),
        allocation_id: record.allocation_id.clone(),
        allocation_address: format_address(record.allocation_address),
        active: true,
    }
}

fn validate_hook_key(value: &str) -> Result<(), HookApiError> {
    if value.trim().is_empty() || value.len() > MAX_HOOK_KEY_BYTES {
        return Err(HookApiError::request(
            RpcErrorCode::InvalidRequest,
            format!("hook_key must contain 1..={MAX_HOOK_KEY_BYTES} non-whitespace bytes"),
        ));
    }
    Ok(())
}

fn signature_matches(bytes: &[u8], signature: &[Option<u8>]) -> bool {
    bytes.len() == signature.len()
        && bytes
            .iter()
            .zip(signature)
            .all(|(actual, expected)| match expected {
                Some(expected) => *actual == *expected,
                None => true,
            })
}

/// We copy saved instructions verbatim into the trampoline.  Until relocation
/// is implemented, reject instructions whose meaning depends on their old RIP
/// or on a relative branch target.  This compact decoder intentionally accepts
/// only common, position-independent x64 instructions and rejects everything
/// else rather than risking a subtly incorrect detour.
fn validate_relocatable_x64(bytes: &[u8]) -> Result<(), HookApiError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let instruction_start = offset;
        let mut address_size_override = false;
        let mut rex_w = false;
        while let Some(prefix) = bytes.get(offset) {
            match *prefix {
                0x40..=0x4f => {
                    rex_w = *prefix & 0x08 != 0;
                    offset += 1;
                }
                0x66 | 0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => offset += 1,
                0x67 => {
                    address_size_override = true;
                    offset += 1;
                }
                _ => break,
            }
        }
        let opcode = *bytes
            .get(offset)
            .ok_or_else(|| invalid_instruction(instruction_start))?;
        offset += 1;
        if matches!(opcode, 0xe8 | 0xe9 | 0xeb | 0xe0..=0xe3 | 0x70..=0x7f) {
            return Err(HookApiError::request(
                RpcErrorCode::InvalidRequest,
                "hook overwrite contains a relative branch or call that requires relocation",
            ));
        }
        let (has_modrm, immediate_bytes) = match opcode {
            0x90 | 0xc3 | 0xcc | 0x50..=0x5f => (false, 0),
            0xc2 => (false, 2),
            0xb8..=0xbf => (false, if rex_w { 8 } else { 4 }),
            0x00..=0x03
            | 0x08..=0x0b
            | 0x10..=0x13
            | 0x18..=0x1b
            | 0x20..=0x23
            | 0x28..=0x2b
            | 0x30..=0x33
            | 0x38..=0x3b
            | 0x63
            | 0x84..=0x8f
            | 0xd0..=0xd3
            | 0xfe
            | 0xff => (true, 0),
            0x69 | 0x81 | 0xc7 => (true, 4),
            0x6b | 0x80 | 0x82 | 0x83 | 0xc0 | 0xc1 | 0xc6 => (true, 1),
            0xf6 | 0xf7 => (true, 0),
            0x0f => {
                let extended = *bytes
                    .get(offset)
                    .ok_or_else(|| invalid_instruction(instruction_start))?;
                offset += 1;
                if (0x80..=0x8f).contains(&extended) {
                    return Err(HookApiError::request(
                        RpcErrorCode::InvalidRequest,
                        "hook overwrite contains a relative conditional branch that requires relocation",
                    ));
                }
                match extended {
                    0x10 | 0x11 | 0x1f | 0x28 | 0x29 | 0x49 | 0xaf | 0xb6 | 0xb7 | 0xbe | 0xbf => {
                        (true, 0)
                    }
                    _ => return Err(invalid_instruction(instruction_start)),
                }
            }
            _ => return Err(invalid_instruction(instruction_start)),
        };
        if has_modrm {
            let value = *bytes
                .get(offset)
                .ok_or_else(|| invalid_instruction(instruction_start))?;
            offset += 1;
            let mode = value >> 6;
            let rm = value & 7;
            if mode == 0 && rm == 5 {
                let message = if address_size_override {
                    "hook overwrite contains address-relative memory access that requires relocation"
                } else {
                    "hook overwrite contains RIP-relative memory access that requires relocation"
                };
                return Err(HookApiError::request(RpcErrorCode::InvalidRequest, message));
            }
            if mode != 3 && rm == 4 {
                let sib = *bytes
                    .get(offset)
                    .ok_or_else(|| invalid_instruction(instruction_start))?;
                offset += 1;
                if mode == 0 && (sib & 7) == 5 {
                    offset = offset
                        .checked_add(4)
                        .ok_or_else(|| invalid_instruction(instruction_start))?;
                }
            }
            offset = offset
                .checked_add(match mode {
                    1 => 1,
                    2 => 4,
                    _ => 0,
                })
                .ok_or_else(|| invalid_instruction(instruction_start))?;
            let immediate_bytes = match opcode {
                0xf6 if ((value >> 3) & 7) == 0 => 1,
                0xf7 if ((value >> 3) & 7) == 0 => 4,
                _ => immediate_bytes,
            };
            offset = offset
                .checked_add(immediate_bytes)
                .ok_or_else(|| invalid_instruction(instruction_start))?;
        } else {
            offset = offset
                .checked_add(immediate_bytes)
                .ok_or_else(|| invalid_instruction(instruction_start))?;
        }
        if offset > bytes.len() {
            return Err(invalid_instruction(instruction_start));
        }
    }
    Ok(())
}

fn relocatable_prefix_len(bytes: &[u8], minimum: usize) -> Result<usize, HookApiError> {
    for size in minimum..=bytes.len() {
        if validate_relocatable_x64(&bytes[..size]).is_ok() {
            return Ok(size);
        }
    }
    Err(HookApiError::request(
        RpcErrorCode::InvalidRequest,
        format!(
            "hook site does not contain at least {minimum} complete position-independent x64 bytes"
        ),
    ))
}

fn invalid_instruction(offset: usize) -> HookApiError {
    HookApiError::request(
        RpcErrorCode::InvalidRequest,
        format!(
            "hook overwrite contains an unsupported or incomplete x64 instruction at byte {offset}"
        ),
    )
}

fn build_detour(destination: usize, overwrite_len: usize) -> Vec<u8> {
    let mut bytes = vec![0x90; overwrite_len];
    bytes[..6].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
    bytes[6..ABSOLUTE_JUMP_BYTES].copy_from_slice(&(destination as u64).to_le_bytes());
    bytes
}

fn build_trampoline(payload: &[u8], original_bytes: &[u8], continuation: usize) -> Vec<u8> {
    let mut trampoline =
        Vec::with_capacity(payload.len() + original_bytes.len() + ABSOLUTE_JUMP_BYTES);
    trampoline.extend_from_slice(payload);
    trampoline.extend_from_slice(original_bytes);
    trampoline.extend_from_slice(&build_detour(continuation, ABSOLUTE_JUMP_BYTES));
    trampoline
}

fn parse_address(text: &str) -> Result<usize, HookApiError> {
    let digits = text.strip_prefix("0x").ok_or_else(|| {
        HookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "hook target address was not hexadecimal",
        )
    })?;
    usize::from_str_radix(digits, 16).map_err(|_| {
        HookApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "hook target address exceeded agent width",
        )
    })
}

fn parse_agent_address(text: &str) -> usize {
    usize::from_str_radix(
        text.strip_prefix("0x")
            .expect("agent allocation addresses are 0x-prefixed"),
        16,
    )
    .expect("agent allocation address must fit its architecture")
}

fn format_address(address: usize) -> String {
    format!("{address:#x}")
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use deimos_core::memory::{
        HookActivateRequest, HookDeactivateRequest, HookHeartbeatRequest, MemoryProtection,
        MemoryRegionDescriptor, MemoryScanScope,
    };
    use deimos_core::process::{
        OpenProcessRequest, ProcessAccessMode, ProcessDescriptor, ProcessIdentity, ProcessKind,
    };
    use deimos_core::rpc::RpcErrorCode;

    use crate::mutation::MutationState;
    use crate::process::{
        MemoryBackend, MutationBackend, OpenedProcess, ProcessBackend, ProcessBackendError,
        ProcessBackendErrorKind, ProcessSessionRegistry, RemoteThreadPoll, StartedRemoteThread,
    };

    use super::{
        activate, activate_template, build_detour, build_trampoline, cleanup_session, deactivate,
        expire_at, heartbeat, relocatable_prefix_len, validate_relocatable_x64, HookState,
        HOOK_LEASE,
    };

    const TARGET: usize = 0x1000;
    const ALLOCATION: usize = 0x2000;
    const SIGNATURE: &str = "90 90 90 90 90 90 90 90 90 90 90 90 90 90 C3 90";
    const SECOND_SIGNATURE: &str = "90 90 90 90 90 90 90 90 90 90 90 90 90 90 C3 C3";
    const LONG_SIGNATURE: &str = concat!(
        "90 90 90 90 90 90 90 90 90 90 90 90 90 90 C3 90 ",
        "90 90 90 90 90 90 90 90 90 90 90 90 90 90 C3 C3"
    );

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Failure {
        Allocate,
        TrampolineWrite,
        TrampolineFlush,
        TargetProtect,
        TargetWrite,
        TargetFlush,
        TargetRestore,
        Free,
    }

    struct Data {
        primary: Vec<u8>,
        allocations: BTreeMap<usize, Vec<u8>>,
        target_protection: MemoryProtection,
        next_allocation: usize,
        failures: Vec<Failure>,
    }

    #[derive(Clone)]
    pub(crate) struct Backend(Arc<Mutex<Data>>);

    #[derive(Clone, Copy)]
    pub(crate) struct Handle;

    #[derive(Clone, Copy)]
    pub(crate) struct Thread;

    impl Backend {
        pub(crate) fn new(failure: Option<Failure>) -> Self {
            Self::with_failures(failure.into_iter().collect())
        }

        fn with_primary(primary: Vec<u8>, failures: Vec<Failure>) -> Self {
            Self(Arc::new(Mutex::new(Data {
                primary,
                allocations: BTreeMap::new(),
                target_protection: MemoryProtection::ReadOnly,
                next_allocation: ALLOCATION,
                failures,
            })))
        }

        fn with_failures(failures: Vec<Failure>) -> Self {
            Self::with_primary(
                vec![
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0xc3, 0xc3,
                ],
                failures,
            )
        }

        pub(crate) fn core(failure: Option<Failure>) -> Self {
            let mut primary = Vec::new();
            for marker in 1..=6 {
                primary.extend_from_slice(&[
                    0xb8, marker, 0xd0, 0xc0, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0xc3,
                ]);
            }
            Self::with_primary(primary, failure.into_iter().collect())
        }

        pub(crate) fn primary(&self) -> Vec<u8> {
            self.0.lock().expect("data lock").primary.clone()
        }

        pub(crate) fn corrupt_primary_byte(&self, offset: usize) {
            let mut data = self.0.lock().expect("data lock");
            data.primary[offset] ^= 0xff;
        }

        pub(crate) fn allocation_count(&self) -> usize {
            self.0.lock().expect("data lock").allocations.len()
        }
    }

    fn failure(message: &str) -> ProcessBackendError {
        ProcessBackendError::new(ProcessBackendErrorKind::Native, message)
    }

    fn take_failure(data: &mut Data, expected: Failure) -> bool {
        if let Some(index) = data
            .failures
            .iter()
            .position(|actual| *actual as u8 == expected as u8)
        {
            data.failures.remove(index);
            true
        } else {
            false
        }
    }

    impl ProcessBackend for Backend {
        type Handle = Handle;

        fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
            Ok(vec![process()])
        }

        fn open_process(
            &self,
            _pid: u32,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            Ok(OpenedProcess {
                handle: Handle,
                process: process(),
            })
        }

        fn open_process_for_access(
            &self,
            pid: u32,
            _access_mode: ProcessAccessMode,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            self.open_process(pid)
        }

        fn validate_process(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<(), ProcessBackendError> {
            Ok(())
        }

        fn enumerate_modules(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<Vec<deimos_core::process::ModuleDescriptor>, ProcessBackendError> {
            Ok(Vec::new())
        }
    }

    impl MemoryBackend for Backend {
        fn enumerate_memory_regions(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<Vec<MemoryRegionDescriptor>, ProcessBackendError> {
            Ok(vec![MemoryRegionDescriptor {
                base_address: format!("{TARGET:#x}"),
                size: self.0.lock().expect("data lock").primary.len(),
                protection: MemoryProtection::ReadOnly,
            }])
        }

        fn read_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
            size: usize,
        ) -> Result<Vec<u8>, ProcessBackendError> {
            let data = self.0.lock().expect("data lock");
            let end_outside_primary = match address.checked_add(size) {
                Some(end) => end > TARGET + data.primary.len(),
                None => true,
            };
            if address < TARGET || end_outside_primary {
                return Err(failure("read range"));
            }
            Ok(data.primary[address - TARGET..address - TARGET + size].to_vec())
        }
    }

    impl MutationBackend for Backend {
        type ThreadHandle = Thread;

        fn write_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
            bytes: &[u8],
        ) -> Result<(), ProcessBackendError> {
            let mut data = self.0.lock().expect("data lock");
            if address == ALLOCATION && take_failure(&mut data, Failure::TrampolineWrite) {
                return Err(failure("forced trampoline write failure"));
            }
            let target_range = address >= TARGET && address < TARGET + data.primary.len();
            if target_range && take_failure(&mut data, Failure::TargetWrite) {
                return Err(failure("forced target write failure"));
            }
            if address >= TARGET && address < TARGET + data.primary.len() {
                let offset = address - TARGET;
                let out_of_range = match offset.checked_add(bytes.len()) {
                    Some(end) => end > data.primary.len(),
                    None => true,
                };
                if out_of_range {
                    return Err(failure("target write range"));
                }
                data.primary[offset..offset + bytes.len()].copy_from_slice(bytes);
                return Ok(());
            }
            let allocation = data
                .allocations
                .get_mut(&address)
                .ok_or_else(|| failure("allocation write range"))?;
            if bytes.len() > allocation.len() {
                return Err(failure("allocation write range"));
            }
            allocation[..bytes.len()].copy_from_slice(bytes);
            Ok(())
        }

        fn allocate_memory(
            &self,
            _handle: &Self::Handle,
            size: usize,
            _protection: MemoryProtection,
        ) -> Result<usize, ProcessBackendError> {
            let mut data = self.0.lock().expect("data lock");
            if take_failure(&mut data, Failure::Allocate) {
                return Err(failure("forced allocation failure"));
            }
            let address = data.next_allocation;
            data.next_allocation += 0x1000;
            data.allocations.insert(address, vec![0; size]);
            Ok(address)
        }

        fn free_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
        ) -> Result<(), ProcessBackendError> {
            let mut data = self.0.lock().expect("data lock");
            if take_failure(&mut data, Failure::Free) {
                return Err(failure("forced allocation free failure"));
            }
            data.allocations
                .remove(&address)
                .map(|_| ())
                .ok_or_else(|| failure("allocation free range"))
        }

        fn protect_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
            _size: usize,
            protection: MemoryProtection,
        ) -> Result<MemoryProtection, ProcessBackendError> {
            let mut data = self.0.lock().expect("data lock");
            let target_range = address >= TARGET && address < TARGET + data.primary.len();
            if target_range
                && protection == MemoryProtection::ExecuteReadWrite
                && take_failure(&mut data, Failure::TargetProtect)
            {
                return Err(failure("forced target protect failure"));
            }
            if target_range
                && protection == MemoryProtection::ReadOnly
                && take_failure(&mut data, Failure::TargetRestore)
            {
                return Err(failure("forced target restore failure"));
            }
            let previous = data.target_protection;
            data.target_protection = protection;
            Ok(previous)
        }

        fn start_remote_thread(
            &self,
            _handle: &Self::Handle,
            _start_address: usize,
            _parameter: Option<usize>,
        ) -> Result<StartedRemoteThread<Self::ThreadHandle>, ProcessBackendError> {
            Err(failure("not used by hooks"))
        }

        fn poll_remote_thread(
            &self,
            _thread: &Self::ThreadHandle,
            _wait_timeout_ms: u32,
        ) -> Result<RemoteThreadPoll, ProcessBackendError> {
            Err(failure("not used by hooks"))
        }

        fn flush_instruction_cache(
            &self,
            _handle: &Self::Handle,
            address: usize,
            _size: usize,
        ) -> Result<(), ProcessBackendError> {
            let mut data = self.0.lock().expect("data lock");
            let failure_stage = if address >= ALLOCATION {
                Failure::TrampolineFlush
            } else {
                Failure::TargetFlush
            };
            if take_failure(&mut data, failure_stage) {
                return Err(failure("forced instruction-cache flush failure"));
            }
            Ok(())
        }
    }

    fn process() -> ProcessDescriptor {
        let path = r"C:\\fixture\\deimos-memory-fixture.exe".to_string();
        ProcessDescriptor {
            pid: 7,
            name: "deimos-memory-fixture.exe".to_string(),
            kind: ProcessKind::MemoryFixture,
            executable_path: Some(path.clone()),
            identity: Some(ProcessIdentity {
                pid: 7,
                creation_time_100ns: "1".to_string(),
                executable_path: path,
            }),
        }
    }

    pub(crate) fn registry(
        backend: &Backend,
    ) -> (
        ProcessSessionRegistry<Handle>,
        deimos_core::process::ProcessSessionId,
    ) {
        let mut sessions = ProcessSessionRegistry::new();
        let session = sessions
            .open(
                backend,
                &OpenProcessRequest {
                    pid: 7,
                    expected_identity: None,
                    access_mode: ProcessAccessMode::Mutation,
                },
            )
            .expect("mutation session");
        (sessions, session.session_id)
    }

    fn request(session_id: deimos_core::process::ProcessSessionId) -> HookActivateRequest {
        HookActivateRequest {
            session_id,
            hook_key: "fixture.detour".to_string(),
            signature: SIGNATURE.to_string(),
            scope: MemoryScanScope::Process,
            payload: vec![0x90],
        }
    }

    fn second_request(session_id: deimos_core::process::ProcessSessionId) -> HookActivateRequest {
        HookActivateRequest {
            session_id,
            hook_key: "fixture.second".to_string(),
            signature: SECOND_SIGNATURE.to_string(),
            scope: MemoryScanScope::Process,
            payload: vec![0x90],
        }
    }

    #[test]
    fn absolute_detours_preserve_registers_and_pad_the_full_overwrite() {
        let detour = build_detour(0x1122_3344_5566_7788, 17);
        assert_eq!(&detour[..6], &[0xff, 0x25, 0, 0, 0, 0]);
        assert_eq!(&detour[6..14], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&detour[14..], &[0x90; 3]);
    }

    #[test]
    fn trampoline_falls_through_saved_bytes_then_continuation() {
        let trampoline = build_trampoline(&[0x90], &[1, 2, 3], 0x1234);
        assert_eq!(&trampoline[..4], &[0x90, 1, 2, 3]);
        assert_eq!(&trampoline[4..10], &[0xff, 0x25, 0, 0, 0, 0]);
        assert_eq!(&trampoline[10..], &0x1234u64.to_le_bytes());
    }

    #[test]
    fn lease_is_the_documented_thirty_seconds() {
        assert_eq!(HOOK_LEASE.as_secs(), 30);
    }

    #[test]
    fn relocation_guard_accepts_safe_code_and_rejects_relative_operands() {
        assert!(validate_relocatable_x64(&[
            0xc7, 0x01, 1, 0, 0, 0, 0xc7, 0x41, 4, 0, 0, 0, 0, 0x31, 0xc0, 0xc3,
        ])
        .is_ok());
        assert_eq!(
            validate_relocatable_x64(&[0xe8, 0, 0, 0, 0])
                .expect_err("relative call must be rejected")
                .into_rpc_error(1, "hook.activate")
                .code,
            RpcErrorCode::InvalidRequest
        );
        assert_eq!(
            relocatable_prefix_len(
                &[
                    0xf2, 0x0f, 0x10, 0x40, 0x58, // movsd xmm0,[rax+58]
                    0xf2, 0x0f, 0x10, 0x48, 0x60, // movsd xmm1,[rax+60]
                    0xf2, 0x0f, 0x10, 0x50, 0x68, // movsd xmm2,[rax+68]
                    0xc3,
                ],
                14,
            )
            .expect("SIMD core-hook instructions should decode"),
            15
        );
        assert_eq!(
            validate_relocatable_x64(&[0x48, 0x8b, 0x05, 0, 0, 0, 0])
                .expect_err("RIP-relative read must be rejected")
                .into_rpc_error(2, "hook.activate")
                .code,
            RpcErrorCode::InvalidRequest
        );
        assert!(validate_relocatable_x64(&[
            0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, // mov rax, imm64
            0x90,
        ])
        .is_ok());
        assert!(
            validate_relocatable_x64(&[0x48, 0xb8, 1, 2, 3, 4])
                .expect_err("truncated movabs must be rejected")
                .into_rpc_error(3, "hook.activate")
                .code
                == RpcErrorCode::InvalidRequest
        );
    }

    #[test]
    fn activation_is_idempotent_and_deactivation_releases_its_allocation() {
        let backend = Backend::new(None);
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let now = Instant::now();
        let first = activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request(session_id.clone()),
            now,
        )
        .expect("activation");
        assert_ne!(backend.primary(), before);
        assert_eq!(backend.allocation_count(), 1);
        let duplicate = activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request(session_id.clone()),
            now + HOOK_LEASE,
        )
        .expect("duplicate activation");
        assert_eq!(duplicate.allocation_id, first.allocation_id);
        assert_eq!(backend.allocation_count(), 1);
        assert_eq!(hooks.tracked_count(&session_id), 1);
        let response = deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &HookDeactivateRequest {
                session_id: session_id.clone(),
                hook_key: "fixture.detour".to_string(),
            },
        )
        .expect("deactivate");
        assert!(response.deactivated && response.allocation_released);
        assert_eq!(backend.primary(), before);
        assert_eq!(backend.allocation_count(), 0);
        assert_eq!(mutations.tracked_count(&session_id), 0);
        assert!(
            !deactivate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &HookDeactivateRequest {
                    session_id,
                    hook_key: "fixture.detour".to_string()
                }
            )
            .expect("idempotent deactivation")
            .deactivated
        );
    }

    #[test]
    fn template_overwrite_does_not_modify_verified_signature_suffix() {
        let backend = Backend::new(None);
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let request = HookActivateRequest {
            session_id: session_id.clone(),
            hook_key: "fixture.long-signature".to_string(),
            signature: LONG_SIGNATURE.to_string(),
            scope: MemoryScanScope::Process,
            payload: vec![0x90],
        };

        activate_template(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request,
            0,
            Some(16),
            Instant::now(),
        )
        .expect("template activation");

        let active = backend.primary();
        assert_ne!(&active[..16], &before[..16]);
        assert_eq!(&active[16..], &before[16..]);

        deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &HookDeactivateRequest {
                session_id,
                hook_key: request.hook_key,
            },
        )
        .expect("template deactivation");
        assert_eq!(backend.primary(), before);
    }

    #[test]
    fn every_activation_failure_rolls_back_fixture_bytes_and_allocations() {
        for failure_stage in [
            Failure::Allocate,
            Failure::TrampolineWrite,
            Failure::TrampolineFlush,
            Failure::TargetProtect,
            Failure::TargetWrite,
            Failure::TargetFlush,
            Failure::TargetRestore,
        ] {
            let backend = Backend::new(Some(failure_stage));
            let before = backend.primary();
            let (mut sessions, session_id) = registry(&backend);
            let mut mutations = MutationState::new();
            let mut hooks = HookState::default();
            assert!(activate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &request(session_id.clone()),
                Instant::now()
            )
            .is_err());
            assert_eq!(
                backend.primary(),
                before,
                "failure stage must leave fixture unchanged"
            );
            assert_eq!(
                backend.allocation_count(),
                0,
                "failure stage must free its allocation"
            );
            assert_eq!(mutations.tracked_count(&session_id), 0);
            assert_eq!(hooks.tracked_count(&session_id), 0);
        }
    }

    #[test]
    fn failed_cleanup_retains_a_retryable_hook_record_and_allocation() {
        let backend = Backend::with_failures(vec![Failure::TargetFlush, Failure::Free]);
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        assert!(activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request(session_id.clone()),
            Instant::now(),
        )
        .is_err());
        assert_eq!(hooks.tracked_count(&session_id), 1);
        assert_eq!(mutations.tracked_count(&session_id), 1);
        assert_eq!(backend.allocation_count(), 1);
        deactivate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &HookDeactivateRequest {
                session_id: session_id.clone(),
                hook_key: "fixture.detour".to_string(),
            },
        )
        .expect("retained recovery record should be retryable");
        assert_eq!(backend.primary(), before);
        assert_eq!(hooks.tracked_count(&session_id), 0);
        assert_eq!(mutations.tracked_count(&session_id), 0);
    }

    #[test]
    fn one_cleanup_failure_does_not_block_later_hooks_in_the_same_session() {
        let backend = Backend::with_failures(vec![Failure::Free]);
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request(session_id.clone()),
            Instant::now(),
        )
        .expect("first hook activation");
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &second_request(session_id.clone()),
            Instant::now(),
        )
        .expect("second hook activation");
        let error = cleanup_session(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        )
        .expect_err("one forced release failure should be reported after every hook is attempted");
        assert_eq!(
            error.into_rpc_error(1, "hook.cleanup").code,
            RpcErrorCode::MemoryWriteFailed
        );
        assert_eq!(hooks.tracked_count(&session_id), 1);
        assert_eq!(mutations.tracked_count(&session_id), 1);
        cleanup_session(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        )
        .expect("the retained hook should clean up on retry");
        assert_eq!(hooks.tracked_count(&session_id), 0);
        assert_eq!(mutations.tracked_count(&session_id), 0);
    }

    #[test]
    fn heartbeat_renews_and_expiry_or_session_cleanup_restores_memory() {
        let backend = Backend::new(None);
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let start = Instant::now();
        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request(session_id.clone()),
            start,
        )
        .expect("activation");
        heartbeat(
            &mut hooks,
            &HookHeartbeatRequest {
                session_id: session_id.clone(),
                hook_key: "fixture.detour".to_string(),
            },
            start + HOOK_LEASE - std::time::Duration::from_secs(1),
        )
        .expect("heartbeat");
        assert_eq!(
            expire_at(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                start + HOOK_LEASE
            )
            .expect("expiry sweep"),
            0
        );
        assert_eq!(
            expire_at(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                start + HOOK_LEASE * 2
            )
            .expect("expiry sweep"),
            1
        );
        assert_eq!(backend.primary(), before);
        assert_eq!(backend.allocation_count(), 0);
        assert_eq!(hooks.tracked_count(&session_id), 0);

        activate(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &request(session_id.clone()),
            start,
        )
        .expect("reactivation");
        cleanup_session(
            &mut sessions,
            &backend,
            &mut mutations,
            &mut hooks,
            &session_id,
        )
        .expect("session cleanup");
        assert_eq!(backend.primary(), before);
        assert_eq!(backend.allocation_count(), 0);
    }

    #[test]
    fn bad_or_ambiguous_signatures_do_not_allocate_or_modify_memory() {
        let backend = Backend::new(None);
        let before = backend.primary();
        let (mut sessions, session_id) = registry(&backend);
        let mut mutations = MutationState::new();
        let mut hooks = HookState::default();
        let mut short = request(session_id.clone());
        short.signature = "10 11".to_string();
        assert_eq!(
            activate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &short,
                Instant::now()
            )
            .expect_err("short signature")
            .into_rpc_error(1, "hook.activate")
            .code,
            RpcErrorCode::MemoryPatternInvalid
        );
        let mut ambiguous = request(session_id.clone());
        ambiguous.signature = "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??".to_string();
        assert_eq!(
            activate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &ambiguous,
                Instant::now()
            )
            .expect_err("ambiguous signature")
            .into_rpc_error(2, "hook.activate")
            .code,
            RpcErrorCode::MemoryAmbiguousMatch
        );
        let mut stale = request(session_id);
        stale.signature = "AA BB CC DD EE FF 00 01 02 03 04 05 06 07".to_string();
        assert_eq!(
            activate(
                &mut sessions,
                &backend,
                &mut mutations,
                &mut hooks,
                &stale,
                Instant::now()
            )
            .expect_err("stale signature")
            .into_rpc_error(3, "hook.activate")
            .code,
            RpcErrorCode::MemoryRequiredMatchNotFound
        );
        assert_eq!(backend.primary(), before);
        assert_eq!(backend.allocation_count(), 0);
    }
}
