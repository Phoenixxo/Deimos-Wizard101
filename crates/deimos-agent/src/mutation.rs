use std::collections::{BTreeMap, HashMap, HashSet};

use deimos_core::memory::{
    MemoryAllocateRequest, MemoryAllocationResponse, MemoryFreeRequest, MemoryFreeResponse,
    MemoryProtectRequest, MemoryProtectResponse, MemoryProtection, MemoryWriteRequest,
    MemoryWriteResponse, RemoteThreadStartRequest, RemoteThreadStartResponse, MAX_ALLOCATION_BYTES,
    MAX_MEMORY_WRITE_BYTES, MAX_REMOTE_THREAD_WAIT_MS,
};
use deimos_core::process::ProcessSessionId;
use deimos_core::rpc::{RpcError, RpcErrorCode};

use crate::process::{
    MutationBackend, ProcessApiError, ProcessBackendError, ProcessSessionRegistry,
};

#[derive(Clone, Debug)]
struct TrackedAllocation {
    address: usize,
    size: usize,
}

struct TrackedThread<T> {
    thread_id: u32,
    handle: T,
}

pub struct MutationState<T> {
    allocations: HashMap<ProcessSessionId, BTreeMap<String, TrackedAllocation>>,
    threads: HashMap<ProcessSessionId, BTreeMap<u32, TrackedThread<T>>>,
    next_allocation: u64,
}

impl<T> Default for MutationState<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> MutationState<T> {
    pub fn new() -> Self {
        Self {
            allocations: HashMap::new(),
            threads: HashMap::new(),
            next_allocation: 1,
        }
    }

    fn next_allocation_id(&mut self) -> String {
        let id = format!("allocation-{:016x}", self.next_allocation);
        self.next_allocation = self.next_allocation.saturating_add(1);
        id
    }

    pub fn tracked_count(&self, session_id: &ProcessSessionId) -> usize {
        self.allocations.get(session_id).map_or(0, BTreeMap::len)
    }

    fn forget_session(&mut self, session_id: &ProcessSessionId) {
        self.allocations.remove(session_id);
        self.threads.remove(session_id);
    }

    #[cfg(test)]
    fn tracked_thread_count(&self, session_id: &ProcessSessionId) -> usize {
        self.threads.get(session_id).map_or(0, BTreeMap::len)
    }
}

#[derive(Debug)]
pub enum MutationApiError {
    Process(ProcessApiError),
    Request {
        code: RpcErrorCode,
        message: String,
        details: BTreeMap<String, String>,
    },
}

impl From<ProcessApiError> for MutationApiError {
    fn from(error: ProcessApiError) -> Self {
        Self::Process(error)
    }
}

impl From<ProcessBackendError> for MutationApiError {
    fn from(error: ProcessBackendError) -> Self {
        Self::backend(RpcErrorCode::Internal, error)
    }
}

impl MutationApiError {
    fn request(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self::Request {
            code,
            message: message.into(),
            details: BTreeMap::new(),
        }
    }

    fn backend(code: RpcErrorCode, error: ProcessBackendError) -> Self {
        let mut details = BTreeMap::new();
        if let Some(native_code) = error.native_code {
            details.insert("native_code".to_string(), native_code.to_string());
        }
        Self::Request {
            code,
            message: error.message,
            details,
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

    fn summary(&self) -> String {
        match self {
            Self::Process(error) => error.message().to_string(),
            Self::Request { message, .. } => message.clone(),
        }
    }
}

pub fn write<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    request: &MemoryWriteRequest,
) -> Result<MemoryWriteResponse, MutationApiError> {
    if request.bytes.is_empty() || request.bytes.len() > MAX_MEMORY_WRITE_BYTES {
        return Err(MutationApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("memory writes must contain between 1 and {MAX_MEMORY_WRITE_BYTES} bytes"),
        ));
    }
    let address = validate_range(&request.address, request.bytes.len())?;
    let execution = sessions.with_mutation_session_effect(
        backend,
        &request.session_id,
        |backend, handle, _| {
            backend
                .write_memory(handle, address, &request.bytes)
                .map_err(|error| MutationApiError::backend(RpcErrorCode::MemoryWriteFailed, error))
        },
    )?;
    if let Some(error) = execution.validation_error {
        return Err(MutationApiError::Process(
            error.with_detail("write_completed", "true"),
        ));
    }
    Ok(MemoryWriteResponse {
        session_id: request.session_id.clone(),
        address: format_address(address),
        bytes_written: request.bytes.len(),
    })
}

/// Flushes code that was just written to a remote process before it can be
/// reached by a detour.  It intentionally shares mutation-session validation
/// with writes so a stale process never receives a cache operation.
pub fn flush_instruction_cache<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    session_id: &ProcessSessionId,
    address: &str,
    size: usize,
) -> Result<(), MutationApiError> {
    let address = validate_range(address, size)?;
    let execution =
        sessions.with_mutation_session_effect(backend, session_id, |backend, handle, _| {
            backend
                .flush_instruction_cache(handle, address, size)
                .map_err(|error| MutationApiError::backend(RpcErrorCode::MemoryWriteFailed, error))
        })?;
    if let Some(error) = execution.validation_error {
        return Err(MutationApiError::Process(
            error.with_detail("instruction_cache_flushed", "true"),
        ));
    }
    Ok(())
}

pub fn allocate<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    state: &mut MutationState<B::ThreadHandle>,
    request: &MemoryAllocateRequest,
) -> Result<MemoryAllocationResponse, MutationApiError> {
    if request.size == 0 || request.size > MAX_ALLOCATION_BYTES {
        return Err(MutationApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("allocation size must be between 1 and {MAX_ALLOCATION_BYTES} bytes"),
        ));
    }
    if matches!(
        request.protection,
        MemoryProtection::CopyOnWrite | MemoryProtection::ExecuteCopyOnWrite
    ) {
        return Err(MutationApiError::request(
            RpcErrorCode::InvalidRequest,
            "copy-on-write protection is not valid for private remote allocations",
        ));
    }
    let allocation_id = state.next_allocation_id();
    let execution = sessions.with_mutation_session_effect(
        backend,
        &request.session_id,
        |backend, handle, _| {
            backend
                .allocate_memory(handle, request.size, request.protection)
                .map_err(|error| {
                    MutationApiError::backend(RpcErrorCode::MemoryAllocationFailed, error)
                })
        },
    )?;
    state
        .allocations
        .entry(request.session_id.clone())
        .or_default()
        .insert(
            allocation_id.clone(),
            TrackedAllocation {
                address: execution.value,
                size: request.size,
            },
        );
    if let Some(error) = execution.validation_error {
        return Err(MutationApiError::Process(
            error
                .with_detail("allocation_id", allocation_id.clone())
                .with_detail("allocation_address", format_address(execution.value))
                .with_detail("allocation_tracked", "true"),
        ));
    }
    Ok(MemoryAllocationResponse {
        session_id: request.session_id.clone(),
        allocation_id,
        address: format_address(execution.value),
        size: request.size,
        protection: request.protection,
    })
}

pub fn free<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    state: &mut MutationState<B::ThreadHandle>,
    request: &MemoryFreeRequest,
) -> Result<MemoryFreeResponse, MutationApiError> {
    let allocation = state
        .allocations
        .get(&request.session_id)
        .and_then(|allocations| allocations.get(&request.allocation_id))
        .cloned()
        .ok_or_else(|| {
            MutationApiError::request(
                RpcErrorCode::InvalidRequest,
                format!(
                    "allocation {} is not tracked by process session {}",
                    request.allocation_id, request.session_id.0
                ),
            )
            .with_detail("allocation_id", request.allocation_id.clone())
            .with_detail("session_id", request.session_id.0.clone())
        })?;
    refresh_session_threads(backend, state, &request.session_id)?;
    if session_has_pending_threads(state, &request.session_id) {
        return Err(MutationApiError::request(
            RpcErrorCode::RemoteThreadFailed,
            format!(
                "allocation {} cannot be released while this session owns a running or unqueryable remote thread",
                request.allocation_id
            ),
        )
        .with_detail("allocation_id", request.allocation_id.clone())
        .with_detail("session_id", request.session_id.0.clone()));
    }
    let execution = sessions.with_mutation_session_effect(
        backend,
        &request.session_id,
        |backend, handle, _| {
            backend
                .free_memory(handle, allocation.address)
                .map_err(|error| {
                    MutationApiError::backend(RpcErrorCode::MemoryAllocationFailed, error)
                })
        },
    )?;
    remove_allocation(state, &request.session_id, &request.allocation_id);
    if let Some(error) = execution.validation_error {
        return Err(MutationApiError::Process(
            error
                .with_detail("allocation_id", request.allocation_id.clone())
                .with_detail("allocation_released", "true"),
        ));
    }
    Ok(MemoryFreeResponse {
        session_id: request.session_id.clone(),
        allocation_id: request.allocation_id.clone(),
        address: format_address(allocation.address),
        size: allocation.size,
    })
}

pub fn protect<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    request: &MemoryProtectRequest,
) -> Result<MemoryProtectResponse, MutationApiError> {
    let address = validate_range(&request.address, request.size)?;
    let execution = sessions.with_mutation_session_effect(
        backend,
        &request.session_id,
        |backend, handle, _| {
            backend
                .protect_memory(handle, address, request.size, request.protection)
                .map_err(|error| {
                    MutationApiError::backend(RpcErrorCode::MemoryProtectionFailed, error)
                })
        },
    )?;
    if let Some(error) = execution.validation_error {
        return Err(MutationApiError::Process(
            error.with_detail("protection_changed", "true"),
        ));
    }
    Ok(MemoryProtectResponse {
        session_id: request.session_id.clone(),
        address: format_address(address),
        size: request.size,
        previous_protection: execution.value,
        protection: request.protection,
    })
}

pub fn start_thread<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    state: &mut MutationState<B::ThreadHandle>,
    request: &RemoteThreadStartRequest,
) -> Result<RemoteThreadStartResponse, MutationApiError> {
    if request.wait_timeout_ms == 0 {
        return Err(MutationApiError::request(
            RpcErrorCode::InvalidRequest,
            "remote threads require a bounded non-zero wait timeout; asynchronous thread ownership belongs to transactional hook management",
        ));
    }
    if request.wait_timeout_ms > MAX_REMOTE_THREAD_WAIT_MS {
        return Err(MutationApiError::request(
            RpcErrorCode::MemoryLimitExceeded,
            format!("remote-thread wait timeout cannot exceed {MAX_REMOTE_THREAD_WAIT_MS} ms"),
        ));
    }
    let start_address = validate_address(&request.start_address)?;
    let parameter = request
        .parameter
        .as_deref()
        .map(validate_address)
        .transpose()?;
    let (flush_address, flush_size) =
        containing_allocation(state, &request.session_id, start_address)
            .map(|allocation| (allocation.address, allocation.size))
            .unwrap_or((0, 0));
    let execution = sessions.with_mutation_session_effect(
        backend,
        &request.session_id,
        |backend, handle, _| {
            backend
                .flush_instruction_cache(handle, flush_address, flush_size)
                .map_err(|error| {
                    MutationApiError::backend(RpcErrorCode::RemoteThreadFailed, error)
                })?;
            backend
                .start_remote_thread(handle, start_address, parameter)
                .map_err(|error| MutationApiError::backend(RpcErrorCode::RemoteThreadFailed, error))
        },
    )?;
    let thread_id = execution.value.thread_id;
    state
        .threads
        .entry(request.session_id.clone())
        .or_default()
        .insert(
            thread_id,
            TrackedThread {
                thread_id,
                handle: execution.value.handle,
            },
        );
    if let Some(error) = execution.validation_error {
        return Err(MutationApiError::Process(
            error
                .with_detail("thread_id", thread_id.to_string())
                .with_detail("thread_tracked", "true"),
        ));
    }
    let result = poll_thread(
        backend,
        state,
        &request.session_id,
        thread_id,
        request.wait_timeout_ms,
    )
    .map_err(|error| {
        error
            .with_detail("thread_id", thread_id.to_string())
            .with_detail("thread_tracked", "true")
    })?;
    Ok(RemoteThreadStartResponse {
        session_id: request.session_id.clone(),
        thread_id,
        completed: result.completed,
        exit_code: result.exit_code,
    })
}

pub fn cleanup_session<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    state: &mut MutationState<B::ThreadHandle>,
    session_id: &ProcessSessionId,
) -> Result<(), MutationApiError> {
    match sessions.status(backend, session_id) {
        Err(error) if error.is_process_exited() => {
            state.forget_session(session_id);
            return Ok(());
        }
        Err(error) => return Err(MutationApiError::Process(error)),
        Ok(_) => {}
    }

    let mut failures = Vec::new();
    let thread_ids = state
        .threads
        .get(session_id)
        .map(|threads| threads.keys().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    for thread_id in thread_ids {
        if let Err(error) = poll_thread(backend, state, session_id, thread_id, 0) {
            failures.push(format!("thread {thread_id}: {}", error.summary()));
        }
    }

    let allocation_ids = state
        .allocations
        .get(session_id)
        .map(|allocations| allocations.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    for allocation_id in allocation_ids.into_iter().rev() {
        if session_has_pending_threads(state, session_id) {
            failures.push(format!(
                "allocation {allocation_id}: session still owns a running or unqueryable remote thread"
            ));
            continue;
        }
        let allocation = state
            .allocations
            .get(session_id)
            .and_then(|allocations| allocations.get(&allocation_id))
            .cloned()
            .expect("collected allocation must remain tracked");
        let release =
            sessions.with_mutation_session_effect(backend, session_id, |backend, handle, _| {
                backend
                    .free_memory(handle, allocation.address)
                    .map_err(|error| {
                        MutationApiError::backend(RpcErrorCode::MemoryAllocationFailed, error)
                    })
            });
        match release {
            Ok(execution) => {
                remove_allocation(state, session_id, &allocation_id);
                if let Some(error) = execution.validation_error {
                    if error.is_process_exited() {
                        state.forget_session(session_id);
                        return Ok(());
                    }
                    failures.push(format!(
                        "allocation {allocation_id} released but validation failed: {}",
                        error.message()
                    ));
                }
            }
            Err(MutationApiError::Process(error)) if error.is_process_exited() => {
                // Windows releases a process's virtual allocations when that
                // process exits, so stale tracking can be discarded safely.
                state.forget_session(session_id);
                return Ok(());
            }
            Err(error) => {
                failures.push(format!("allocation {allocation_id}: {}", error.summary()));
            }
        }
    }
    if let Some(threads) = state.threads.get(session_id) {
        for thread in threads.values() {
            failures.push(format!(
                "thread {}: completion is still pending; its handle remains tracked",
                thread.thread_id
            ));
        }
    }
    let failure_code = if state
        .threads
        .get(session_id)
        .is_some_and(|threads| !threads.is_empty())
    {
        RpcErrorCode::RemoteThreadFailed
    } else {
        RpcErrorCode::MemoryAllocationFailed
    };
    cleanup_failures(session_id, failures, failure_code)
}

pub fn cleanup_all<B: MutationBackend>(
    sessions: &mut ProcessSessionRegistry<B::Handle>,
    backend: &B,
    state: &mut MutationState<B::ThreadHandle>,
) -> Result<(), MutationApiError> {
    let session_ids = state
        .allocations
        .keys()
        .chain(state.threads.keys())
        .cloned()
        .collect::<HashSet<_>>();
    let mut failures = Vec::new();
    for session_id in session_ids {
        if let Err(error) = cleanup_session(sessions, backend, state, &session_id) {
            failures.push(format!("session {}: {}", session_id.0, error.summary()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(MutationApiError::request(
            RpcErrorCode::MemoryAllocationFailed,
            format!(
                "mutation cleanup failed for {} session(s); retained resources can be retried",
                failures.len()
            ),
        )
        .with_detail("cleanup_failures", failures.join("; ")))
    }
}

fn remove_allocation<T>(
    state: &mut MutationState<T>,
    session_id: &ProcessSessionId,
    allocation_id: &str,
) {
    if let Some(allocations) = state.allocations.get_mut(session_id) {
        allocations.remove(allocation_id);
        if allocations.is_empty() {
            state.allocations.remove(session_id);
        }
    }
}

fn remove_thread<T>(state: &mut MutationState<T>, session_id: &ProcessSessionId, thread_id: u32) {
    if let Some(threads) = state.threads.get_mut(session_id) {
        threads.remove(&thread_id);
        if threads.is_empty() {
            state.threads.remove(session_id);
        }
    }
}

fn poll_thread<B: MutationBackend>(
    backend: &B,
    state: &mut MutationState<B::ThreadHandle>,
    session_id: &ProcessSessionId,
    thread_id: u32,
    wait_timeout_ms: u32,
) -> Result<crate::process::RemoteThreadPoll, MutationApiError> {
    let result = {
        let thread = state
            .threads
            .get(session_id)
            .and_then(|threads| threads.get(&thread_id))
            .ok_or_else(|| {
                MutationApiError::request(
                    RpcErrorCode::InvalidRequest,
                    format!("remote thread {thread_id} is not tracked"),
                )
            })?;
        backend
            .poll_remote_thread(&thread.handle, wait_timeout_ms)
            .map_err(|error| MutationApiError::backend(RpcErrorCode::RemoteThreadFailed, error))?
    };
    if result.completed {
        remove_thread(state, session_id, thread_id);
    }
    Ok(result)
}

fn containing_allocation<'a, T>(
    state: &'a MutationState<T>,
    session_id: &ProcessSessionId,
    address: usize,
) -> Option<&'a TrackedAllocation> {
    state
        .allocations
        .get(session_id)?
        .values()
        .find(|allocation| {
            allocation
                .address
                .checked_add(allocation.size)
                .is_some_and(|end| allocation.address <= address && address < end)
        })
}

fn session_has_pending_threads<T>(state: &MutationState<T>, session_id: &ProcessSessionId) -> bool {
    state
        .threads
        .get(session_id)
        .is_some_and(|threads| !threads.is_empty())
}

fn refresh_session_threads<B: MutationBackend>(
    backend: &B,
    state: &mut MutationState<B::ThreadHandle>,
    session_id: &ProcessSessionId,
) -> Result<(), MutationApiError> {
    let thread_ids = state
        .threads
        .get(session_id)
        .map(|threads| {
            threads
                .values()
                .map(|thread| thread.thread_id)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut failures = Vec::new();
    for thread_id in thread_ids {
        if let Err(error) = poll_thread(backend, state, session_id, thread_id, 0) {
            failures.push(format!("thread {thread_id}: {}", error.summary()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(MutationApiError::request(
            RpcErrorCode::RemoteThreadFailed,
            "one or more remote threads could not be queried; every allocation owned by the session remains tracked",
        )
        .with_detail("thread_failures", failures.join("; ")))
    }
}

fn cleanup_failures(
    session_id: &ProcessSessionId,
    failures: Vec<String>,
    code: RpcErrorCode,
) -> Result<(), MutationApiError> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(MutationApiError::request(
            code,
            format!(
                "mutation cleanup for session {} retained resources that are not yet safe to release",
                session_id.0
            ),
        )
        .with_detail("session_id", session_id.0.clone())
        .with_detail("cleanup_failures", failures.join("; ")))
    }
}

fn validate_address(text: &str) -> Result<usize, MutationApiError> {
    let value = text.strip_prefix("0x").ok_or_else(|| {
        MutationApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            format!("address {text:?} must use 0x-prefixed hexadecimal notation"),
        )
    })?;
    if value.is_empty() {
        return Err(MutationApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            "address must contain hexadecimal digits after 0x",
        ));
    }
    usize::from_str_radix(value, 16).map_err(|_| {
        MutationApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            format!("address {text:?} is not valid for this agent architecture"),
        )
    })
}

fn validate_range(text: &str, size: usize) -> Result<usize, MutationApiError> {
    if size == 0 {
        return Err(MutationApiError::request(
            RpcErrorCode::InvalidRequest,
            "memory range size must be greater than zero",
        ));
    }
    let address = validate_address(text)?;
    address.checked_add(size).ok_or_else(|| {
        MutationApiError::request(
            RpcErrorCode::MemoryInvalidAddress,
            format!("memory range at {text} with size {size} overflows the address space"),
        )
    })?;
    Ok(address)
}

fn format_address(address: usize) -> String {
    format!("{address:#x}")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use deimos_core::memory::{
        MemoryAllocateRequest, MemoryFreeRequest, MemoryProtectRequest, MemoryProtection,
        MemoryWriteRequest, RemoteThreadStartRequest,
    };
    use deimos_core::process::{
        ModuleDescriptor, OpenProcessRequest, ProcessAccessMode, ProcessDescriptor, ProcessIdentity,
    };
    use deimos_core::rpc::RpcErrorCode;

    use crate::process::{
        MemoryBackend, MutationBackend, OpenedProcess, ProcessBackend, ProcessBackendError,
        ProcessBackendErrorKind, ProcessSessionRegistry, RemoteThreadPoll, StartedRemoteThread,
    };

    use super::{allocate, cleanup_session, free, protect, start_thread, write, MutationState};

    const BASE: usize = 0x1000;

    #[derive(Default)]
    struct MockMutationData {
        primary: Vec<u8>,
        allocations: BTreeMap<usize, Vec<u8>>,
        protections: BTreeMap<usize, MemoryProtection>,
        next_allocation: usize,
        started_threads: usize,
        thread_completed: bool,
        validation_failure: bool,
    }

    #[derive(Clone)]
    struct MockMutationBackend {
        data: Arc<Mutex<MockMutationData>>,
    }

    #[derive(Clone, Copy)]
    struct MockHandle;

    #[derive(Clone, Copy)]
    struct MockThreadHandle {
        thread_id: u32,
    }

    impl MockMutationBackend {
        fn new() -> Self {
            Self {
                data: Arc::new(Mutex::new(MockMutationData {
                    primary: vec![0x55; 16],
                    next_allocation: 0x2000,
                    thread_completed: true,
                    ..MockMutationData::default()
                })),
            }
        }

        fn snapshot(&self) -> Vec<u8> {
            self.data.lock().expect("mock data lock").primary.clone()
        }
    }

    impl ProcessBackend for MockMutationBackend {
        type Handle = MockHandle;

        fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
            Ok(vec![mock_process()])
        }

        fn open_process(
            &self,
            _pid: u32,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            Ok(OpenedProcess {
                handle: MockHandle,
                process: mock_process(),
            })
        }

        fn open_process_for_access(
            &self,
            _pid: u32,
            _access_mode: ProcessAccessMode,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            self.open_process(7)
        }

        fn validate_process(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<(), ProcessBackendError> {
            if self.data.lock().expect("mock data lock").validation_failure {
                Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    "process identity could not be verified",
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
            Ok(Vec::new())
        }
    }

    impl MemoryBackend for MockMutationBackend {
        fn enumerate_memory_regions(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<Vec<deimos_core::memory::MemoryRegionDescriptor>, ProcessBackendError> {
            Ok(Vec::new())
        }

        fn read_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
            size: usize,
        ) -> Result<Vec<u8>, ProcessBackendError> {
            let data = self.data.lock().expect("mock data lock");
            read_mock_range(&data, address, size)
        }
    }

    impl MutationBackend for MockMutationBackend {
        type ThreadHandle = MockThreadHandle;

        fn write_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
            bytes: &[u8],
        ) -> Result<(), ProcessBackendError> {
            let mut data = self.data.lock().expect("mock data lock");
            if address >= BASE {
                let offset = address - BASE;
                let end = offset
                    .checked_add(bytes.len())
                    .ok_or_else(mock_range_error)?;
                if end <= data.primary.len() {
                    data.primary[offset..end].copy_from_slice(bytes);
                    return Ok(());
                }
            }
            for (allocation_base, allocation) in &mut data.allocations {
                if address >= *allocation_base {
                    let offset = address - *allocation_base;
                    let end = offset
                        .checked_add(bytes.len())
                        .ok_or_else(mock_range_error)?;
                    if end <= allocation.len() {
                        allocation[offset..end].copy_from_slice(bytes);
                        return Ok(());
                    }
                }
            }
            Err(mock_range_error())
        }

        fn allocate_memory(
            &self,
            _handle: &Self::Handle,
            size: usize,
            protection: MemoryProtection,
        ) -> Result<usize, ProcessBackendError> {
            let mut data = self.data.lock().expect("mock data lock");
            let address = data.next_allocation;
            data.next_allocation += 0x1000;
            data.allocations.insert(address, vec![0; size]);
            data.protections.insert(address, protection);
            Ok(address)
        }

        fn free_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
        ) -> Result<(), ProcessBackendError> {
            let mut data = self.data.lock().expect("mock data lock");
            if data.allocations.remove(&address).is_none() {
                return Err(mock_range_error());
            }
            data.protections.remove(&address);
            Ok(())
        }

        fn protect_memory(
            &self,
            _handle: &Self::Handle,
            address: usize,
            _size: usize,
            protection: MemoryProtection,
        ) -> Result<MemoryProtection, ProcessBackendError> {
            let mut data = self.data.lock().expect("mock data lock");
            let previous = data
                .protections
                .insert(address, protection)
                .unwrap_or(MemoryProtection::ReadWrite);
            Ok(previous)
        }

        fn start_remote_thread(
            &self,
            _handle: &Self::Handle,
            _start_address: usize,
            _parameter: Option<usize>,
        ) -> Result<StartedRemoteThread<Self::ThreadHandle>, ProcessBackendError> {
            let mut data = self.data.lock().expect("mock data lock");
            data.started_threads += 1;
            let thread_id = data.started_threads as u32;
            Ok(StartedRemoteThread {
                thread_id,
                handle: MockThreadHandle { thread_id },
            })
        }

        fn poll_remote_thread(
            &self,
            thread: &Self::ThreadHandle,
            _wait_timeout_ms: u32,
        ) -> Result<RemoteThreadPoll, ProcessBackendError> {
            let data = self.data.lock().expect("mock data lock");
            assert!(
                thread.thread_id <= data.started_threads as u32,
                "only started mock threads may be polled"
            );
            Ok(RemoteThreadPoll {
                completed: data.thread_completed,
                exit_code: data.thread_completed.then_some(0),
            })
        }

        fn flush_instruction_cache(
            &self,
            _handle: &Self::Handle,
            _address: usize,
            _size: usize,
        ) -> Result<(), ProcessBackendError> {
            Ok(())
        }
    }

    fn mock_process() -> ProcessDescriptor {
        let path = r"C:\fixture\deimos-memory-fixture.exe".to_string();
        ProcessDescriptor {
            pid: 7,
            name: "deimos-memory-fixture.exe".to_string(),
            kind: deimos_core::process::ProcessKind::MemoryFixture,
            executable_path: Some(path.clone()),
            identity: Some(ProcessIdentity {
                pid: 7,
                creation_time_100ns: "1".to_string(),
                executable_path: path,
            }),
        }
    }

    fn registry(
        backend: &MockMutationBackend,
        access_mode: ProcessAccessMode,
    ) -> (
        ProcessSessionRegistry<MockHandle>,
        deimos_core::process::ProcessSessionId,
    ) {
        let mut sessions = ProcessSessionRegistry::new();
        let session = sessions
            .open(
                backend,
                &OpenProcessRequest {
                    pid: 7,
                    expected_identity: None,
                    access_mode,
                },
            )
            .expect("mock session should open");
        (sessions, session.session_id)
    }

    #[test]
    fn read_only_sessions_cannot_mutate_and_failed_ranges_are_atomic() {
        let backend = MockMutationBackend::new();
        let before = backend.snapshot();
        let (mut read_only, session_id) = registry(&backend, ProcessAccessMode::ReadOnly);
        let error = write(
            &mut read_only,
            &backend,
            &MemoryWriteRequest {
                session_id,
                address: "0x1004".to_string(),
                bytes: vec![1, 2, 3, 4],
            },
        )
        .expect_err("read-only session must reject writes");
        assert_eq!(
            error.into_rpc_error(1, "memory.write").code,
            RpcErrorCode::CapabilityRequired
        );
        assert_eq!(backend.snapshot(), before);

        let (mut mutation, session_id) = registry(&backend, ProcessAccessMode::Mutation);
        let error = write(
            &mut mutation,
            &backend,
            &MemoryWriteRequest {
                session_id,
                address: "0x100f".to_string(),
                bytes: vec![9, 9],
            },
        )
        .expect_err("range crossing the mock region must fail");
        assert_eq!(
            error.into_rpc_error(2, "memory.write").code,
            RpcErrorCode::MemoryWriteFailed
        );
        assert_eq!(backend.snapshot(), before);
    }

    #[test]
    fn writes_change_only_the_requested_bytes() {
        let backend = MockMutationBackend::new();
        let (mut sessions, session_id) = registry(&backend, ProcessAccessMode::Mutation);
        write(
            &mut sessions,
            &backend,
            &MemoryWriteRequest {
                session_id,
                address: "0x1004".to_string(),
                bytes: vec![1, 2, 3, 4],
            },
        )
        .expect("valid write should succeed");
        let snapshot = backend.snapshot();
        assert_eq!(&snapshot[..4], &[0x55; 4]);
        assert_eq!(&snapshot[4..8], &[1, 2, 3, 4]);
        assert_eq!(&snapshot[8..], &[0x55; 8]);
    }

    #[test]
    fn allocations_are_tracked_freed_and_cleaned_up() {
        let backend = MockMutationBackend::new();
        let (mut sessions, session_id) = registry(&backend, ProcessAccessMode::Mutation);
        let mut state = MutationState::new();
        let first = allocate(
            &mut sessions,
            &backend,
            &mut state,
            &MemoryAllocateRequest {
                session_id: session_id.clone(),
                size: 32,
                protection: MemoryProtection::ReadWrite,
            },
        )
        .expect("allocation should succeed");
        let second = allocate(
            &mut sessions,
            &backend,
            &mut state,
            &MemoryAllocateRequest {
                session_id: session_id.clone(),
                size: 64,
                protection: MemoryProtection::ExecuteReadWrite,
            },
        )
        .expect("executable allocation should succeed");
        assert_eq!(state.tracked_count(&session_id), 2);

        free(
            &mut sessions,
            &backend,
            &mut state,
            &MemoryFreeRequest {
                session_id: session_id.clone(),
                allocation_id: first.allocation_id,
            },
        )
        .expect("tracked allocation should free");
        assert_eq!(state.tracked_count(&session_id), 1);

        cleanup_session(&mut sessions, &backend, &mut state, &session_id)
            .expect("session cleanup should release remaining allocations");
        assert_eq!(state.tracked_count(&session_id), 0);
        assert!(!backend
            .data
            .lock()
            .expect("mock data lock")
            .allocations
            .contains_key(&parse_address(&second.address)));
    }

    #[test]
    fn protection_and_remote_thread_results_are_explicit() {
        let backend = MockMutationBackend::new();
        let (mut sessions, session_id) = registry(&backend, ProcessAccessMode::Mutation);
        let mut state = MutationState::new();
        let changed = protect(
            &mut sessions,
            &backend,
            &MemoryProtectRequest {
                session_id: session_id.clone(),
                address: "0x1000".to_string(),
                size: 16,
                protection: MemoryProtection::ExecuteReadWrite,
            },
        )
        .expect("protection should change");
        assert_eq!(changed.previous_protection, MemoryProtection::ReadWrite);

        let thread = start_thread(
            &mut sessions,
            &backend,
            &mut state,
            &RemoteThreadStartRequest {
                session_id,
                start_address: "0x1000".to_string(),
                parameter: Some("0x1008".to_string()),
                wait_timeout_ms: 10,
            },
        )
        .expect("remote thread should start");
        assert!(thread.completed);
        assert_eq!(thread.exit_code, Some(0));
    }

    #[test]
    fn unknown_remote_thread_completion_blocks_unsafe_cleanup() {
        let backend = MockMutationBackend::new();
        backend
            .data
            .lock()
            .expect("mock data lock")
            .thread_completed = false;
        let (mut sessions, session_id) = registry(&backend, ProcessAccessMode::Mutation);
        let mut state = MutationState::new();
        let executable_allocation = allocate(
            &mut sessions,
            &backend,
            &mut state,
            &MemoryAllocateRequest {
                session_id: session_id.clone(),
                size: 32,
                protection: MemoryProtection::ExecuteReadWrite,
            },
        )
        .expect("allocation should succeed");
        let unrelated_allocation = allocate(
            &mut sessions,
            &backend,
            &mut state,
            &MemoryAllocateRequest {
                session_id: session_id.clone(),
                size: 64,
                protection: MemoryProtection::ReadWrite,
            },
        )
        .expect("unrelated allocation should succeed");
        let thread = start_thread(
            &mut sessions,
            &backend,
            &mut state,
            &RemoteThreadStartRequest {
                session_id: session_id.clone(),
                start_address: executable_allocation.address,
                parameter: None,
                wait_timeout_ms: 10,
            },
        )
        .expect("thread start itself should succeed");
        assert!(!thread.completed);

        let error = free(
            &mut sessions,
            &backend,
            &mut state,
            &MemoryFreeRequest {
                session_id: session_id.clone(),
                allocation_id: unrelated_allocation.allocation_id,
            },
        )
        .expect_err("pending threads must pin even unrelated session allocations")
        .into_rpc_error(8, "memory.free");
        assert_eq!(error.code, RpcErrorCode::RemoteThreadFailed);
        assert_eq!(state.tracked_count(&session_id), 2);

        let error = cleanup_session(&mut sessions, &backend, &mut state, &session_id)
            .expect_err("uncertain remote thread must block all session allocation cleanup")
            .into_rpc_error(9, "process.close");
        assert_eq!(error.code, RpcErrorCode::RemoteThreadFailed);
        assert_eq!(state.tracked_count(&session_id), 2);
        assert_eq!(state.tracked_thread_count(&session_id), 1);

        backend
            .data
            .lock()
            .expect("mock data lock")
            .thread_completed = true;
        cleanup_session(&mut sessions, &backend, &mut state, &session_id)
            .expect("cleanup should finish after the remote thread exits");
        assert_eq!(state.tracked_count(&session_id), 0);
        assert_eq!(state.tracked_thread_count(&session_id), 0);
    }

    #[test]
    fn unverified_live_process_retains_allocations_for_cleanup_retry() {
        let backend = MockMutationBackend::new();
        let (mut sessions, session_id) = registry(&backend, ProcessAccessMode::Mutation);
        let mut state = MutationState::new();
        allocate(
            &mut sessions,
            &backend,
            &mut state,
            &MemoryAllocateRequest {
                session_id: session_id.clone(),
                size: 32,
                protection: MemoryProtection::ReadWrite,
            },
        )
        .expect("allocation should succeed");
        backend
            .data
            .lock()
            .expect("mock data lock")
            .validation_failure = true;

        let error = cleanup_session(&mut sessions, &backend, &mut state, &session_id)
            .expect_err("unverified process must retain cleanup ownership")
            .into_rpc_error(10, "process.close");
        assert_eq!(error.code, RpcErrorCode::Internal);
        assert_eq!(state.tracked_count(&session_id), 1);
        assert_eq!(
            backend
                .data
                .lock()
                .expect("mock data lock")
                .allocations
                .len(),
            1
        );

        backend
            .data
            .lock()
            .expect("mock data lock")
            .validation_failure = false;
        cleanup_session(&mut sessions, &backend, &mut state, &session_id)
            .expect("cleanup should remain retryable after verification recovers");
        assert_eq!(state.tracked_count(&session_id), 0);
    }

    fn read_mock_range(
        data: &MockMutationData,
        address: usize,
        size: usize,
    ) -> Result<Vec<u8>, ProcessBackendError> {
        if address >= BASE {
            let offset = address - BASE;
            if let Some(end) = offset.checked_add(size) {
                if end <= data.primary.len() {
                    return Ok(data.primary[offset..end].to_vec());
                }
            }
        }
        for (allocation_base, allocation) in &data.allocations {
            if address >= *allocation_base {
                let offset = address - *allocation_base;
                if let Some(end) = offset.checked_add(size) {
                    if end <= allocation.len() {
                        return Ok(allocation[offset..end].to_vec());
                    }
                }
            }
        }
        Err(mock_range_error())
    }

    fn mock_range_error() -> ProcessBackendError {
        ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "mock range is outside committed memory",
        )
    }

    fn parse_address(address: &str) -> usize {
        usize::from_str_radix(address.trim_start_matches("0x"), 16).expect("valid address")
    }
}
