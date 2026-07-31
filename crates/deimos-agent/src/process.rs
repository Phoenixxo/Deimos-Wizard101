use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use deimos_core::client::{
    ClientDescriptor, ClientId, KeyAction, ListClientsResponse, MessageDelivery, MouseButton,
    WindowPoint, WindowRectangle,
};
use deimos_core::lifecycle::SessionDiagnostics;
use deimos_core::memory::{MemoryProtection, MemoryRegionDescriptor};
use deimos_core::process::{
    ListModulesResponse, ListProcessesRequest, ListProcessesResponse, ModuleDescriptor,
    OpenProcessRequest, ProcessAccessMode, ProcessDescriptor, ProcessIdentity, ProcessKind,
    ProcessSessionId, ProcessSessionResponse, ProcessSessionState,
};
use deimos_core::rpc::{RpcError, RpcErrorCode};

static NEXT_REGISTRY_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessBackendErrorKind {
    NotFound,
    AccessDenied,
    Exited,
    IdentityMismatch,
    Native,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessBackendError {
    pub kind: ProcessBackendErrorKind,
    pub message: String,
    pub native_code: Option<i32>,
}

impl ProcessBackendError {
    pub fn new(kind: ProcessBackendErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            native_code: None,
        }
    }

    pub fn with_native_code(mut self, native_code: i32) -> Self {
        self.native_code = Some(native_code);
        self
    }
}

impl fmt::Display for ProcessBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProcessBackendError {}

pub struct OpenedProcess<H> {
    pub handle: H,
    pub process: ProcessDescriptor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientWindowCandidate {
    pub(crate) native_window_id: u64,
    pub pid: u32,
    /// Identity captured while the candidate still belongs to this HWND. It
    /// lets the registry reject a PID that was reused before process metadata
    /// was collected.
    pub process_identity: ProcessIdentity,
    pub is_foreground: bool,
    pub left: i32,
    pub top: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientWindowTarget {
    pub(crate) native_window_id: u64,
    pub process_identity: ProcessIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientWindowSnapshot {
    pub title: String,
    pub is_foreground: bool,
    pub rectangle: WindowRectangle,
}

pub trait ProcessBackend: Send + Sync + 'static {
    type Handle: Send + 'static;

    fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError>;

    fn list_client_windows(&self) -> Result<Vec<ClientWindowCandidate>, ProcessBackendError> {
        Ok(Vec::new())
    }

    fn open_process(&self, pid: u32) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError>;

    fn open_process_for_access(
        &self,
        pid: u32,
        access_mode: ProcessAccessMode,
    ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
        match access_mode {
            ProcessAccessMode::ReadOnly => self.open_process(pid),
            ProcessAccessMode::Mutation => Err(ProcessBackendError::new(
                ProcessBackendErrorKind::AccessDenied,
                "this process backend does not support mutation sessions",
            )),
        }
    }

    fn validate_process(
        &self,
        handle: &Self::Handle,
        expected: &ProcessIdentity,
    ) -> Result<(), ProcessBackendError>;

    fn enumerate_modules(
        &self,
        handle: &Self::Handle,
        expected: &ProcessIdentity,
    ) -> Result<Vec<ModuleDescriptor>, ProcessBackendError>;

    fn inspect_client_window(
        &self,
        _target: &ClientWindowTarget,
    ) -> Result<ClientWindowSnapshot, ProcessBackendError> {
        Err(unsupported_window_operation())
    }

    fn focus_client_window(
        &self,
        _target: &ClientWindowTarget,
    ) -> Result<bool, ProcessBackendError> {
        Err(unsupported_window_operation())
    }

    fn set_client_window_title(
        &self,
        _target: &ClientWindowTarget,
        _title: &str,
    ) -> Result<(), ProcessBackendError> {
        Err(unsupported_window_operation())
    }

    fn client_to_screen(
        &self,
        _target: &ClientWindowTarget,
        _point: WindowPoint,
    ) -> Result<WindowPoint, ProcessBackendError> {
        Err(unsupported_window_operation())
    }

    fn screen_to_client(
        &self,
        _target: &ClientWindowTarget,
        _point: WindowPoint,
    ) -> Result<WindowPoint, ProcessBackendError> {
        Err(unsupported_window_operation())
    }

    fn send_client_key_event(
        &self,
        _target: &ClientWindowTarget,
        _virtual_key: u16,
        _action: KeyAction,
        _delivery: MessageDelivery,
    ) -> Result<(), ProcessBackendError> {
        Err(unsupported_input_operation())
    }

    fn send_client_mouse_move(
        &self,
        _target: &ClientWindowTarget,
        _point: WindowPoint,
        _delivery: MessageDelivery,
    ) -> Result<(), ProcessBackendError> {
        Err(unsupported_input_operation())
    }

    fn send_client_mouse_button(
        &self,
        _target: &ClientWindowTarget,
        _point: WindowPoint,
        _button: MouseButton,
        _pressed: bool,
        _delivery: MessageDelivery,
    ) -> Result<(), ProcessBackendError> {
        Err(unsupported_input_operation())
    }
}

fn unsupported_window_operation() -> ProcessBackendError {
    ProcessBackendError::new(
        ProcessBackendErrorKind::AccessDenied,
        "window operations require the Windows agent running natively or inside Wine/CrossOver",
    )
}

fn unsupported_input_operation() -> ProcessBackendError {
    ProcessBackendError::new(
        ProcessBackendErrorKind::AccessDenied,
        "input operations require the Windows agent running natively or inside Wine/CrossOver",
    )
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ClientRegistryKey {
    native_window_id: u64,
    pid: u32,
    creation_time_100ns: String,
    // Windows executable paths are case-insensitive. Normalizing the path
    // keeps an agent-owned client ID stable if the same process is reported
    // with different path casing on a later discovery pass.
    executable_path: String,
}

impl ClientRegistryKey {
    fn new(native_window_id: u64, process_identity: &ProcessIdentity) -> Self {
        Self {
            native_window_id,
            pid: process_identity.pid,
            creation_time_100ns: process_identity.creation_time_100ns.clone(),
            executable_path: process_identity.executable_path.to_ascii_lowercase(),
        }
    }
}

pub struct ClientRegistry {
    clients: HashMap<ClientRegistryKey, ClientId>,
    id_prefix: String,
    next_client: u64,
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRegistry {
    pub fn new() -> Self {
        let registry = NEXT_REGISTRY_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            clients: HashMap::new(),
            id_prefix: format!("client-{registry}"),
            next_client: 1,
        }
    }

    pub fn list<B: ProcessBackend>(
        &mut self,
        backend: &B,
    ) -> Result<ListClientsResponse, ProcessBackendError> {
        let windows = backend.list_client_windows()?;
        let processes = backend
            .list_processes()?
            .into_iter()
            .filter(|process| process.kind == deimos_core::process::ProcessKind::Wizard101)
            .filter_map(|process| process.identity.clone().map(|identity| (identity, process)))
            .map(|(identity, process)| (process.pid, (identity, process)))
            .collect::<HashMap<_, _>>();

        let mut seen_keys = HashSet::new();
        let mut discovered = Vec::new();
        for (discovery_order, window) in windows.into_iter().enumerate() {
            let Some((identity, process)) = processes.get(&window.pid) else {
                continue;
            };
            if !same_process_identity(&window.process_identity, identity) {
                continue;
            }
            let key = ClientRegistryKey::new(window.native_window_id, identity);
            // EnumWindows normally reports every top-level window once, but
            // a duplicate backend result must not produce duplicate client
            // descriptors for the same agent-owned identity.
            if !seen_keys.insert(key.clone()) {
                continue;
            }
            discovered.push((discovery_order, window, key, process.clone()));
        }

        let mut screen_positions = discovered
            .iter()
            .map(|(discovery_order, window, _, _)| (*discovery_order, window.top, window.left))
            .collect::<Vec<_>>();
        screen_positions
            .sort_by_key(|(discovery_order, top, left)| (*top, *left, *discovery_order));
        let screen_orders = screen_positions
            .into_iter()
            .enumerate()
            .map(|(screen_order, (discovery_order, _, _))| (discovery_order, screen_order))
            .collect::<HashMap<_, _>>();

        let mut active = HashMap::new();
        let mut clients = Vec::new();
        for (discovery_order, window, key, process) in discovered {
            let client_id = self.clients.get(&key).cloned().unwrap_or_else(|| {
                let id = ClientId(format!("{}-{}", self.id_prefix, self.next_client));
                self.next_client += 1;
                id
            });
            active.insert(key, client_id.clone());
            clients.push(ClientDescriptor {
                client_id,
                process,
                is_foreground: window.is_foreground,
                screen_order: screen_orders
                    .get(&discovery_order)
                    .copied()
                    .expect("every window has a screen order"),
            });
        }
        self.clients = active;

        Ok(ListClientsResponse { clients })
    }

    pub fn resolve<B: ProcessBackend>(
        &mut self,
        backend: &B,
        client_id: &ClientId,
    ) -> Result<ClientWindowTarget, ProcessBackendError> {
        self.list(backend)?;
        let (key, _) = self
            .clients
            .iter()
            .find(|(_, active_id)| *active_id == client_id)
            .ok_or_else(|| {
                ProcessBackendError::new(
                    ProcessBackendErrorKind::NotFound,
                    format!(
                        "client {} is no longer associated with an active Wizard101 window",
                        client_id.0
                    ),
                )
            })?;
        Ok(ClientWindowTarget {
            native_window_id: key.native_window_id,
            process_identity: ProcessIdentity {
                pid: key.pid,
                creation_time_100ns: key.creation_time_100ns.clone(),
                executable_path: key.executable_path.clone(),
            },
        })
    }
}

fn same_process_identity(left: &ProcessIdentity, right: &ProcessIdentity) -> bool {
    left.pid == right.pid
        && left.creation_time_100ns == right.creation_time_100ns
        && left
            .executable_path
            .eq_ignore_ascii_case(&right.executable_path)
}

/// Read-only memory operations are deliberately a separate capability layered
/// on the process/session backend. No method here can mutate a target.
pub trait MemoryBackend: ProcessBackend {
    fn enumerate_memory_regions(
        &self,
        handle: &Self::Handle,
        expected: &ProcessIdentity,
    ) -> Result<Vec<MemoryRegionDescriptor>, ProcessBackendError>;

    fn read_memory(
        &self,
        handle: &Self::Handle,
        address: usize,
        size: usize,
    ) -> Result<Vec<u8>, ProcessBackendError>;
}

pub struct StartedRemoteThread<T> {
    pub thread_id: u32,
    pub handle: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteThreadPoll {
    pub completed: bool,
    pub exit_code: Option<u32>,
}

pub struct MutationExecution<T> {
    pub value: T,
    pub validation_error: Option<ProcessApiError>,
}

pub struct SuspendedProcess {
    instruction_pointers: Vec<usize>,
    resume_guard: Option<Box<dyn ProcessThreadResume>>,
}

pub(crate) trait ProcessThreadResume: Send {
    fn resume(&mut self) -> Result<(), ProcessBackendError>;
}

#[cfg(test)]
impl ProcessThreadResume for () {
    fn resume(&mut self) -> Result<(), ProcessBackendError> {
        Ok(())
    }
}

impl SuspendedProcess {
    #[cfg(any(windows, test))]
    pub(crate) fn new(
        instruction_pointers: Vec<usize>,
        resume_guard: impl ProcessThreadResume + 'static,
    ) -> Self {
        Self {
            instruction_pointers,
            resume_guard: Some(Box::new(resume_guard)),
        }
    }

    pub(crate) fn executes_range(&self, address: usize, size: usize) -> bool {
        let Some(end) = address.checked_add(size) else {
            return true;
        };
        self.instruction_pointers.iter().any(|instruction_pointer| {
            address <= *instruction_pointer && *instruction_pointer < end
        })
    }

    pub(crate) fn resume(mut self) -> Result<(), ProcessBackendError> {
        let result = self
            .resume_guard
            .as_mut()
            .expect("suspended process retains its resume guard")
            .resume();
        if result.is_ok() {
            self.resume_guard = None;
        }
        result
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if let Some(guard) = &mut self.resume_guard {
            let _ = guard.resume();
        }
    }
}

/// Mutation methods are isolated from the read-only backend contract so a
/// caller must opt into both a mutation session and mutation capabilities.
pub trait MutationBackend: MemoryBackend {
    type ThreadHandle: Send + 'static;

    fn write_memory(
        &self,
        handle: &Self::Handle,
        address: usize,
        bytes: &[u8],
    ) -> Result<(), ProcessBackendError>;

    fn allocate_memory(
        &self,
        handle: &Self::Handle,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<usize, ProcessBackendError>;

    /// Allocate within rel32 reach of a hook site. Backends that cannot honor
    /// the placement hint may fall back to a normal allocation; callers still
    /// verify the final displacement before modifying the target.
    fn allocate_memory_near(
        &self,
        handle: &Self::Handle,
        _target: usize,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<usize, ProcessBackendError> {
        self.allocate_memory(handle, size, protection)
    }

    fn free_memory(&self, handle: &Self::Handle, address: usize)
        -> Result<(), ProcessBackendError>;

    fn suspend_process_threads(
        &self,
        handle: &Self::Handle,
    ) -> Result<SuspendedProcess, ProcessBackendError>;

    fn protect_memory(
        &self,
        handle: &Self::Handle,
        address: usize,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<MemoryProtection, ProcessBackendError>;

    fn start_remote_thread(
        &self,
        handle: &Self::Handle,
        start_address: usize,
        parameter: Option<usize>,
    ) -> Result<StartedRemoteThread<Self::ThreadHandle>, ProcessBackendError>;

    fn poll_remote_thread(
        &self,
        thread: &Self::ThreadHandle,
        wait_timeout_ms: u32,
    ) -> Result<RemoteThreadPoll, ProcessBackendError>;

    /// Flush a concrete written range, or the entire target process when both
    /// `address` and `size` are zero.
    fn flush_instruction_cache(
        &self,
        handle: &Self::Handle,
        address: usize,
        size: usize,
    ) -> Result<(), ProcessBackendError>;
}

#[cfg(any(windows, test))]
pub(crate) fn enumerate_modules_with_revalidation<B, F>(
    backend: &B,
    handle: &B::Handle,
    expected: &ProcessIdentity,
    collect: F,
) -> Result<Vec<ModuleDescriptor>, ProcessBackendError>
where
    B: ProcessBackend,
    F: FnOnce() -> Result<Vec<ModuleDescriptor>, ProcessBackendError>,
{
    backend.validate_process(handle, expected)?;
    let modules = collect()?;
    // The collector may use only a PID (as ToolHelp does), so confirm that the
    // original session handle still identifies the same live process before
    // allowing those results to escape.
    backend.validate_process(handle, expected)?;
    Ok(modules)
}

#[cfg(not(windows))]
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedProcessBackend;

#[cfg(not(windows))]
impl ProcessBackend for UnsupportedProcessBackend {
    type Handle = ();

    fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
        Err(ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "process APIs require the Windows agent running natively or inside Wine/CrossOver",
        ))
    }

    fn open_process(&self, _pid: u32) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
        Err(ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "process APIs require the Windows agent running natively or inside Wine/CrossOver",
        ))
    }

    fn validate_process(
        &self,
        _handle: &Self::Handle,
        _expected: &ProcessIdentity,
    ) -> Result<(), ProcessBackendError> {
        Err(ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "process APIs require the Windows agent running natively or inside Wine/CrossOver",
        ))
    }

    fn enumerate_modules(
        &self,
        _handle: &Self::Handle,
        _expected: &ProcessIdentity,
    ) -> Result<Vec<ModuleDescriptor>, ProcessBackendError> {
        Err(ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "process APIs require the Windows agent running natively or inside Wine/CrossOver",
        ))
    }
}

#[cfg(not(windows))]
impl MemoryBackend for UnsupportedProcessBackend {
    fn enumerate_memory_regions(
        &self,
        _handle: &Self::Handle,
        _expected: &ProcessIdentity,
    ) -> Result<Vec<MemoryRegionDescriptor>, ProcessBackendError> {
        Err(ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "memory APIs require the Windows agent running natively or inside Wine/CrossOver",
        ))
    }

    fn read_memory(
        &self,
        _handle: &Self::Handle,
        _address: usize,
        _size: usize,
    ) -> Result<Vec<u8>, ProcessBackendError> {
        Err(ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "memory APIs require the Windows agent running natively or inside Wine/CrossOver",
        ))
    }
}

#[cfg(not(windows))]
impl MutationBackend for UnsupportedProcessBackend {
    type ThreadHandle = ();

    fn write_memory(
        &self,
        _handle: &Self::Handle,
        _address: usize,
        _bytes: &[u8],
    ) -> Result<(), ProcessBackendError> {
        unsupported_mutation()
    }

    fn allocate_memory(
        &self,
        _handle: &Self::Handle,
        _size: usize,
        _protection: MemoryProtection,
    ) -> Result<usize, ProcessBackendError> {
        unsupported_mutation()
    }

    fn free_memory(
        &self,
        _handle: &Self::Handle,
        _address: usize,
    ) -> Result<(), ProcessBackendError> {
        unsupported_mutation()
    }

    fn suspend_process_threads(
        &self,
        _handle: &Self::Handle,
    ) -> Result<SuspendedProcess, ProcessBackendError> {
        unsupported_mutation()
    }

    fn protect_memory(
        &self,
        _handle: &Self::Handle,
        _address: usize,
        _size: usize,
        _protection: MemoryProtection,
    ) -> Result<MemoryProtection, ProcessBackendError> {
        unsupported_mutation()
    }

    fn start_remote_thread(
        &self,
        _handle: &Self::Handle,
        _start_address: usize,
        _parameter: Option<usize>,
    ) -> Result<StartedRemoteThread<Self::ThreadHandle>, ProcessBackendError> {
        unsupported_mutation()
    }

    fn poll_remote_thread(
        &self,
        _thread: &Self::ThreadHandle,
        _wait_timeout_ms: u32,
    ) -> Result<RemoteThreadPoll, ProcessBackendError> {
        unsupported_mutation()
    }

    fn flush_instruction_cache(
        &self,
        _handle: &Self::Handle,
        _address: usize,
        _size: usize,
    ) -> Result<(), ProcessBackendError> {
        unsupported_mutation()
    }
}

#[cfg(not(windows))]
fn unsupported_mutation<T>() -> Result<T, ProcessBackendError> {
    Err(ProcessBackendError::new(
        ProcessBackendErrorKind::Native,
        "mutation APIs require the Windows agent running natively or inside Wine/CrossOver",
    ))
}

#[derive(Debug)]
pub struct ProcessApiError {
    code: RpcErrorCode,
    message: String,
    details: BTreeMap<String, String>,
}

impl ProcessApiError {
    pub(crate) fn from_backend(
        error: ProcessBackendError,
        pid: Option<u32>,
        session_id: Option<&ProcessSessionId>,
    ) -> Self {
        let code = match error.kind {
            ProcessBackendErrorKind::NotFound => RpcErrorCode::ProcessNotFound,
            ProcessBackendErrorKind::AccessDenied => RpcErrorCode::ProcessAccessDenied,
            ProcessBackendErrorKind::Exited | ProcessBackendErrorKind::IdentityMismatch => {
                RpcErrorCode::ProcessExited
            }
            ProcessBackendErrorKind::Native => RpcErrorCode::Internal,
        };
        let mut details = BTreeMap::new();
        if let Some(pid) = pid {
            details.insert("pid".to_string(), pid.to_string());
        }
        if let Some(session_id) = session_id {
            details.insert("session_id".to_string(), session_id.0.clone());
        }
        if let Some(native_code) = error.native_code {
            details.insert("native_code".to_string(), native_code.to_string());
        }
        Self {
            code,
            message: error.message,
            details,
        }
    }

    fn session_not_found(session_id: &ProcessSessionId) -> Self {
        Self {
            code: RpcErrorCode::SessionNotFound,
            message: format!("process session {} does not exist", session_id.0),
            details: BTreeMap::from([("session_id".to_string(), session_id.0.clone())]),
        }
    }

    fn process_exited(session_id: &ProcessSessionId, pid: u32) -> Self {
        Self {
            code: RpcErrorCode::ProcessExited,
            message: format!("process {pid} for session {} has exited", session_id.0),
            details: BTreeMap::from([
                ("pid".to_string(), pid.to_string()),
                ("session_id".to_string(), session_id.0.clone()),
            ]),
        }
    }

    fn session_closed(session_id: &ProcessSessionId) -> Self {
        Self {
            code: RpcErrorCode::InvalidRequest,
            message: format!("process session {} is closed", session_id.0),
            details: BTreeMap::from([("session_id".to_string(), session_id.0.clone())]),
        }
    }

    pub fn into_rpc_error(self, request_id: u64, operation: impl Into<String>) -> RpcError {
        let mut error = RpcError::new(self.code, self.message, request_id, operation, None);
        error.details = self.details;
        error
    }

    pub(crate) fn is_process_exited(&self) -> bool {
        self.code == RpcErrorCode::ProcessExited
    }

    pub(crate) fn with_detail(mut self, name: &str, value: impl Into<String>) -> Self {
        self.details.insert(name.to_string(), value.into());
        self
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

struct ProcessSession<H> {
    process: ProcessDescriptor,
    state: ProcessSessionState,
    access_mode: ProcessAccessMode,
    handle: Option<H>,
}

pub struct ProcessSessionRegistry<H> {
    sessions: HashMap<ProcessSessionId, ProcessSession<H>>,
    id_prefix: String,
    next_session: u64,
}

impl<H> Default for ProcessSessionRegistry<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H> ProcessSessionRegistry<H> {
    pub fn new() -> Self {
        let registry = NEXT_REGISTRY_ID.fetch_add(1, Ordering::Relaxed);
        Self::with_id_prefix(format!("{:08x}-{registry:016x}", std::process::id()))
    }

    pub(crate) fn process_kind(&self, session_id: &ProcessSessionId) -> Option<ProcessKind> {
        self.sessions
            .get(session_id)
            .map(|session| session.process.kind)
    }

    fn with_id_prefix(id_prefix: impl Into<String>) -> Self {
        Self {
            sessions: HashMap::new(),
            id_prefix: id_prefix.into(),
            next_session: 1,
        }
    }

    pub fn list<B: ProcessBackend<Handle = H>>(
        &self,
        backend: &B,
        request: &ListProcessesRequest,
    ) -> Result<ListProcessesResponse, ProcessApiError> {
        let mut processes = backend
            .list_processes()
            .map_err(|error| ProcessApiError::from_backend(error, None, None))?;
        if !request.names.is_empty() {
            processes.retain(|process| {
                request
                    .names
                    .iter()
                    .any(|name| process.name.eq_ignore_ascii_case(name))
            });
        }
        processes.sort_by_key(|process| process.pid);
        Ok(ListProcessesResponse { processes })
    }

    pub fn refresh_and_diagnose<B: ProcessBackend<Handle = H>>(
        &mut self,
        backend: &B,
    ) -> SessionDiagnostics {
        let open_sessions = self
            .sessions
            .iter()
            .filter(|(_, session)| session.state == ProcessSessionState::Open)
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();

        for session_id in open_sessions {
            let session = self
                .sessions
                .get(&session_id)
                .expect("collected session must still exist");
            let validation = backend.validate_process(
                session
                    .handle
                    .as_ref()
                    .expect("open sessions always contain a handle"),
                session
                    .process
                    .identity
                    .as_ref()
                    .expect("open sessions always contain an identity"),
            );
            if validation.as_ref().is_err_and(|error| {
                matches!(
                    error.kind,
                    ProcessBackendErrorKind::NotFound
                        | ProcessBackendErrorKind::Exited
                        | ProcessBackendErrorKind::IdentityMismatch
                )
            }) {
                self.mark_exited(&session_id);
            }
        }

        self.sessions
            .values()
            .fold(SessionDiagnostics::default(), |mut counts, session| {
                match session.state {
                    ProcessSessionState::Open => counts.open += 1,
                    ProcessSessionState::Closed => counts.closed += 1,
                    ProcessSessionState::Exited => counts.exited += 1,
                }
                counts
            })
    }

    pub fn open<B: ProcessBackend<Handle = H>>(
        &mut self,
        backend: &B,
        request: &OpenProcessRequest,
    ) -> Result<ProcessSessionResponse, ProcessApiError> {
        let opened = backend
            .open_process_for_access(request.pid, request.access_mode)
            .map_err(|error| ProcessApiError::from_backend(error, Some(request.pid), None))?;
        let actual_identity = opened.process.identity.as_ref().ok_or_else(|| {
            ProcessApiError::from_backend(
                ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    "opened process did not provide a stable identity",
                ),
                Some(request.pid),
                None,
            )
        })?;

        if request
            .expected_identity
            .as_ref()
            .is_some_and(|expected| expected != actual_identity)
        {
            return Err(ProcessApiError::from_backend(
                ProcessBackendError::new(
                    ProcessBackendErrorKind::IdentityMismatch,
                    format!(
                        "process {pid} changed identity before it could be opened",
                        pid = request.pid
                    ),
                ),
                Some(request.pid),
                None,
            ));
        }

        let session_id = self.next_session_id();
        let response = ProcessSessionResponse {
            session_id: session_id.clone(),
            state: ProcessSessionState::Open,
            access_mode: request.access_mode,
            process: opened.process.clone(),
        };
        self.sessions.insert(
            session_id,
            ProcessSession {
                process: opened.process,
                state: ProcessSessionState::Open,
                access_mode: request.access_mode,
                handle: Some(opened.handle),
            },
        );
        Ok(response)
    }

    pub fn status<B: ProcessBackend<Handle = H>>(
        &mut self,
        backend: &B,
        session_id: &ProcessSessionId,
    ) -> Result<ProcessSessionResponse, ProcessApiError> {
        self.ensure_live(backend, session_id)?;
        let session = self
            .sessions
            .get(session_id)
            .expect("validated session must still exist");
        Ok(session_response(session_id, session))
    }

    pub fn close<B: ProcessBackend<Handle = H>>(
        &mut self,
        backend: &B,
        session_id: &ProcessSessionId,
    ) -> Result<ProcessSessionResponse, ProcessApiError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| ProcessApiError::session_not_found(session_id))?;
        match session.state {
            ProcessSessionState::Closed => return Ok(session_response(session_id, session)),
            ProcessSessionState::Exited => {
                return Err(ProcessApiError::process_exited(
                    session_id,
                    session.process.pid,
                ))
            }
            ProcessSessionState::Open => {}
        }
        let pid = session.process.pid;
        let validation = backend.validate_process(
            session
                .handle
                .as_ref()
                .expect("open sessions always contain a handle"),
            session
                .process
                .identity
                .as_ref()
                .expect("open sessions always contain an identity"),
        );
        if let Err(error) = validation {
            if matches!(
                error.kind,
                ProcessBackendErrorKind::NotFound
                    | ProcessBackendErrorKind::Exited
                    | ProcessBackendErrorKind::IdentityMismatch
            ) {
                let session = self
                    .sessions
                    .get_mut(session_id)
                    .expect("session must still exist");
                session.handle.take();
                session.state = ProcessSessionState::Exited;
            }
            return Err(ProcessApiError::from_backend(
                error,
                Some(pid),
                Some(session_id),
            ));
        }
        let session = self
            .sessions
            .get_mut(session_id)
            .expect("session must still exist");
        session.handle.take();
        session.state = ProcessSessionState::Closed;
        Ok(session_response(session_id, session))
    }

    pub fn modules<B: ProcessBackend<Handle = H>>(
        &mut self,
        backend: &B,
        session_id: &ProcessSessionId,
    ) -> Result<ListModulesResponse, ProcessApiError> {
        self.ensure_live(backend, session_id)?;
        let session = self
            .sessions
            .get(session_id)
            .expect("validated session must still exist");
        if session.state == ProcessSessionState::Closed {
            return Err(ProcessApiError::session_closed(session_id));
        }
        let identity = session
            .process
            .identity
            .as_ref()
            .expect("open sessions always contain an identity");
        let modules = backend.enumerate_modules(
            session
                .handle
                .as_ref()
                .expect("open sessions always contain a handle"),
            identity,
        );
        let modules = match modules {
            Ok(modules) => modules,
            Err(error) => {
                let pid = session.process.pid;
                if matches!(
                    error.kind,
                    ProcessBackendErrorKind::NotFound
                        | ProcessBackendErrorKind::Exited
                        | ProcessBackendErrorKind::IdentityMismatch
                ) {
                    self.mark_exited(session_id);
                }
                return Err(ProcessApiError::from_backend(
                    error,
                    Some(pid),
                    Some(session_id),
                ));
            }
        };
        Ok(ListModulesResponse {
            session_id: session_id.clone(),
            process: session.process.clone(),
            modules,
        })
    }

    /// Run a memory operation against a live session and revalidate the
    /// process identity after it completes. The closure must not retain the
    /// borrowed handle or process descriptor.
    pub fn with_live_session<B, F, R, E>(
        &mut self,
        backend: &B,
        session_id: &ProcessSessionId,
        operation: F,
    ) -> Result<R, E>
    where
        B: ProcessBackend<Handle = H>,
        F: FnOnce(&B, &H, &ProcessDescriptor) -> Result<R, E>,
        E: From<ProcessApiError> + From<ProcessBackendError>,
    {
        self.ensure_live(backend, session_id).map_err(E::from)?;
        if self
            .sessions
            .get(session_id)
            .is_some_and(|session| session.state == ProcessSessionState::Closed)
        {
            return Err(E::from(ProcessApiError::session_closed(session_id)));
        }
        let result = {
            let session = self
                .sessions
                .get(session_id)
                .expect("validated session must still exist");
            operation(
                backend,
                session
                    .handle
                    .as_ref()
                    .expect("open sessions always contain a handle"),
                &session.process,
            )
        };

        let validation = {
            let session = self
                .sessions
                .get(session_id)
                .expect("session must still exist during revalidation");
            backend.validate_process(
                session
                    .handle
                    .as_ref()
                    .expect("open sessions always contain a handle"),
                session
                    .process
                    .identity
                    .as_ref()
                    .expect("open sessions always contain an identity"),
            )
        };
        if let Err(error) = validation {
            let pid = self
                .sessions
                .get(session_id)
                .expect("session must still exist after validation")
                .process
                .pid;
            if matches!(
                error.kind,
                ProcessBackendErrorKind::NotFound
                    | ProcessBackendErrorKind::Exited
                    | ProcessBackendErrorKind::IdentityMismatch
            ) {
                self.mark_exited(session_id);
            }
            return Err(E::from(ProcessApiError::from_backend(
                error,
                Some(pid),
                Some(session_id),
            )));
        }

        result
    }

    pub fn with_live_mutation_session<B, F, R, E>(
        &mut self,
        backend: &B,
        session_id: &ProcessSessionId,
        operation: F,
    ) -> Result<R, E>
    where
        B: ProcessBackend<Handle = H>,
        F: FnOnce(&B, &H, &ProcessDescriptor) -> Result<R, E>,
        E: From<ProcessApiError> + From<ProcessBackendError>,
    {
        let execution = self.with_mutation_session_effect(backend, session_id, operation)?;
        if let Some(error) = execution.validation_error {
            return Err(E::from(error));
        }
        Ok(execution.value)
    }

    /// Execute a side effect after pre-validating a mutation session, then
    /// report post-operation identity validation separately. This lets the
    /// caller register ownership of a successful allocation or thread before
    /// surfacing a validation error.
    pub fn with_mutation_session_effect<B, F, R, E>(
        &mut self,
        backend: &B,
        session_id: &ProcessSessionId,
        operation: F,
    ) -> Result<MutationExecution<R>, E>
    where
        B: ProcessBackend<Handle = H>,
        F: FnOnce(&B, &H, &ProcessDescriptor) -> Result<R, E>,
        E: From<ProcessApiError> + From<ProcessBackendError>,
    {
        if self
            .sessions
            .get(session_id)
            .is_some_and(|session| session.access_mode != ProcessAccessMode::Mutation)
        {
            return Err(E::from(ProcessApiError {
                code: RpcErrorCode::CapabilityRequired,
                message: format!(
                    "process session {} is read-only; open a mutation session explicitly",
                    session_id.0
                ),
                details: BTreeMap::from([
                    ("session_id".to_string(), session_id.0.clone()),
                    ("required_access_mode".to_string(), "mutation".to_string()),
                ]),
            }));
        }
        self.ensure_live(backend, session_id).map_err(E::from)?;
        if self
            .sessions
            .get(session_id)
            .is_some_and(|session| session.state == ProcessSessionState::Closed)
        {
            return Err(E::from(ProcessApiError::session_closed(session_id)));
        }
        let value = {
            let session = self
                .sessions
                .get(session_id)
                .expect("validated mutation session must exist");
            operation(
                backend,
                session
                    .handle
                    .as_ref()
                    .expect("open sessions always contain a handle"),
                &session.process,
            )?
        };
        let validation_error = {
            let session = self
                .sessions
                .get(session_id)
                .expect("mutation session must exist during revalidation");
            backend
                .validate_process(
                    session
                        .handle
                        .as_ref()
                        .expect("open sessions always contain a handle"),
                    session
                        .process
                        .identity
                        .as_ref()
                        .expect("open sessions always contain an identity"),
                )
                .err()
        };
        let validation_error = validation_error.map(|error| {
            let pid = self
                .sessions
                .get(session_id)
                .expect("mutation session must exist after validation")
                .process
                .pid;
            if matches!(
                error.kind,
                ProcessBackendErrorKind::NotFound
                    | ProcessBackendErrorKind::Exited
                    | ProcessBackendErrorKind::IdentityMismatch
            ) {
                self.mark_exited(session_id);
            }
            ProcessApiError::from_backend(error, Some(pid), Some(session_id))
        });
        Ok(MutationExecution {
            value,
            validation_error,
        })
    }

    fn ensure_live<B: ProcessBackend<Handle = H>>(
        &mut self,
        backend: &B,
        session_id: &ProcessSessionId,
    ) -> Result<(), ProcessApiError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| ProcessApiError::session_not_found(session_id))?;
        match session.state {
            ProcessSessionState::Closed => return Ok(()),
            ProcessSessionState::Exited => {
                return Err(ProcessApiError::process_exited(
                    session_id,
                    session.process.pid,
                ))
            }
            ProcessSessionState::Open => {}
        }

        let identity = session
            .process
            .identity
            .as_ref()
            .expect("open sessions always contain an identity");
        let validation = backend.validate_process(
            session
                .handle
                .as_ref()
                .expect("open sessions always contain a handle"),
            identity,
        );
        if let Err(error) = validation {
            let pid = session.process.pid;
            if matches!(
                error.kind,
                ProcessBackendErrorKind::NotFound
                    | ProcessBackendErrorKind::Exited
                    | ProcessBackendErrorKind::IdentityMismatch
            ) {
                self.mark_exited(session_id);
            }
            return Err(ProcessApiError::from_backend(
                error,
                Some(pid),
                Some(session_id),
            ));
        }
        Ok(())
    }

    fn mark_exited(&mut self, session_id: &ProcessSessionId) {
        let session = self
            .sessions
            .get_mut(session_id)
            .expect("session must still exist");
        session.handle.take();
        session.state = ProcessSessionState::Exited;
    }

    fn next_session_id(&mut self) -> ProcessSessionId {
        loop {
            let value = self.next_session;
            self.next_session = self
                .next_session
                .checked_add(1)
                .expect("process session ID space exhausted");
            let candidate = ProcessSessionId(format!("{}-{value:016x}", self.id_prefix));
            if !self.sessions.contains_key(&candidate) {
                return candidate;
            }
        }
    }
}

fn session_response<H>(
    session_id: &ProcessSessionId,
    session: &ProcessSession<H>,
) -> ProcessSessionResponse {
    ProcessSessionResponse {
        session_id: session_id.clone(),
        state: session.state,
        access_mode: session.access_mode,
        process: session.process.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use deimos_core::process::{
        classify_process, ListProcessesRequest, ModuleDescriptor, OpenProcessRequest,
        ProcessDescriptor, ProcessIdentity, ProcessSessionState, MEMORY_FIXTURE_EXECUTABLE,
        WIZARD101_EXECUTABLE,
    };
    use deimos_core::rpc::RpcErrorCode;

    use super::{
        enumerate_modules_with_revalidation, ClientRegistry, ClientWindowCandidate, OpenedProcess,
        ProcessBackend, ProcessBackendError, ProcessBackendErrorKind, ProcessSessionRegistry,
    };

    #[derive(Clone)]
    struct MockBackend {
        state: Arc<Mutex<HashMap<u32, MockProcess>>>,
        windows: Arc<Mutex<Vec<ClientWindowCandidate>>>,
        dropped_handles: Arc<AtomicUsize>,
        validation_failure: Arc<Mutex<Option<ProcessBackendErrorKind>>>,
    }

    #[derive(Clone)]
    struct MockProcess {
        name: String,
        creation: String,
        path: String,
        alive: bool,
    }

    struct MockHandle {
        pid: u32,
        dropped_handles: Arc<AtomicUsize>,
    }

    impl Drop for MockHandle {
        fn drop(&mut self) {
            self.dropped_handles.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl MockBackend {
        fn new() -> Self {
            let processes = HashMap::from([
                (
                    336,
                    MockProcess {
                        name: WIZARD101_EXECUTABLE.to_string(),
                        creation: "1000".to_string(),
                        path: format!(r"C:\Wizard101\{WIZARD101_EXECUTABLE}"),
                        alive: true,
                    },
                ),
                (
                    712,
                    MockProcess {
                        name: MEMORY_FIXTURE_EXECUTABLE.to_string(),
                        creation: "2000".to_string(),
                        path: format!(r"C:\Deimos\{MEMORY_FIXTURE_EXECUTABLE}"),
                        alive: true,
                    },
                ),
            ]);
            Self {
                state: Arc::new(Mutex::new(processes)),
                windows: Arc::new(Mutex::new(Vec::new())),
                dropped_handles: Arc::new(AtomicUsize::new(0)),
                validation_failure: Arc::new(Mutex::new(None)),
            }
        }

        fn set_windows(&self, windows: Vec<ClientWindowCandidate>) {
            *self.windows.lock().expect("mock windows should lock") = windows;
        }

        fn identity(&self, pid: u32) -> ProcessIdentity {
            let state = self.state.lock().expect("mock state should lock");
            let process = state.get(&pid).expect("mock process should exist");
            Self::descriptor(pid, process)
                .identity
                .expect("mock descriptor should have an identity")
        }

        fn stop(&self, pid: u32) {
            self.state
                .lock()
                .expect("mock state should lock")
                .get_mut(&pid)
                .expect("mock process should exist")
                .alive = false;
        }

        fn replace_identity(&self, pid: u32) {
            self.state
                .lock()
                .expect("mock state should lock")
                .get_mut(&pid)
                .expect("mock process should exist")
                .creation = "replacement".to_string();
        }

        fn set_validation_failure(&self, failure: Option<ProcessBackendErrorKind>) {
            *self
                .validation_failure
                .lock()
                .expect("mock validation failure should lock") = failure;
        }

        fn descriptor(pid: u32, process: &MockProcess) -> ProcessDescriptor {
            let identity = ProcessIdentity {
                pid,
                creation_time_100ns: process.creation.clone(),
                executable_path: process.path.clone(),
            };
            ProcessDescriptor {
                pid,
                name: process.name.clone(),
                kind: classify_process(&process.name),
                executable_path: Some(process.path.clone()),
                identity: Some(identity),
            }
        }
    }

    impl ProcessBackend for MockBackend {
        type Handle = MockHandle;

        fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
            Ok(self
                .state
                .lock()
                .expect("mock state should lock")
                .iter()
                .filter(|(_, process)| process.alive)
                .map(|(pid, process)| Self::descriptor(*pid, process))
                .collect())
        }

        fn list_client_windows(&self) -> Result<Vec<ClientWindowCandidate>, ProcessBackendError> {
            Ok(self
                .windows
                .lock()
                .expect("mock windows should lock")
                .clone())
        }

        fn open_process(
            &self,
            pid: u32,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            let state = self.state.lock().expect("mock state should lock");
            let process = state.get(&pid).ok_or_else(|| {
                ProcessBackendError::new(ProcessBackendErrorKind::NotFound, "missing process")
            })?;
            if !process.alive {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Exited,
                    "process exited",
                ));
            }
            Ok(OpenedProcess {
                handle: MockHandle {
                    pid,
                    dropped_handles: Arc::clone(&self.dropped_handles),
                },
                process: Self::descriptor(pid, process),
            })
        }

        fn validate_process(
            &self,
            handle: &Self::Handle,
            expected: &ProcessIdentity,
        ) -> Result<(), ProcessBackendError> {
            if let Some(kind) = *self
                .validation_failure
                .lock()
                .expect("mock validation failure should lock")
            {
                return Err(ProcessBackendError::new(
                    kind,
                    "process identity could not be verified",
                ));
            }
            let state = self.state.lock().expect("mock state should lock");
            let process = state.get(&handle.pid).ok_or_else(|| {
                ProcessBackendError::new(ProcessBackendErrorKind::NotFound, "missing process")
            })?;
            if !process.alive {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Exited,
                    "process exited",
                ));
            }
            if process.creation != expected.creation_time_100ns
                || !process.path.eq_ignore_ascii_case(&expected.executable_path)
            {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::IdentityMismatch,
                    "process identity changed",
                ));
            }
            Ok(())
        }

        fn enumerate_modules(
            &self,
            handle: &Self::Handle,
            expected: &ProcessIdentity,
        ) -> Result<Vec<ModuleDescriptor>, ProcessBackendError> {
            self.validate_process(handle, expected)?;
            Ok(vec![ModuleDescriptor {
                name: expected
                    .executable_path
                    .rsplit('\\')
                    .next()
                    .expect("mock path should contain a name")
                    .to_string(),
                executable_path: expected.executable_path.clone(),
                base_address: "0x140000000".to_string(),
                size: 57_712_640,
            }])
        }
    }

    fn open_request(pid: u32) -> OpenProcessRequest {
        OpenProcessRequest {
            pid,
            expected_identity: None,
            access_mode: deimos_core::process::ProcessAccessMode::ReadOnly,
        }
    }

    #[test]
    fn discovers_wizard_and_fixture_using_wine_internal_pids() {
        let backend = MockBackend::new();
        let registry = ProcessSessionRegistry::<MockHandle>::with_id_prefix("test");
        let response = registry
            .list(&backend, &ListProcessesRequest::default())
            .expect("listing should succeed");

        assert_eq!(
            response
                .processes
                .iter()
                .map(|process| (process.pid, process.kind))
                .collect::<Vec<_>>(),
            vec![
                (336, deimos_core::process::ProcessKind::Wizard101),
                (712, deimos_core::process::ProcessKind::MemoryFixture),
            ]
        );
        assert_eq!(
            response.processes[0]
                .identity
                .as_ref()
                .expect("identity should be present")
                .pid,
            336,
            "the agent must return its Wine-internal PID unchanged"
        );
    }

    #[test]
    fn client_ids_are_stable_until_the_window_or_process_identity_changes() {
        let backend = MockBackend::new();
        backend.set_windows(vec![ClientWindowCandidate {
            native_window_id: 0xabc,
            pid: 336,
            process_identity: backend.identity(336),
            is_foreground: true,
            left: 100,
            top: 50,
        }]);
        let mut registry = ClientRegistry::new();

        let first = registry.list(&backend).expect("first listing should work");
        let second = registry.list(&backend).expect("second listing should work");
        assert_eq!(first.clients[0].client_id, second.clients[0].client_id);

        backend
            .state
            .lock()
            .expect("mock state should lock")
            .get_mut(&336)
            .expect("mock process should exist")
            .path
            .make_ascii_uppercase();
        let case_changed = registry
            .list(&backend)
            .expect("path case change should still list");
        assert_eq!(
            first.clients[0].client_id,
            case_changed.clients[0].client_id
        );

        backend.set_windows(Vec::new());
        assert!(registry
            .list(&backend)
            .expect("closed window should be pruned")
            .clients
            .is_empty());
        backend.replace_identity(336);
        backend.set_windows(vec![ClientWindowCandidate {
            native_window_id: 0xabc,
            pid: 336,
            process_identity: backend.identity(336),
            is_foreground: false,
            left: 100,
            top: 50,
        }]);
        let reused = registry.list(&backend).expect("reused window should list");
        assert_ne!(first.clients[0].client_id, reused.clients[0].client_id);
    }

    #[test]
    fn client_discovery_preserves_native_order_and_reports_visual_order() {
        let backend = MockBackend::new();
        {
            let mut state = backend.state.lock().expect("mock state should lock");
            state.insert(
                337,
                MockProcess {
                    name: WIZARD101_EXECUTABLE.to_string(),
                    creation: "1001".to_string(),
                    path: format!(r"C:\Wizard101-2\{WIZARD101_EXECUTABLE}"),
                    alive: true,
                },
            );
        }
        backend.set_windows(vec![
            ClientWindowCandidate {
                native_window_id: 20,
                pid: 336,
                process_identity: backend.identity(336),
                is_foreground: false,
                left: 500,
                top: 100,
            },
            ClientWindowCandidate {
                native_window_id: 10,
                pid: 337,
                process_identity: backend.identity(337),
                is_foreground: true,
                left: 50,
                top: 20,
            },
        ]);

        let clients = ClientRegistry::new()
            .list(&backend)
            .expect("client listing should work")
            .clients;
        assert_eq!(
            clients
                .iter()
                .map(|client| client.process.pid)
                .collect::<Vec<_>>(),
            vec![336, 337]
        );
        assert_eq!(
            clients
                .iter()
                .map(|client| client.screen_order)
                .collect::<Vec<_>>(),
            vec![1, 0]
        );
        assert!(!clients[0].is_foreground);
        assert!(clients[1].is_foreground);
        assert_ne!(clients[0].client_id, clients[1].client_id);
    }

    #[test]
    fn client_resolution_keeps_multiple_windows_isolated() {
        let backend = MockBackend::new();
        {
            let mut state = backend.state.lock().expect("mock state should lock");
            state.insert(
                337,
                MockProcess {
                    name: WIZARD101_EXECUTABLE.to_string(),
                    creation: "1001".to_string(),
                    path: format!(r"C:\Wizard101-2\{WIZARD101_EXECUTABLE}"),
                    alive: true,
                },
            );
        }
        backend.set_windows(vec![
            ClientWindowCandidate {
                native_window_id: 20,
                pid: 336,
                process_identity: backend.identity(336),
                is_foreground: true,
                left: 0,
                top: 0,
            },
            ClientWindowCandidate {
                native_window_id: 10,
                pid: 337,
                process_identity: backend.identity(337),
                is_foreground: false,
                left: 100,
                top: 100,
            },
        ]);
        let mut registry = ClientRegistry::new();
        let listed = registry
            .list(&backend)
            .expect("client listing should work")
            .clients;
        let first_id = listed
            .iter()
            .find(|client| client.process.pid == 336)
            .expect("first client")
            .client_id
            .clone();
        let second_id = listed
            .iter()
            .find(|client| client.process.pid == 337)
            .expect("second client")
            .client_id
            .clone();

        let first = registry
            .resolve(&backend, &first_id)
            .expect("first client should resolve");
        let second = registry
            .resolve(&backend, &second_id)
            .expect("second client should resolve");
        assert_eq!(first.native_window_id, 20);
        assert_eq!(first.process_identity.pid, 336);
        assert_eq!(second.native_window_id, 10);
        assert_eq!(second.process_identity.pid, 337);
    }

    #[test]
    fn client_discovery_deduplicates_repeated_window_candidates() {
        let backend = MockBackend::new();
        let candidate = ClientWindowCandidate {
            native_window_id: 0xabc,
            pid: 336,
            process_identity: backend.identity(336),
            is_foreground: true,
            left: 100,
            top: 50,
        };
        backend.set_windows(vec![candidate.clone(), candidate]);

        let clients = ClientRegistry::new()
            .list(&backend)
            .expect("client listing should work")
            .clients;
        assert_eq!(clients.len(), 1);
    }

    #[test]
    fn client_discovery_rejects_a_window_when_its_pid_was_reused() {
        let backend = MockBackend::new();
        let stale_candidate = ClientWindowCandidate {
            native_window_id: 0xabc,
            pid: 336,
            process_identity: backend.identity(336),
            is_foreground: true,
            left: 100,
            top: 50,
        };
        backend.replace_identity(336);
        backend.set_windows(vec![stale_candidate]);

        assert!(ClientRegistry::new()
            .list(&backend)
            .expect("client listing should work")
            .clients
            .is_empty());
    }

    #[test]
    fn sessions_are_distinct_stable_and_close_handles() {
        let backend = MockBackend::new();
        let mut registry = ProcessSessionRegistry::with_id_prefix("agent");
        let first = registry
            .open(&backend, &open_request(336))
            .expect("first open should work");
        let second = registry
            .open(&backend, &open_request(336))
            .expect("second client open should work");

        assert_ne!(first.session_id, second.session_id);
        assert_eq!(
            registry
                .status(&backend, &first.session_id)
                .expect("status should work")
                .session_id,
            first.session_id
        );
        let modules = registry
            .modules(&backend, &first.session_id)
            .expect("modules should enumerate");
        assert_eq!(modules.modules.len(), 1);
        assert_eq!(
            modules.modules[0].executable_path,
            format!(r"C:\Wizard101\{WIZARD101_EXECUTABLE}")
        );

        let closed = registry
            .close(&backend, &first.session_id)
            .expect("close should work");
        assert_eq!(closed.state, ProcessSessionState::Closed);
        assert_eq!(backend.dropped_handles.load(Ordering::SeqCst), 1);
        assert_eq!(
            registry
                .status(&backend, &first.session_id)
                .expect("closed status should remain queryable")
                .state,
            ProcessSessionState::Closed
        );
        drop(registry);
        assert_eq!(
            backend.dropped_handles.load(Ordering::SeqCst),
            2,
            "dropping the registry must close any remaining native handles"
        );
    }

    #[test]
    fn native_revalidation_failure_retains_the_open_session_handle() {
        let backend = MockBackend::new();
        let mut registry = ProcessSessionRegistry::with_id_prefix("agent");
        let session = registry
            .open(&backend, &open_request(336))
            .expect("session should open");
        backend.set_validation_failure(Some(ProcessBackendErrorKind::Native));

        let error = registry
            .close(&backend, &session.session_id)
            .expect_err("unverified live process must not be closed");
        assert_eq!(error.code, RpcErrorCode::Internal);
        assert_eq!(
            backend.dropped_handles.load(Ordering::SeqCst),
            0,
            "native revalidation failure must retain the process handle"
        );

        backend.set_validation_failure(None);
        let closed = registry
            .close(&backend, &session.session_id)
            .expect("close should remain retryable after verification recovers");
        assert_eq!(closed.state, ProcessSessionState::Closed);
        assert_eq!(backend.dropped_handles.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stale_and_reused_process_sessions_return_process_exited_and_close_handles() {
        let backend = MockBackend::new();
        let mut registry = ProcessSessionRegistry::with_id_prefix("agent");
        let exited = registry
            .open(&backend, &open_request(336))
            .expect("open should work");
        backend.stop(336);

        let error = registry
            .status(&backend, &exited.session_id)
            .expect_err("stale session should fail");
        assert_eq!(error.code, RpcErrorCode::ProcessExited);
        assert_eq!(backend.dropped_handles.load(Ordering::SeqCst), 1);
        let repeated = registry
            .status(&backend, &exited.session_id)
            .expect_err("stale tombstone should remain structured");
        assert_eq!(repeated.code, RpcErrorCode::ProcessExited);

        let reused = registry
            .open(&backend, &open_request(712))
            .expect("fixture open should work");
        backend.replace_identity(712);
        let error = registry
            .modules(&backend, &reused.session_id)
            .expect_err("PID reuse should invalidate the session");
        assert_eq!(error.code, RpcErrorCode::ProcessExited);
        assert_eq!(backend.dropped_handles.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn list_to_open_identity_race_is_rejected_and_handle_is_closed() {
        let backend = MockBackend::new();
        let registry = ProcessSessionRegistry::<MockHandle>::with_id_prefix("list");
        let listed = registry
            .list(&backend, &ListProcessesRequest::default())
            .expect("listing should work")
            .processes
            .into_iter()
            .find(|process| process.pid == 336)
            .expect("wizard should be listed");
        backend.replace_identity(336);

        let mut opener = ProcessSessionRegistry::with_id_prefix("open");
        let error = opener
            .open(
                &backend,
                &OpenProcessRequest {
                    pid: 336,
                    expected_identity: listed.identity,
                    access_mode: deimos_core::process::ProcessAccessMode::ReadOnly,
                },
            )
            .expect_err("changed identity should fail open");
        assert_eq!(error.code, RpcErrorCode::ProcessExited);
        assert_eq!(
            backend.dropped_handles.load(Ordering::SeqCst),
            1,
            "rejected open handles must be closed"
        );
    }

    #[test]
    fn module_results_are_discarded_when_identity_changes_during_collection() {
        let backend = MockBackend::new();
        let opened = backend
            .open_process(336)
            .expect("wizard process should open");
        let expected = opened
            .process
            .identity
            .as_ref()
            .expect("opened process should have an identity");

        let error = enumerate_modules_with_revalidation(&backend, &opened.handle, expected, || {
            backend.replace_identity(336);
            Ok(vec![ModuleDescriptor {
                name: "replacement.dll".to_string(),
                executable_path: r"C:\Replacement\replacement.dll".to_string(),
                base_address: "0x10000000".to_string(),
                size: 4096,
            }])
        })
        .expect_err("post-enumeration identity change must discard module results");

        assert_eq!(error.kind, ProcessBackendErrorKind::IdentityMismatch);
    }
}
