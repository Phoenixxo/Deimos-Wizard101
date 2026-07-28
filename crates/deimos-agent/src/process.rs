use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use deimos_core::process::{
    ListModulesResponse, ListProcessesRequest, ListProcessesResponse, ModuleDescriptor,
    OpenProcessRequest, ProcessDescriptor, ProcessIdentity, ProcessSessionId,
    ProcessSessionResponse, ProcessSessionState,
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

pub trait ProcessBackend: Send + Sync + 'static {
    type Handle: Send + 'static;

    fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError>;

    fn open_process(&self, pid: u32) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError>;

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

#[derive(Debug)]
pub struct ProcessApiError {
    code: RpcErrorCode,
    message: String,
    details: BTreeMap<String, String>,
}

impl ProcessApiError {
    fn from_backend(
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
}

struct ProcessSession<H> {
    process: ProcessDescriptor,
    state: ProcessSessionState,
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

    pub fn open<B: ProcessBackend<Handle = H>>(
        &mut self,
        backend: &B,
        request: &OpenProcessRequest,
    ) -> Result<ProcessSessionResponse, ProcessApiError> {
        let opened = backend
            .open_process(request.pid)
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
            process: opened.process.clone(),
        };
        self.sessions.insert(
            session_id,
            ProcessSession {
                process: opened.process,
                state: ProcessSessionState::Open,
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
        let session = self
            .sessions
            .get_mut(session_id)
            .expect("session must still exist");
        session.handle.take();
        session.state = if validation.as_ref().is_err_and(|error| {
            matches!(
                error.kind,
                ProcessBackendErrorKind::NotFound
                    | ProcessBackendErrorKind::Exited
                    | ProcessBackendErrorKind::IdentityMismatch
            )
        }) {
            ProcessSessionState::Exited
        } else {
            ProcessSessionState::Closed
        };
        if let Err(error) = validation {
            return Err(ProcessApiError::from_backend(
                error,
                Some(pid),
                Some(session_id),
            ));
        }
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
        enumerate_modules_with_revalidation, OpenedProcess, ProcessBackend, ProcessBackendError,
        ProcessBackendErrorKind, ProcessSessionRegistry,
    };

    #[derive(Clone)]
    struct MockBackend {
        state: Arc<Mutex<HashMap<u32, MockProcess>>>,
        dropped_handles: Arc<AtomicUsize>,
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
                dropped_handles: Arc::new(AtomicUsize::new(0)),
            }
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
