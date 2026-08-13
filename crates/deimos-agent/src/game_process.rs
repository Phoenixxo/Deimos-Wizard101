use std::collections::{BTreeMap, HashSet};
use std::thread;
use std::time::{Duration, Instant};

use deimos_core::client::ClientDescriptor;
use deimos_core::game::{
    GameLaunchRequest, GameLaunchResponse, GameTerminateRequest, GameTerminateResponse,
    MAX_GAME_OPERATION_TIMEOUT_MS,
};
use deimos_core::rpc::{RpcError, RpcErrorCode};

use crate::process::{ClientRegistry, ProcessBackend, ProcessBackendError};

const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub struct GameProcessError {
    code: RpcErrorCode,
    message: String,
    details: BTreeMap<String, String>,
}

impl GameProcessError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: RpcErrorCode::InvalidRequest,
            message: message.into(),
            details: BTreeMap::new(),
        }
    }

    fn backend(code: RpcErrorCode, action: &str, error: ProcessBackendError) -> Self {
        let mut details = BTreeMap::new();
        if let Some(native_code) = error.native_code {
            details.insert("native_code".to_string(), native_code.to_string());
        }
        Self {
            code,
            message: format!("{action}: {}", error.message),
            details,
        }
    }

    fn timeout(action: &str, timeout_ms: u32) -> Self {
        let mut details = BTreeMap::new();
        details.insert("timeout_ms".to_string(), timeout_ms.to_string());
        Self {
            code: RpcErrorCode::GameLaunchTimeout,
            message: format!("timed out after {timeout_ms} ms waiting for {action}"),
            details,
        }
    }

    pub fn into_rpc_error(self, request_id: u64, operation: &str) -> RpcError {
        let mut error = RpcError::new(self.code, self.message, request_id, operation, None);
        error.details = self.details;
        error
    }
}

pub fn launch<B: ProcessBackend>(
    clients: &mut ClientRegistry,
    backend: &B,
    request: &GameLaunchRequest,
    cancelled: impl Fn() -> bool,
) -> Result<GameLaunchResponse, GameProcessError> {
    validate_timeout(request.timeout_ms)?;
    validate_game_path(&request.game_path)?;
    validate_login_server(&request.login_server)?;

    let before = clients
        .list(backend)
        .map_err(|error| {
            GameProcessError::backend(
                RpcErrorCode::GameLaunchFailed,
                "could not inspect existing Wizard101 clients",
                error,
            )
        })?
        .clients;
    let known = before
        .iter()
        .filter_map(identity_key)
        .collect::<HashSet<_>>();
    let launched_identity = backend
        .launch_game(&request.game_path, &request.login_server)
        .map_err(|error| {
            GameProcessError::backend(
                RpcErrorCode::GameLaunchFailed,
                "could not start Wizard101",
                error,
            )
        })?;

    let deadline = Instant::now() + Duration::from_millis(u64::from(request.timeout_ms));
    loop {
        if cancelled() {
            return Err(GameProcessError::invalid_request(
                "the agent began shutting down while Wizard101 was starting",
            ));
        }
        let current = clients
            .list(backend)
            .map_err(|error| {
                GameProcessError::backend(
                    RpcErrorCode::GameLaunchFailed,
                    "could not confirm the new Wizard101 window",
                    error,
                )
            })?
            .clients;
        let mut new_clients = current
            .into_iter()
            .filter(|client| {
                identity_key(client)
                    .as_ref()
                    .is_some_and(|identity| !known.contains(identity))
            })
            .collect::<Vec<_>>();
        if let Some(index) = new_clients.iter().position(|client| {
            client
                .process
                .identity
                .as_ref()
                .is_some_and(|identity| same_identity(identity, &launched_identity))
        }) {
            return Ok(GameLaunchResponse {
                launched_process_id: launched_identity.pid,
                client: new_clients.swap_remove(index),
            });
        }
        if Instant::now() >= deadline {
            return Err(GameProcessError::timeout(
                "a new Wizard101 process and window",
                request.timeout_ms,
            ));
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

pub fn terminate<B: ProcessBackend>(
    clients: &mut ClientRegistry,
    backend: &B,
    request: &GameTerminateRequest,
    cancelled: impl Fn() -> bool,
) -> Result<GameTerminateResponse, GameProcessError> {
    validate_timeout(request.timeout_ms)?;
    let target = clients
        .resolve(backend, &request.client_id)
        .map_err(|error| {
            GameProcessError::backend(
                RpcErrorCode::GameTerminationFailed,
                "could not resolve the selected Wizard101 client",
                error,
            )
        })?;
    let process_id = target.process_identity.pid;
    let deadline = Instant::now() + Duration::from_millis(u64::from(request.timeout_ms));
    backend
        .terminate_process_and_wait(&target.process_identity, request.timeout_ms)
        .map_err(|error| {
            GameProcessError::backend(
                RpcErrorCode::GameTerminationFailed,
                "could not terminate the selected Wizard101 process",
                error,
            )
        })?;

    loop {
        if cancelled() {
            return Err(GameProcessError::invalid_request(
                "the agent began shutting down while Wizard101 was stopping",
            ));
        }
        let active = clients
            .list(backend)
            .map_err(|error| {
                GameProcessError::backend(
                    RpcErrorCode::GameTerminationFailed,
                    "could not confirm that Wizard101 stopped",
                    error,
                )
            })?
            .clients
            .into_iter()
            .any(|client| client.client_id == request.client_id);
        if !active {
            return Ok(GameTerminateResponse {
                client_id: request.client_id.clone(),
                process_id,
                terminated: true,
            });
        }
        if Instant::now() >= deadline {
            let mut error = GameProcessError::timeout(
                "the selected Wizard101 process and window to close",
                request.timeout_ms,
            );
            error.code = RpcErrorCode::GameTerminationFailed;
            return Err(error);
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn validate_timeout(timeout_ms: u32) -> Result<(), GameProcessError> {
    if timeout_ms == 0 || timeout_ms > MAX_GAME_OPERATION_TIMEOUT_MS {
        return Err(GameProcessError::invalid_request(format!(
            "timeout_ms must be between 1 and {MAX_GAME_OPERATION_TIMEOUT_MS}"
        )));
    }
    Ok(())
}

fn validate_game_path(game_path: &str) -> Result<(), GameProcessError> {
    if game_path.trim().is_empty() || game_path.contains('\0') {
        return Err(GameProcessError::invalid_request(
            "game_path must be a non-empty Windows installation path",
        ));
    }
    Ok(())
}

fn validate_login_server(login_server: &str) -> Result<(), GameProcessError> {
    let (host, port) = login_server.rsplit_once(':').ok_or_else(|| {
        GameProcessError::invalid_request("login_server must use host:port format")
    })?;
    if host.trim().is_empty() || host.contains(char::is_whitespace) || port.parse::<u16>().is_err()
    {
        return Err(GameProcessError::invalid_request(
            "login_server must contain a host and a valid TCP port",
        ));
    }
    Ok(())
}

fn identity_key(client: &ClientDescriptor) -> Option<(u32, String, String)> {
    client.process.identity.as_ref().map(|identity| {
        (
            identity.pid,
            identity.creation_time_100ns.clone(),
            identity.executable_path.to_ascii_lowercase(),
        )
    })
}

fn same_identity(
    left: &deimos_core::process::ProcessIdentity,
    right: &deimos_core::process::ProcessIdentity,
) -> bool {
    left.pid == right.pid
        && left.creation_time_100ns == right.creation_time_100ns
        && left
            .executable_path
            .eq_ignore_ascii_case(&right.executable_path)
}

#[cfg(test)]
mod tests {
    use super::{launch, terminate};
    use crate::process::{
        ClientRegistry, ClientWindowCandidate, OpenedProcess, ProcessBackend, ProcessBackendError,
        ProcessBackendErrorKind,
    };
    use deimos_core::client::ClientId;
    use deimos_core::game::{GameLaunchRequest, GameTerminateRequest};
    use deimos_core::process::{ModuleDescriptor, ProcessDescriptor, ProcessIdentity, ProcessKind};
    use deimos_core::rpc::RpcErrorCode;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FakeClient {
        window: u64,
        process: ProcessDescriptor,
    }

    #[derive(Default)]
    struct FakeState {
        clients: Vec<FakeClient>,
        launches: VecDeque<Result<FakeClient, ProcessBackendError>>,
        launch_identity_override: Option<ProcessIdentity>,
    }

    #[derive(Clone, Default)]
    struct FakeBackend {
        state: Arc<Mutex<FakeState>>,
    }

    impl FakeBackend {
        fn with_launches(launches: Vec<Result<FakeClient, ProcessBackendError>>) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeState {
                    clients: Vec::new(),
                    launches: launches.into(),
                    launch_identity_override: None,
                })),
            }
        }

        fn with_launch_identity_override(launched: FakeClient, identity: ProcessIdentity) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeState {
                    clients: Vec::new(),
                    launches: vec![Ok(launched)].into(),
                    launch_identity_override: Some(identity),
                })),
            }
        }

        fn client(pid: u32, window: u64) -> FakeClient {
            FakeClient {
                window,
                process: ProcessDescriptor {
                    pid,
                    name: "WizardGraphicalClient.exe".to_string(),
                    kind: ProcessKind::Wizard101,
                    executable_path: Some(format!("C:\\Wizard101\\Bin\\{pid}.exe")),
                    identity: Some(ProcessIdentity {
                        pid,
                        creation_time_100ns: format!("{pid}00"),
                        executable_path: format!(
                            "C:\\Wizard101\\Bin\\WizardGraphicalClient-{pid}.exe"
                        ),
                    }),
                },
            }
        }
    }

    impl ProcessBackend for FakeBackend {
        type Handle = ();

        fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
            Ok(self
                .state
                .lock()
                .expect("state lock")
                .clients
                .iter()
                .map(|client| client.process.clone())
                .collect())
        }

        fn list_client_windows(&self) -> Result<Vec<ClientWindowCandidate>, ProcessBackendError> {
            Ok(self
                .state
                .lock()
                .expect("state lock")
                .clients
                .iter()
                .map(|client| ClientWindowCandidate {
                    native_window_id: client.window,
                    pid: client.process.pid,
                    process_identity: client.process.identity.clone().expect("identity"),
                    is_foreground: false,
                    left: client.process.pid as i32,
                    top: 0,
                })
                .collect())
        }

        fn launch_game(
            &self,
            _game_path: &str,
            _login_server: &str,
        ) -> Result<ProcessIdentity, ProcessBackendError> {
            let mut state = self.state.lock().expect("state lock");
            let launched = state.launches.pop_front().unwrap_or_else(|| {
                Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    "no launch result was queued",
                ))
            })?;
            let identity = state
                .launch_identity_override
                .take()
                .unwrap_or_else(|| launched.process.identity.clone().expect("identity"));
            state.clients.push(launched);
            Ok(identity)
        }

        fn terminate_process_and_wait(
            &self,
            expected: &ProcessIdentity,
            _timeout_ms: u32,
        ) -> Result<(), ProcessBackendError> {
            let mut state = self.state.lock().expect("state lock");
            let before = state.clients.len();
            state.clients.retain(|client| {
                let Some(identity) = client.process.identity.as_ref() else {
                    return true;
                };
                identity.pid != expected.pid
                    || identity.creation_time_100ns != expected.creation_time_100ns
                    || !identity
                        .executable_path
                        .eq_ignore_ascii_case(&expected.executable_path)
            });
            if state.clients.len() == before {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::NotFound,
                    "process was not found",
                ));
            }
            Ok(())
        }

        fn open_process(
            &self,
            pid: u32,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            let process = self
                .list_processes()?
                .into_iter()
                .find(|process| process.pid == pid)
                .ok_or_else(|| {
                    ProcessBackendError::new(
                        ProcessBackendErrorKind::NotFound,
                        "process was not found",
                    )
                })?;
            Ok(OpenedProcess {
                handle: (),
                process,
            })
        }

        fn validate_process(
            &self,
            _handle: &Self::Handle,
            expected: &ProcessIdentity,
        ) -> Result<(), ProcessBackendError> {
            if self
                .list_processes()?
                .iter()
                .filter_map(|process| process.identity.as_ref())
                .any(|identity| identity == expected)
            {
                Ok(())
            } else {
                Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Exited,
                    "process exited",
                ))
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

    fn launch_request() -> GameLaunchRequest {
        GameLaunchRequest {
            game_path: "C:\\Wizard101".to_string(),
            login_server: "login.us.wizard101.com:12000".to_string(),
            timeout_ms: 50,
        }
    }

    #[test]
    fn single_and_multiple_launches_return_distinct_confirmed_clients() {
        let backend = FakeBackend::with_launches(vec![
            Ok(FakeBackend::client(101, 1001)),
            Ok(FakeBackend::client(102, 1002)),
        ]);
        let mut registry = ClientRegistry::new();

        let first = launch(&mut registry, &backend, &launch_request(), || false)
            .expect("first launch should succeed");
        let second = launch(&mut registry, &backend, &launch_request(), || false)
            .expect("second launch should succeed");

        assert_eq!(first.launched_process_id, 101);
        assert_eq!(second.launched_process_id, 102);
        assert_ne!(first.client.client_id, second.client.client_id);
        assert_eq!(first.client.process.pid, 101);
        assert_eq!(second.client.process.pid, 102);
    }

    #[test]
    fn launch_failure_and_timeout_are_structured() {
        let backend = FakeBackend::with_launches(vec![Err(ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "CreateProcess failed",
        ))]);
        let mut registry = ClientRegistry::new();
        let error = launch(&mut registry, &backend, &launch_request(), || false)
            .expect_err("spawn failure should escape");
        assert_eq!(error.code, RpcErrorCode::GameLaunchFailed);

        #[derive(Clone, Default)]
        struct NoWindowBackend(FakeBackend);
        impl ProcessBackend for NoWindowBackend {
            type Handle = ();

            fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
                self.0.list_processes()
            }

            fn launch_game(
                &self,
                _game_path: &str,
                _login_server: &str,
            ) -> Result<ProcessIdentity, ProcessBackendError> {
                Ok(ProcessIdentity {
                    pid: 500,
                    creation_time_100ns: "50000".to_string(),
                    executable_path: "C:\\Wizard101\\Bin\\WizardGraphicalClient-500.exe"
                        .to_string(),
                })
            }

            fn open_process(
                &self,
                pid: u32,
            ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
                self.0.open_process(pid)
            }

            fn validate_process(
                &self,
                handle: &Self::Handle,
                expected: &ProcessIdentity,
            ) -> Result<(), ProcessBackendError> {
                self.0.validate_process(handle, expected)
            }

            fn enumerate_modules(
                &self,
                handle: &Self::Handle,
                expected: &ProcessIdentity,
            ) -> Result<Vec<ModuleDescriptor>, ProcessBackendError> {
                self.0.enumerate_modules(handle, expected)
            }
        }
        let mut request = launch_request();
        request.timeout_ms = 1;
        let error = launch(
            &mut ClientRegistry::new(),
            &NoWindowBackend::default(),
            &request,
            || false,
        )
        .expect_err("missing window should time out");
        assert_eq!(error.code, RpcErrorCode::GameLaunchTimeout);
    }

    #[test]
    fn unrelated_new_window_cannot_confirm_the_launched_process() {
        let backend = FakeBackend::with_launch_identity_override(
            FakeBackend::client(600, 6001),
            ProcessIdentity {
                pid: 601,
                creation_time_100ns: "60100".to_string(),
                executable_path: "C:\\Wizard101\\Bin\\WizardGraphicalClient-601.exe".to_string(),
            },
        );
        let mut request = launch_request();
        request.timeout_ms = 1;

        let error = launch(&mut ClientRegistry::new(), &backend, &request, || false)
            .expect_err("an unrelated client must not satisfy launch confirmation");

        assert_eq!(error.code, RpcErrorCode::GameLaunchTimeout);
    }

    #[test]
    fn termination_uses_opaque_client_identity_and_confirms_cleanup() {
        let backend = FakeBackend::with_launches(vec![Ok(FakeBackend::client(201, 2001))]);
        let mut registry = ClientRegistry::new();
        let launched = launch(&mut registry, &backend, &launch_request(), || false)
            .expect("launch should succeed");
        let response = terminate(
            &mut registry,
            &backend,
            &GameTerminateRequest {
                client_id: launched.client.client_id.clone(),
                timeout_ms: 50,
            },
            || false,
        )
        .expect("termination should succeed");

        assert!(response.terminated);
        assert_eq!(response.process_id, 201);
        assert_eq!(response.client_id, launched.client.client_id);
        assert!(registry.list(&backend).expect("list").clients.is_empty());
    }

    #[test]
    fn invalid_launch_input_is_rejected_before_process_creation() {
        let backend = FakeBackend::with_launches(Vec::new());
        let mut request = launch_request();
        request.login_server = "missing-port".to_string();
        let error = launch(&mut ClientRegistry::new(), &backend, &request, || false)
            .expect_err("invalid server should fail");
        assert_eq!(error.code, RpcErrorCode::InvalidRequest);
    }

    #[test]
    fn termination_rejects_stale_client_ids() {
        let error = terminate(
            &mut ClientRegistry::new(),
            &FakeBackend::default(),
            &GameTerminateRequest {
                client_id: ClientId("client-stale".to_string()),
                timeout_ms: 50,
            },
            || false,
        )
        .expect_err("stale clients should fail");
        assert_eq!(error.code, RpcErrorCode::GameTerminationFailed);
    }
}
