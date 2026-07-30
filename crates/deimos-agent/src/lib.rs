use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use deimos_core::client::{ListClientsRequest, CAPABILITY_CLIENT_DISCOVERY, OP_CLIENT_LIST};
use deimos_core::lifecycle::{
    AgentHealth, AgentHealthRequest, AgentIdentity, AgentShutdownRequest, AgentShutdownResponse,
    AgentState, CAPABILITY_AGENT_LIFECYCLE, OP_AGENT_HEALTH, OP_AGENT_SHUTDOWN,
};
use deimos_core::memory::{
    MemoryBatchReadRequest, MemoryPointerChainRequest, MemoryReadRequest, MemoryScanRequest,
    MemorySessionRequest, TypedMemoryReadRequest, CAPABILITY_MEMORY_READ_ONLY,
    OP_MEMORY_POINTER_CHAIN, OP_MEMORY_READ, OP_MEMORY_READ_BATCH, OP_MEMORY_READ_TYPED,
    OP_MEMORY_REGIONS, OP_MEMORY_SCAN,
};
use deimos_core::process::{
    ListProcessesRequest, OpenProcessRequest, SessionRequest, CAPABILITY_PROCESS_READ_ONLY,
    OP_MODULE_LIST, OP_PROCESS_CLOSE, OP_PROCESS_LIST, OP_PROCESS_OPEN, OP_PROCESS_STATUS,
};
use deimos_core::rpc::{AuthToken, RpcCall, RpcConfig, RpcError, RpcErrorCode, RpcServer};
use deimos_core::{ProbeReport, ProbeRequest};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

#[cfg(not(windows))]
use deimos_core::WINDOWS_AGENT_TARGET;

pub const CAPABILITY_PROBE: &str = "probe";
pub const MAX_AGENT_CONNECTIONS: usize = 16;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const SHUTDOWN_WORKER_TIMEOUT: Duration = Duration::from_secs(1);

pub mod instance;
pub mod memory;
pub mod process;

#[cfg(windows)]
mod windows_probe;

#[cfg(windows)]
pub mod windows_process;

#[cfg(windows)]
use windows_process::WindowsProcessBackend as PlatformProcessBackend;

#[cfg(not(windows))]
use process::UnsupportedProcessBackend as PlatformProcessBackend;

use process::{ClientRegistry, MemoryBackend, ProcessSessionRegistry};

#[cfg(windows)]
pub fn run(request: &ProbeRequest) -> ProbeReport {
    windows_probe::run(request)
}

#[cfg(not(windows))]
pub fn run(request: &ProbeRequest) -> ProbeReport {
    let mut report = ProbeReport::new(request);
    report.errors.push(
        "This probe must be built for Windows and run inside the Wizard101 CrossOver bottle."
            .to_string(),
    );
    report.build_target = Some(WINDOWS_AGENT_TARGET.to_string());
    report
}

pub fn serve(listener: TcpListener, token: AuthToken, config: RpcConfig) -> io::Result<()> {
    let service = Arc::new(AgentService::try_new(PlatformProcessBackend)?);
    let server = Arc::new(RpcServer::with_agent_identity(
        token,
        vec![
            CAPABILITY_AGENT_LIFECYCLE.to_string(),
            CAPABILITY_PROBE.to_string(),
            CAPABILITY_CLIENT_DISCOVERY.to_string(),
            CAPABILITY_PROCESS_READ_ONLY.to_string(),
            CAPABILITY_MEMORY_READ_ONLY.to_string(),
        ],
        service.identity().clone(),
        config,
    ));
    listener.set_nonblocking(true)?;
    let shutdown_acknowledged = Arc::new(AtomicBool::new(false));
    let mut workers: Vec<ConnectionWorker> = Vec::new();
    while !shutdown_acknowledged.load(Ordering::Acquire) {
        reap_finished_workers(&mut workers)?;
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                if service.is_shutting_down() || workers.len() >= MAX_AGENT_CONNECTIONS {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let control = stream.try_clone()?;
                let server = Arc::clone(&server);
                let service = Arc::clone(&service);
                let shutdown_acknowledged = Arc::clone(&shutdown_acknowledged);
                let handle = std::thread::spawn(move || {
                    if let Err(error) = serve_connection_with_service_and_shutdown(
                        &server,
                        stream,
                        &service,
                        &shutdown_acknowledged,
                    ) {
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "component": "deimos-agent",
                                "event": "connection_error",
                                "message": error.to_string(),
                                "process_id": std::process::id()
                            })
                        );
                    }
                });
                workers.push(ConnectionWorker { control, handle });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("agent failed to accept a connection: {error}"),
                ));
            }
        }
    }
    drop(listener);
    stop_and_join_workers(&mut workers)
}

pub fn serve_connection(server: &RpcServer, stream: TcpStream) -> io::Result<()> {
    let service = AgentService::try_new(PlatformProcessBackend)?;
    serve_connection_with_service(server, stream, &service)
}

fn serve_connection_with_service<B: MemoryBackend>(
    server: &RpcServer,
    stream: TcpStream,
    service: &AgentService<B>,
) -> io::Result<()> {
    let shutdown_acknowledged = AtomicBool::new(false);
    serve_connection_with_service_and_shutdown(server, stream, service, &shutdown_acknowledged)
}

fn serve_connection_with_service_and_shutdown<B: MemoryBackend>(
    server: &RpcServer,
    stream: TcpStream,
    service: &AgentService<B>,
    shutdown_acknowledged: &AtomicBool,
) -> io::Result<()> {
    server.serve_connection_with_after_response(
        stream,
        |call| service.handle_call(call),
        |operation, _response_written| {
            let shutting_down = service.is_shutting_down();
            if shutting_down && operation == OP_AGENT_SHUTDOWN {
                shutdown_acknowledged.store(true, Ordering::Release);
            }
            shutting_down
        },
    )
}

struct ConnectionWorker {
    control: TcpStream,
    handle: JoinHandle<()>,
}

fn reap_finished_workers(workers: &mut Vec<ConnectionWorker>) -> io::Result<()> {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].handle.is_finished() {
            let worker = workers.swap_remove(index);
            worker
                .handle
                .join()
                .map_err(|_| io::Error::other("agent connection worker panicked"))?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn stop_and_join_workers(workers: &mut Vec<ConnectionWorker>) -> io::Result<()> {
    for worker in workers.iter() {
        let _ = worker.control.shutdown(Shutdown::Both);
    }

    let deadline = Instant::now() + SHUTDOWN_WORKER_TIMEOUT;
    while !workers.is_empty() && Instant::now() < deadline {
        reap_finished_workers(workers)?;
        if !workers.is_empty() {
            std::thread::sleep(ACCEPT_POLL_INTERVAL);
        }
    }
    reap_finished_workers(workers)?;
    if workers.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{} agent connection worker(s) did not stop after shutdown",
                workers.len()
            ),
        ))
    }
}

pub struct AgentService<B: MemoryBackend> {
    backend: B,
    identity: AgentIdentity,
    clients: Mutex<ClientRegistry>,
    sessions: Mutex<ProcessSessionRegistry<B::Handle>>,
    shutting_down: AtomicBool,
}

impl<B: MemoryBackend> AgentService<B> {
    pub fn try_new(backend: B) -> io::Result<Self> {
        let instance_id = AuthToken::generate()?.as_str().to_string();
        Ok(Self::with_identity(
            backend,
            AgentIdentity {
                instance_id,
                version: env!("CARGO_PKG_VERSION").to_string(),
                build_id: deimos_core::BUILD_ID.to_string(),
                process_id: std::process::id(),
            },
        ))
    }

    pub fn with_identity(backend: B, identity: AgentIdentity) -> Self {
        Self {
            backend,
            identity,
            clients: Mutex::new(ClientRegistry::new()),
            sessions: Mutex::new(ProcessSessionRegistry::new()),
            shutting_down: AtomicBool::new(false),
        }
    }

    pub fn identity(&self) -> &AgentIdentity {
        &self.identity
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    pub fn handle_call(&self, call: &RpcCall) -> Result<Value, Box<RpcError>> {
        if self.is_shutting_down()
            && !matches!(call.operation.as_str(), OP_AGENT_HEALTH | OP_AGENT_SHUTDOWN)
        {
            return Err(Box::new(RpcError::new(
                RpcErrorCode::InvalidRequest,
                "agent is shutting down; reconnect after the host starts a replacement",
                call.request_id,
                call.operation.clone(),
                call.native_context.clone(),
            )));
        }

        match call.operation.as_str() {
            OP_AGENT_HEALTH => {
                let _: AgentHealthRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let sessions = sessions.refresh_and_diagnose(&self.backend);
                encode_payload(
                    call,
                    AgentHealth {
                        identity: self.identity.clone(),
                        state: if self.is_shutting_down() {
                            AgentState::ShuttingDown
                        } else {
                            AgentState::Ready
                        },
                        sessions,
                    },
                )
            }
            OP_AGENT_SHUTDOWN => {
                let request: AgentShutdownRequest = decode_payload(call)?;
                if request.reason.trim().is_empty() {
                    return Err(Box::new(RpcError::new(
                        RpcErrorCode::InvalidRequest,
                        "agent.shutdown requires a non-empty reason",
                        call.request_id,
                        call.operation.clone(),
                        call.native_context.clone(),
                    )));
                }
                self.shutting_down.store(true, Ordering::Release);
                encode_payload(
                    call,
                    AgentShutdownResponse {
                        identity: self.identity.clone(),
                        state: AgentState::ShuttingDown,
                        reason: request.reason,
                    },
                )
            }
            CAPABILITY_PROBE => {
                let request: ProbeRequest = decode_payload(call)?;
                encode_payload(call, run(&request))
            }
            OP_CLIENT_LIST => {
                let _: ListClientsRequest = decode_payload(call)?;
                let mut clients = self.lock_clients(call)?;
                let response = clients.list(&self.backend).map_err(|error| {
                    Box::new(
                        process::ProcessApiError::from_backend(error, None, None)
                            .into_rpc_error(call.request_id, &call.operation),
                    )
                })?;
                encode_payload(call, response)
            }
            OP_MEMORY_REGIONS => {
                let request: MemorySessionRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let response =
                    memory::regions(&mut sessions, &self.backend, &request).map_err(|error| {
                        Box::new(error.into_rpc_error(call.request_id, &call.operation))
                    })?;
                encode_payload(call, response)
            }
            OP_MEMORY_READ => {
                let request: MemoryReadRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let response =
                    memory::read(&mut sessions, &self.backend, &request).map_err(|error| {
                        Box::new(error.into_rpc_error(call.request_id, &call.operation))
                    })?;
                encode_payload(call, response)
            }
            OP_MEMORY_READ_BATCH => {
                let request: MemoryBatchReadRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let response = memory::read_batch(&mut sessions, &self.backend, &request).map_err(
                    |error| Box::new(error.into_rpc_error(call.request_id, &call.operation)),
                )?;
                encode_payload(call, response)
            }
            OP_MEMORY_READ_TYPED => {
                let request: TypedMemoryReadRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let response = memory::read_typed(&mut sessions, &self.backend, &request).map_err(
                    |error| Box::new(error.into_rpc_error(call.request_id, &call.operation)),
                )?;
                encode_payload(call, response)
            }
            OP_MEMORY_SCAN => {
                let request: MemoryScanRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let response =
                    memory::scan(&mut sessions, &self.backend, &request).map_err(|error| {
                        Box::new(error.into_rpc_error(call.request_id, &call.operation))
                    })?;
                encode_payload(call, response)
            }
            OP_MEMORY_POINTER_CHAIN => {
                let request: MemoryPointerChainRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let response = memory::pointer_chain(&mut sessions, &self.backend, &request)
                    .map_err(|error| {
                        Box::new(error.into_rpc_error(call.request_id, &call.operation))
                    })?;
                encode_payload(call, response)
            }
            OP_PROCESS_LIST => {
                let request: ListProcessesRequest = decode_payload(call)?;
                let sessions = self.lock_sessions(call)?;
                let response = sessions.list(&self.backend, &request).map_err(|error| {
                    Box::new(error.into_rpc_error(call.request_id, &call.operation))
                })?;
                encode_payload(call, response)
            }
            OP_PROCESS_OPEN => {
                let request: OpenProcessRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let response = sessions.open(&self.backend, &request).map_err(|error| {
                    Box::new(error.into_rpc_error(call.request_id, &call.operation))
                })?;
                encode_payload(call, response)
            }
            OP_PROCESS_CLOSE | OP_PROCESS_STATUS | OP_MODULE_LIST => {
                let request: SessionRequest = decode_payload(call)?;
                let mut sessions = self.lock_sessions(call)?;
                let response = match call.operation.as_str() {
                    OP_PROCESS_CLOSE => encode_payload(
                        call,
                        sessions
                            .close(&self.backend, &request.session_id)
                            .map_err(|error| {
                                Box::new(error.into_rpc_error(call.request_id, &call.operation))
                            })?,
                    ),
                    OP_PROCESS_STATUS => encode_payload(
                        call,
                        sessions
                            .status(&self.backend, &request.session_id)
                            .map_err(|error| {
                                Box::new(error.into_rpc_error(call.request_id, &call.operation))
                            })?,
                    ),
                    OP_MODULE_LIST => encode_payload(
                        call,
                        sessions
                            .modules(&self.backend, &request.session_id)
                            .map_err(|error| {
                                Box::new(error.into_rpc_error(call.request_id, &call.operation))
                            })?,
                    ),
                    _ => unreachable!("operation was matched above"),
                }?;
                Ok(response)
            }
            _ => Err(Box::new(RpcError::new(
                RpcErrorCode::UnsupportedOperation,
                format!("unsupported operation: {}", call.operation),
                call.request_id,
                call.operation.clone(),
                call.native_context.clone(),
            ))),
        }
    }

    fn lock_sessions(
        &self,
        call: &RpcCall,
    ) -> Result<std::sync::MutexGuard<'_, ProcessSessionRegistry<B::Handle>>, Box<RpcError>> {
        self.sessions.lock().map_err(|_| {
            Box::new(RpcError::new(
                RpcErrorCode::Internal,
                "process session registry lock was poisoned",
                call.request_id,
                call.operation.clone(),
                call.native_context.clone(),
            ))
        })
    }

    fn lock_clients(
        &self,
        call: &RpcCall,
    ) -> Result<std::sync::MutexGuard<'_, ClientRegistry>, Box<RpcError>> {
        self.clients.lock().map_err(|_| {
            Box::new(RpcError::new(
                RpcErrorCode::Internal,
                "client discovery registry lock was poisoned",
                call.request_id,
                call.operation.clone(),
                call.native_context.clone(),
            ))
        })
    }
}

fn decode_payload<T: DeserializeOwned>(call: &RpcCall) -> Result<T, Box<RpcError>> {
    serde_json::from_value(call.payload.clone()).map_err(|error| {
        Box::new(RpcError::new(
            RpcErrorCode::InvalidRequest,
            format!("{} payload is invalid: {error}", call.operation),
            call.request_id,
            call.operation.clone(),
            call.native_context.clone(),
        ))
    })
}

fn encode_payload<T: Serialize>(call: &RpcCall, value: T) -> Result<Value, Box<RpcError>> {
    serde_json::to_value(value).map_err(|error| {
        Box::new(RpcError::new(
            RpcErrorCode::Internal,
            format!("failed to serialize {} response: {error}", call.operation),
            call.request_id,
            call.operation.clone(),
            call.native_context.clone(),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        serve, serve_connection, serve_connection_with_service, AgentService, CAPABILITY_PROBE,
        MAX_AGENT_CONNECTIONS,
    };
    use crate::process::{
        ClientWindowCandidate, MemoryBackend, OpenedProcess, ProcessBackend, ProcessBackendError,
        ProcessBackendErrorKind,
    };
    use deimos_core::client::{ListClientsRequest, ListClientsResponse, OP_CLIENT_LIST};
    use deimos_core::lifecycle::{
        AgentHealth, AgentHealthRequest, AgentIdentity, AgentShutdownRequest, AgentState,
        CAPABILITY_AGENT_LIFECYCLE, OP_AGENT_HEALTH, OP_AGENT_SHUTDOWN,
    };
    use deimos_core::memory::MemoryRegionDescriptor;
    use deimos_core::process::{
        classify_process, ModuleDescriptor, OpenProcessRequest, ProcessDescriptor, ProcessIdentity,
        ProcessSessionResponse, SessionRequest, CAPABILITY_PROCESS_READ_ONLY, OP_PROCESS_OPEN,
        OP_PROCESS_STATUS, WIZARD101_EXECUTABLE,
    };
    use deimos_core::rpc::{
        AuthToken, NativeContext, RpcCall, RpcClient, RpcClientError, RpcConfig, RpcErrorCode,
    };
    use deimos_core::{ProbeRequest, PROTOCOL_SCHEMA_VERSION};
    use serde_json::to_value;
    use std::io::Read;
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn test_identity() -> AgentIdentity {
        AgentIdentity {
            instance_id: "agent-lifecycle-test".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_id: deimos_core::BUILD_ID.to_string(),
            process_id: std::process::id(),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn standalone_probe_contract_remains_unchanged() {
        let request = ProbeRequest::default();
        let report = super::run(&request);
        assert_eq!(report.schema_version, PROTOCOL_SCHEMA_VERSION);
        assert_eq!(report.target_process, request.target_process);
        assert!(!report.success);
        assert_eq!(
            report.build_target.as_deref(),
            Some(deimos_core::WINDOWS_AGENT_TARGET)
        );
    }

    #[test]
    fn probe_round_trip_uses_the_authenticated_protocol() {
        let token = AuthToken::generate().expect("token generation should work");
        let (server, listener) = deimos_core::rpc::RpcServer::bind(
            0,
            token.clone(),
            vec![CAPABILITY_PROBE.to_string()],
            RpcConfig::default(),
        )
        .expect("server should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("server should accept");
            serve_connection(&server, stream).expect("server should serve the request");
        });

        let context = NativeContext {
            component: "deimos-native".to_string(),
            version: "test".to_string(),
            native_pid: Some(7),
            launch_id: Some("launch-7".to_string()),
        };
        let mut client = RpcClient::connect(
            address,
            token,
            vec![CAPABILITY_PROBE.to_string()],
            Some(context.clone()),
            RpcConfig::default(),
        )
        .expect("authenticated client should connect");
        assert_eq!(client.capabilities, vec![CAPABILITY_PROBE.to_string()]);

        let report: deimos_core::ProbeReport = serde_json::from_value(
            client
                .call(
                    CAPABILITY_PROBE,
                    to_value(ProbeRequest::default()).expect("request should serialize"),
                    Some(context),
                )
                .expect("probe should return a report"),
        )
        .expect("response should be a probe report");
        assert_eq!(report.schema_version, PROTOCOL_SCHEMA_VERSION);
        server_thread.join().expect("server should not panic");
    }

    #[test]
    fn invalid_probe_and_unknown_operation_return_structured_errors() {
        let token = AuthToken::generate().expect("token generation should work");
        let (server, listener) = deimos_core::rpc::RpcServer::bind(
            0,
            token.clone(),
            vec![CAPABILITY_PROBE.to_string()],
            RpcConfig::default(),
        )
        .expect("server should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("server should accept");
            serve_connection(&server, stream).expect("server should serve requests");
        });
        let context = NativeContext {
            component: "deimos-native".to_string(),
            version: "test".to_string(),
            native_pid: None,
            launch_id: Some("launch-errors".to_string()),
        };
        let mut client = RpcClient::connect(address, token, vec![], None, RpcConfig::default())
            .expect("client should connect");
        let error = client
            .call("unknown", serde_json::Value::Null, Some(context.clone()))
            .expect_err("unknown operation should fail");
        match error {
            RpcClientError::Protocol(error) => {
                assert_eq!(error.code, RpcErrorCode::UnsupportedOperation);
                assert_eq!(error.operation, "unknown");
                assert_eq!(error.native_context, Some(context.clone()));
            }
            other => panic!("unexpected error: {other}"),
        }
        let error = client
            .call(
                CAPABILITY_PROBE,
                serde_json::Value::Null,
                Some(context.clone()),
            )
            .expect_err("invalid probe should fail");
        match error {
            RpcClientError::Protocol(error) => {
                assert_eq!(error.code, RpcErrorCode::InvalidRequest);
                assert_eq!(error.operation, CAPABILITY_PROBE);
                assert_eq!(error.native_context, Some(context));
            }
            other => panic!("unexpected error: {other}"),
        }
        drop(client);
        server_thread.join().expect("server should not panic");
    }

    #[derive(Clone)]
    struct RpcTestBackend {
        alive: Arc<AtomicBool>,
    }

    impl ProcessBackend for RpcTestBackend {
        type Handle = ();

        fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
            Ok(vec![rpc_test_process()])
        }

        fn list_client_windows(&self) -> Result<Vec<ClientWindowCandidate>, ProcessBackendError> {
            let process_identity = rpc_test_process()
                .identity
                .expect("RPC test process should have an identity");
            Ok(vec![ClientWindowCandidate {
                native_window_id: 0x1234,
                pid: 336,
                process_identity,
                is_foreground: true,
                left: 20,
                top: 10,
            }])
        }

        fn open_process(
            &self,
            pid: u32,
        ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
            if pid != 336 {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::NotFound,
                    "process not found",
                ));
            }
            if !self.alive.load(Ordering::SeqCst) {
                return Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Exited,
                    "process exited",
                ));
            }
            Ok(OpenedProcess {
                handle: (),
                process: rpc_test_process(),
            })
        }

        fn validate_process(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<(), ProcessBackendError> {
            if self.alive.load(Ordering::SeqCst) {
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

    impl MemoryBackend for RpcTestBackend {
        fn enumerate_memory_regions(
            &self,
            _handle: &Self::Handle,
            _expected: &ProcessIdentity,
        ) -> Result<Vec<MemoryRegionDescriptor>, ProcessBackendError> {
            Ok(Vec::new())
        }

        fn read_memory(
            &self,
            _handle: &Self::Handle,
            _address: usize,
            _size: usize,
        ) -> Result<Vec<u8>, ProcessBackendError> {
            Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                "RPC test backend has no memory fixture",
            ))
        }
    }

    fn rpc_test_process() -> ProcessDescriptor {
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

    #[test]
    fn client_list_returns_agent_owned_identity_without_a_native_window_handle() {
        let service = AgentService::with_identity(
            RpcTestBackend {
                alive: Arc::new(AtomicBool::new(true)),
            },
            test_identity(),
        );
        let call = RpcCall {
            request_id: 1,
            operation: OP_CLIENT_LIST.to_string(),
            payload: to_value(ListClientsRequest::default())
                .expect("client request should serialize"),
            native_context: None,
        };

        let value = service
            .handle_call(&call)
            .expect("client listing should succeed");
        assert!(value
            .get("clients")
            .and_then(|clients| clients.get(0))
            .and_then(|client| client.get("window_handle"))
            .is_none());
        let response: ListClientsResponse =
            serde_json::from_value(value).expect("client response should deserialize");
        assert_eq!(response.clients.len(), 1);
        assert_eq!(response.clients[0].process.pid, 336);
        assert!(response.clients[0].is_foreground);
    }

    #[test]
    fn authenticated_clients_receive_distinct_agent_owned_sessions() {
        let token = AuthToken::generate().expect("token generation should work");
        let (server, listener) = deimos_core::rpc::RpcServer::bind(
            0,
            token.clone(),
            vec![CAPABILITY_PROCESS_READ_ONLY.to_string()],
            RpcConfig::default(),
        )
        .expect("server should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server = Arc::new(server);
        let backend = RpcTestBackend {
            alive: Arc::new(AtomicBool::new(true)),
        };
        let service = Arc::new(
            AgentService::try_new(backend.clone()).expect("agent identity should be generated"),
        );
        let server_thread = thread::spawn(move || {
            let mut workers = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("server should accept");
                let server = Arc::clone(&server);
                let service = Arc::clone(&service);
                workers.push(thread::spawn(move || {
                    serve_connection_with_service(&server, stream, &service)
                        .expect("server should serve process requests");
                }));
            }
            for worker in workers {
                worker.join().expect("connection worker should not panic");
            }
        });

        let mut first = RpcClient::connect(
            address,
            token.clone(),
            vec![CAPABILITY_PROCESS_READ_ONLY.to_string()],
            None,
            RpcConfig::default(),
        )
        .expect("first client should authenticate");
        let mut second = RpcClient::connect(
            address,
            token,
            vec![CAPABILITY_PROCESS_READ_ONLY.to_string()],
            None,
            RpcConfig::default(),
        )
        .expect("second client should authenticate");
        let request = to_value(OpenProcessRequest {
            pid: 336,
            expected_identity: None,
        })
        .expect("request should serialize");
        let first_session: ProcessSessionResponse = serde_json::from_value(
            first
                .call(OP_PROCESS_OPEN, request.clone(), None)
                .expect("first open should succeed"),
        )
        .expect("response should deserialize");
        let second_session: ProcessSessionResponse = serde_json::from_value(
            second
                .call(OP_PROCESS_OPEN, request, None)
                .expect("second open should succeed"),
        )
        .expect("response should deserialize");

        assert_ne!(first_session.session_id, second_session.session_id);
        backend.alive.store(false, Ordering::SeqCst);
        let stale = first
            .call(
                OP_PROCESS_STATUS,
                to_value(SessionRequest {
                    session_id: first_session.session_id.clone(),
                })
                .expect("status request should serialize"),
                None,
            )
            .expect_err("stale session should fail through RPC");
        match stale {
            RpcClientError::Protocol(error) => {
                assert_eq!(error.code, RpcErrorCode::ProcessExited);
                assert_eq!(
                    error.details.get("session_id"),
                    Some(&first_session.session_id.0)
                );
            }
            other => panic!("unexpected stale-session error: {other}"),
        }
        drop(first);
        drop(second);
        server_thread.join().expect("server should not panic");
    }

    #[test]
    fn disconnect_does_not_stop_agent_and_shutdown_is_acknowledged() {
        let token = AuthToken::generate().expect("token generation should work");
        let listener = std::net::TcpListener::bind(deimos_core::rpc::loopback_address(0))
            .expect("agent should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let server_token = token.clone();
        let config = RpcConfig {
            io_timeout: std::time::Duration::from_millis(200),
            ..RpcConfig::default()
        };
        let server_thread = thread::spawn(move || {
            serve(listener, server_token, config).expect("agent should stop gracefully");
        });

        let first_identity = {
            let client = RpcClient::connect(
                address,
                token.clone(),
                vec![CAPABILITY_AGENT_LIFECYCLE.to_string()],
                None,
                RpcConfig::default(),
            )
            .expect("first host should complete readiness handshake");
            assert_eq!(
                client.capabilities,
                vec![CAPABILITY_AGENT_LIFECYCLE.to_string()]
            );
            client.agent.expect("handshake should identify the agent")
        };

        let reconnected = RpcClient::connect(
            address,
            token.clone(),
            vec![CAPABILITY_AGENT_LIFECYCLE.to_string()],
            None,
            config,
        )
        .expect("host should reconnect after disconnect");
        assert_eq!(
            reconnected.agent.as_ref(),
            Some(&first_identity),
            "disconnect must not replace the agent"
        );
        let health_calls = Arc::new(AtomicUsize::new(0));
        let stop_spam = Arc::new(AtomicBool::new(false));
        let (spam_done_tx, spam_done_rx) = std::sync::mpsc::channel();
        let spam_health_calls = Arc::clone(&health_calls);
        let spam_stop = Arc::clone(&stop_spam);
        let spam_thread = thread::spawn(move || {
            let mut client = reconnected;
            while !spam_stop.load(Ordering::Acquire) {
                match client.call(
                    OP_AGENT_HEALTH,
                    to_value(AgentHealthRequest::default()).expect("health should serialize"),
                    None,
                ) {
                    Ok(payload) => {
                        let health: AgentHealth =
                            serde_json::from_value(payload).expect("health should deserialize");
                        assert_eq!(health.identity, first_identity);
                        spam_health_calls.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => break,
                }
            }
            let _ = spam_done_tx.send(());
        });
        let spam_start_deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while health_calls.load(Ordering::Relaxed) < 3
            && std::time::Instant::now() < spam_start_deadline
        {
            thread::yield_now();
        }
        assert!(
            health_calls.load(Ordering::Relaxed) >= 3,
            "health spam client should make progress before shutdown"
        );

        let mut shutdown_client = RpcClient::connect(
            address,
            token,
            vec![CAPABILITY_AGENT_LIFECYCLE.to_string()],
            None,
            config,
        )
        .expect("shutdown client should connect");
        let shutdown = shutdown_client
            .call(
                OP_AGENT_SHUTDOWN,
                to_value(AgentShutdownRequest {
                    reason: "test complete".to_string(),
                })
                .expect("shutdown should serialize"),
                None,
            )
            .expect("shutdown should be acknowledged");
        assert_eq!(
            shutdown.get("state").and_then(serde_json::Value::as_str),
            Some("shutting_down")
        );
        let spam_stopped = spam_done_rx.recv_timeout(std::time::Duration::from_millis(500));
        if spam_stopped.is_err() {
            stop_spam.store(true, Ordering::Release);
        }
        drop(shutdown_client);
        spam_thread
            .join()
            .expect("health spam client should not panic");
        server_thread.join().expect("agent server should not panic");
        spam_stopped.expect(
            "shutdown acknowledgement must close an authenticated client that keeps sending health",
        );
    }

    #[test]
    fn half_open_connections_are_bounded_and_finished_workers_are_reaped() {
        let token = AuthToken::generate().expect("token generation should work");
        let listener = std::net::TcpListener::bind(deimos_core::rpc::loopback_address(0))
            .expect("agent should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let config = RpcConfig {
            io_timeout: std::time::Duration::from_millis(500),
            ..RpcConfig::default()
        };
        let server_token = token.clone();
        let server_thread = thread::spawn(move || {
            serve(listener, server_token, config).expect("agent should stop gracefully");
        });

        let half_open = (0..MAX_AGENT_CONNECTIONS)
            .map(|_| {
                let stream = TcpStream::connect(address).expect("half-open client should connect");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(150)))
                    .expect("read timeout should apply");
                stream
            })
            .collect::<Vec<_>>();
        thread::sleep(std::time::Duration::from_millis(50));
        let mut overflow = (0..4)
            .map(|_| {
                let stream = TcpStream::connect(address).expect("overflow client should connect");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(150)))
                    .expect("read timeout should apply");
                stream
            })
            .collect::<Vec<_>>();
        thread::sleep(std::time::Duration::from_millis(20));
        let mut rejected = 0;
        for stream in &mut overflow {
            let mut byte = [0u8; 1];
            if !matches!(
                stream.read(&mut byte),
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::WouldBlock
            ) {
                rejected += 1;
            }
        }
        assert!(rejected > 0, "connections beyond the bound must be closed");
        drop(half_open);
        drop(overflow);
        thread::sleep(std::time::Duration::from_millis(50));

        let mut client = RpcClient::connect(
            address,
            token,
            vec![CAPABILITY_AGENT_LIFECYCLE.to_string()],
            None,
            config,
        )
        .expect("capacity should recover after timed-out workers are reaped");
        client
            .call(
                OP_AGENT_SHUTDOWN,
                to_value(AgentShutdownRequest {
                    reason: "resource-bound test complete".to_string(),
                })
                .expect("shutdown should serialize"),
                None,
            )
            .expect("shutdown should be acknowledged");
        drop(client);
        server_thread.join().expect("agent server should not panic");
    }

    #[test]
    fn health_invalidates_exited_game_sessions_without_stopping_agent() {
        let backend = RpcTestBackend {
            alive: Arc::new(AtomicBool::new(true)),
        };
        let service = AgentService::with_identity(backend.clone(), test_identity());
        let open_call = RpcCall {
            request_id: 1,
            operation: OP_PROCESS_OPEN.to_string(),
            payload: to_value(OpenProcessRequest {
                pid: 336,
                expected_identity: None,
            })
            .expect("open request should serialize"),
            native_context: None,
        };
        service
            .handle_call(&open_call)
            .expect("game session should open");
        backend.alive.store(false, Ordering::SeqCst);

        let health_call = RpcCall {
            request_id: 2,
            operation: OP_AGENT_HEALTH.to_string(),
            payload: to_value(AgentHealthRequest::default())
                .expect("health request should serialize"),
            native_context: None,
        };
        let health: AgentHealth = serde_json::from_value(
            service
                .handle_call(&health_call)
                .expect("agent health should remain available"),
        )
        .expect("health should deserialize");

        assert_eq!(health.state, AgentState::Ready);
        assert_eq!(health.sessions.open, 0);
        assert_eq!(health.sessions.exited, 1);
        assert!(!service.is_shutting_down());
        assert_eq!(
            serde_json::from_value::<AgentHealth>(
                service
                    .handle_call(&health_call)
                    .expect("agent should remain healthy after game exit")
            )
            .expect("health should deserialize")
            .state,
            AgentState::Ready
        );
    }

    #[test]
    fn shutting_down_rejects_new_work_with_protocol_1_0_error_code() {
        let backend = RpcTestBackend {
            alive: Arc::new(AtomicBool::new(true)),
        };
        let service = AgentService::with_identity(backend, test_identity());
        service
            .handle_call(&RpcCall {
                request_id: 1,
                operation: OP_AGENT_SHUTDOWN.to_string(),
                payload: to_value(AgentShutdownRequest {
                    reason: "compatibility test".to_string(),
                })
                .expect("shutdown should serialize"),
                native_context: None,
            })
            .expect("shutdown should be accepted");

        let error = service
            .handle_call(&RpcCall {
                request_id: 2,
                operation: CAPABILITY_PROBE.to_string(),
                payload: to_value(ProbeRequest::default()).expect("probe should serialize"),
                native_context: None,
            })
            .expect_err("new work should be rejected during shutdown");
        assert_eq!(error.code, RpcErrorCode::InvalidRequest);
    }
}
