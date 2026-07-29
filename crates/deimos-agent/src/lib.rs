use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

use process::{MemoryBackend, ProcessSessionRegistry};

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
            CAPABILITY_PROCESS_READ_ONLY.to_string(),
            CAPABILITY_MEMORY_READ_ONLY.to_string(),
        ],
        service.identity().clone(),
        config,
    ));
    listener.set_nonblocking(true)?;
    let mut workers = Vec::new();
    while !service.is_shutting_down() {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                let server = Arc::clone(&server);
                let service = Arc::clone(&service);
                workers.push(std::thread::spawn(move || {
                    if let Err(error) = serve_connection_with_service(&server, stream, &service) {
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
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
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
    for worker in workers {
        worker
            .join()
            .map_err(|_| io::Error::other("agent connection worker panicked"))?;
    }
    Ok(())
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
    server.serve_connection(stream, |call| service.handle_call(call))
}

pub struct AgentService<B: MemoryBackend> {
    backend: B,
    identity: AgentIdentity,
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
                process_id: std::process::id(),
            },
        ))
    }

    pub fn with_identity(backend: B, identity: AgentIdentity) -> Self {
        Self {
            backend,
            identity,
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
                RpcErrorCode::AgentShuttingDown,
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
    };
    use crate::process::{
        MemoryBackend, OpenedProcess, ProcessBackend, ProcessBackendError, ProcessBackendErrorKind,
    };
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn test_identity() -> AgentIdentity {
        AgentIdentity {
            instance_id: "agent-lifecycle-test".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            process_id: std::process::id(),
        }
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
        let server_thread = thread::spawn(move || {
            serve(listener, server_token, RpcConfig::default())
                .expect("agent should stop gracefully");
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

        let mut reconnected = RpcClient::connect(
            address,
            token,
            vec![CAPABILITY_AGENT_LIFECYCLE.to_string()],
            None,
            RpcConfig::default(),
        )
        .expect("host should reconnect after disconnect");
        assert_eq!(
            reconnected.agent.as_ref(),
            Some(&first_identity),
            "disconnect must not replace the agent"
        );
        let health: AgentHealth = serde_json::from_value(
            reconnected
                .call(
                    OP_AGENT_HEALTH,
                    to_value(AgentHealthRequest::default()).expect("health should serialize"),
                    None,
                )
                .expect("reconnected agent should be healthy"),
        )
        .expect("health should deserialize");
        assert_eq!(health.state, AgentState::Ready);

        let shutdown = reconnected
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
        drop(reconnected);
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
}
