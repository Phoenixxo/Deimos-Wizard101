use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use deimos_core::lifecycle::{
    AgentHealth, AgentHealthRequest, AgentIdentity, AgentShutdownRequest, AgentShutdownResponse,
    AgentState, CAPABILITY_AGENT_LIFECYCLE, OP_AGENT_HEALTH, OP_AGENT_SHUTDOWN,
};
use deimos_core::rpc::{AuthToken, NativeContext, RpcClient, RpcClientError, RpcConfig};
use serde::Serialize;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BottleId(String);

impl BottleId {
    pub fn new(value: impl Into<String>) -> Result<Self, LifecycleError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(LifecycleError::new(
                LifecycleErrorCode::InvalidBottleId,
                "",
                "bottle ID must not be empty",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct AgentEndpoint {
    pub address: SocketAddr,
    pub token: AuthToken,
}

pub trait AgentProcess: Send {
    fn try_wait(&mut self) -> io::Result<Option<AgentExit>>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentExit {
    pub code: Option<i32>,
    pub stderr: String,
}

pub struct AgentLaunch {
    pub endpoint: AgentEndpoint,
    pub process: Box<dyn AgentProcess>,
}

pub trait AgentRuntime {
    /// Return reconnect metadata previously recorded for this opaque bottle.
    /// DMS-009 owns how that metadata is discovered and persisted.
    fn discover(&mut self, bottle: &BottleId) -> Result<Option<AgentEndpoint>, String>;

    /// Start the already-selected agent artifact in the already-selected
    /// runtime. This lifecycle layer does not choose paths or Wine binaries.
    fn launch(&mut self, bottle: &BottleId) -> Result<AgentLaunch, String>;

    /// Wait for graceful exit when possible, clear stale rendezvous state, and
    /// safely terminate an unresponsive old process before `launch` returns.
    fn retire(
        &mut self,
        bottle: &BottleId,
        endpoint: &AgentEndpoint,
        reason: &str,
    ) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDisposition {
    Reused,
    Reconnected,
    Started,
    Replaced,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReadyAgent {
    pub bottle_id: String,
    pub identity: AgentIdentity,
    pub disposition: AgentDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleErrorCode {
    InvalidBottleId,
    DiscoveryFailed,
    LaunchFailed,
    HandshakeFailed,
    HealthCheckFailed,
    AgentExited,
    MissingCapability,
    IdentityMismatch,
    VersionMismatch,
    ShutdownFailed,
    StaleRecoveryFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LifecycleError {
    pub code: LifecycleErrorCode,
    pub message: String,
    pub bottle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl LifecycleError {
    fn new(
        code: LifecycleErrorCode,
        bottle_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            bottle_id: bottle_id.into(),
            instance_id: None,
            details: BTreeMap::new(),
        }
    }

    fn with_detail(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(name.into(), value.into());
        self
    }

    fn with_instance(mut self, identity: &AgentIdentity) -> Self {
        self.instance_id = Some(identity.instance_id.clone());
        self
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (bottle {}, code {:?})",
            self.message, self.bottle_id, self.code
        )
    }
}

impl std::error::Error for LifecycleError {}

struct ManagedAgent {
    endpoint: AgentEndpoint,
    identity: AgentIdentity,
    client: RpcClient,
    process: Option<Box<dyn AgentProcess>>,
}

enum Candidate {
    Ready {
        client: RpcClient,
        identity: AgentIdentity,
    },
    VersionMismatch {
        client: RpcClient,
        identity: AgentIdentity,
    },
}

pub struct AgentManager<R: AgentRuntime> {
    runtime: R,
    expected_version: String,
    native_context: NativeContext,
    config: RpcConfig,
    readiness_timeout: Duration,
    retry_interval: Duration,
    managed: HashMap<BottleId, ManagedAgent>,
}

impl<R: AgentRuntime> AgentManager<R> {
    pub fn new(
        runtime: R,
        expected_version: impl Into<String>,
        native_context: NativeContext,
    ) -> Self {
        Self {
            runtime,
            expected_version: expected_version.into(),
            native_context,
            config: RpcConfig::default(),
            readiness_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_millis(50),
            managed: HashMap::new(),
        }
    }

    pub fn with_timing(mut self, readiness_timeout: Duration, retry_interval: Duration) -> Self {
        self.readiness_timeout = readiness_timeout;
        self.retry_interval = retry_interval;
        self
    }

    pub fn with_rpc_config(mut self, config: RpcConfig) -> Self {
        self.config = config;
        self
    }

    pub fn ensure_agent(&mut self, bottle: BottleId) -> Result<ReadyAgent, LifecycleError> {
        if self.managed.contains_key(&bottle) {
            match self.health(&bottle) {
                Ok(health) => {
                    return Ok(ReadyAgent {
                        bottle_id: bottle.0,
                        identity: health.identity,
                        disposition: AgentDisposition::Reused,
                    })
                }
                Err(_) => {
                    self.managed.remove(&bottle);
                }
            }
        }

        let existing = self.runtime.discover(&bottle).map_err(|error| {
            LifecycleError::new(
                LifecycleErrorCode::DiscoveryFailed,
                bottle.as_str(),
                format!("failed to discover an existing agent: {error}"),
            )
        })?;

        let mut replacement = false;
        if let Some(endpoint) = existing {
            match self.connect_candidate(&bottle, &endpoint) {
                Ok(Candidate::Ready { client, identity }) => {
                    let ready = ReadyAgent {
                        bottle_id: bottle.0.clone(),
                        identity: identity.clone(),
                        disposition: AgentDisposition::Reconnected,
                    };
                    self.managed.insert(
                        bottle,
                        ManagedAgent {
                            endpoint,
                            identity,
                            client,
                            process: None,
                        },
                    );
                    return Ok(ready);
                }
                Ok(Candidate::VersionMismatch {
                    mut client,
                    identity,
                }) => {
                    replacement = true;
                    let reason = format!(
                        "replace agent version {} with {}",
                        identity.version, self.expected_version
                    );
                    let _ = self.request_shutdown(&bottle, &mut client, &identity, &reason);
                    drop(client);
                    self.retire(&bottle, &endpoint, &reason)?;
                }
                Err(error) => {
                    replacement = true;
                    let reason = format!("recover stale agent state after: {}", error.message);
                    self.retire(&bottle, &endpoint, &reason)?;
                }
            }
        }

        let launch = self.runtime.launch(&bottle).map_err(|error| {
            LifecycleError::new(
                LifecycleErrorCode::LaunchFailed,
                bottle.as_str(),
                format!("failed to launch the agent: {error}"),
            )
        })?;
        self.finish_launch(bottle, launch, replacement)
    }

    pub fn health(&mut self, bottle: &BottleId) -> Result<AgentHealth, LifecycleError> {
        let managed = self.managed.get_mut(bottle).ok_or_else(|| {
            LifecycleError::new(
                LifecycleErrorCode::HealthCheckFailed,
                bottle.as_str(),
                "no managed agent exists for this bottle; call ensure_agent first",
            )
        })?;

        if let Some(process) = managed.process.as_mut() {
            if let Some(exit) = process.try_wait().map_err(|error| {
                LifecycleError::new(
                    LifecycleErrorCode::AgentExited,
                    bottle.as_str(),
                    format!("failed to inspect the agent process: {error}"),
                )
                .with_instance(&managed.identity)
            })? {
                let code = exit
                    .code
                    .map_or_else(|| "signal_or_unknown".to_string(), |code| code.to_string());
                return Err(LifecycleError::new(
                    LifecycleErrorCode::AgentExited,
                    bottle.as_str(),
                    format!(
                        "agent exited unexpectedly with code {code}; restart the agent for this bottle"
                    ),
                )
                .with_instance(&managed.identity)
                .with_detail("exit_code", code)
                .with_detail("stderr", exit.stderr));
            }
        }

        call_health(
            bottle,
            &mut managed.client,
            &managed.identity,
            self.native_context.clone(),
        )
    }

    pub fn shutdown(
        &mut self,
        bottle: &BottleId,
        reason: impl Into<String>,
    ) -> Result<(), LifecycleError> {
        let reason = reason.into();
        let Some(mut managed) = self.managed.remove(bottle) else {
            return Ok(());
        };
        let shutdown =
            self.request_shutdown(bottle, &mut managed.client, &managed.identity, &reason);
        drop(managed.client);
        let retired = self.retire(bottle, &managed.endpoint, &reason);
        shutdown.and(retired)
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    fn connect_candidate(
        &self,
        bottle: &BottleId,
        endpoint: &AgentEndpoint,
    ) -> Result<Candidate, LifecycleError> {
        let mut client = RpcClient::connect(
            endpoint.address,
            endpoint.token.clone(),
            vec![CAPABILITY_AGENT_LIFECYCLE.to_string()],
            Some(self.native_context.clone()),
            self.config,
        )
        .map_err(|error| handshake_error(bottle, error))?;
        if !client
            .capabilities
            .iter()
            .any(|capability| capability == CAPABILITY_AGENT_LIFECYCLE)
        {
            return Err(LifecycleError::new(
                LifecycleErrorCode::MissingCapability,
                bottle.as_str(),
                "agent handshake did not negotiate lifecycle capability; replace the agent",
            ));
        }
        let identity = client.agent.clone().ok_or_else(|| {
            LifecycleError::new(
                LifecycleErrorCode::HandshakeFailed,
                bottle.as_str(),
                "agent handshake omitted identity diagnostics; replace the agent",
            )
        })?;
        if identity.version != self.expected_version {
            return Ok(Candidate::VersionMismatch { client, identity });
        }
        call_health(bottle, &mut client, &identity, self.native_context.clone())?;
        Ok(Candidate::Ready { client, identity })
    }

    fn finish_launch(
        &mut self,
        bottle: BottleId,
        mut launch: AgentLaunch,
        replacement: bool,
    ) -> Result<ReadyAgent, LifecycleError> {
        let deadline = Instant::now() + self.readiness_timeout;
        loop {
            if let Some(exit) = launch.process.try_wait().map_err(|error| {
                LifecycleError::new(
                    LifecycleErrorCode::AgentExited,
                    bottle.as_str(),
                    format!("failed to inspect the starting agent process: {error}"),
                )
            })? {
                let mut error = LifecycleError::new(
                    LifecycleErrorCode::AgentExited,
                    bottle.as_str(),
                    "agent exited before completing its readiness handshake",
                )
                .with_detail(
                    "exit_code",
                    exit.code
                        .map_or_else(|| "signal_or_unknown".to_string(), |code| code.to_string()),
                )
                .with_detail("stderr", exit.stderr);
                self.record_failed_launch_cleanup(&bottle, &launch.endpoint, &mut error);
                return Err(error);
            }

            let last_error = match self.connect_candidate(&bottle, &launch.endpoint) {
                Ok(Candidate::Ready { client, identity }) => {
                    let disposition = if replacement {
                        AgentDisposition::Replaced
                    } else {
                        AgentDisposition::Started
                    };
                    let ready = ReadyAgent {
                        bottle_id: bottle.0.clone(),
                        identity: identity.clone(),
                        disposition,
                    };
                    self.managed.insert(
                        bottle,
                        ManagedAgent {
                            endpoint: launch.endpoint,
                            identity,
                            client,
                            process: Some(launch.process),
                        },
                    );
                    return Ok(ready);
                }
                Ok(Candidate::VersionMismatch {
                    mut client,
                    identity,
                }) => {
                    let reason = format!(
                        "launched agent version {} does not match required version {}",
                        identity.version, self.expected_version
                    );
                    let _ = self.request_shutdown(&bottle, &mut client, &identity, &reason);
                    drop(client);
                    let mut error = LifecycleError::new(
                        LifecycleErrorCode::VersionMismatch,
                        bottle.as_str(),
                        reason,
                    )
                    .with_instance(&identity)
                    .with_detail("expected_version", self.expected_version.clone())
                    .with_detail("actual_version", identity.version);
                    self.record_failed_launch_cleanup(&bottle, &launch.endpoint, &mut error);
                    return Err(error);
                }
                Err(error) => error,
            };

            if Instant::now() >= deadline {
                let mut error = LifecycleError::new(
                    LifecycleErrorCode::HandshakeFailed,
                    bottle.as_str(),
                    "agent did not become ready before the handshake deadline",
                );
                error
                    .details
                    .insert("last_error".to_string(), last_error.message);
                self.record_failed_launch_cleanup(&bottle, &launch.endpoint, &mut error);
                return Err(error);
            }
            thread::sleep(
                self.retry_interval
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn request_shutdown(
        &self,
        bottle: &BottleId,
        client: &mut RpcClient,
        identity: &AgentIdentity,
        reason: &str,
    ) -> Result<(), LifecycleError> {
        let response = client
            .call(
                OP_AGENT_SHUTDOWN,
                serde_json::to_value(AgentShutdownRequest {
                    reason: reason.to_string(),
                })
                .expect("shutdown request should serialize"),
                Some(self.native_context.clone()),
            )
            .map_err(|error| {
                LifecycleError::new(
                    LifecycleErrorCode::ShutdownFailed,
                    bottle.as_str(),
                    format!("agent rejected graceful shutdown: {error}"),
                )
                .with_instance(identity)
            })?;
        let response: AgentShutdownResponse =
            serde_json::from_value(response).map_err(|error| {
                LifecycleError::new(
                    LifecycleErrorCode::ShutdownFailed,
                    bottle.as_str(),
                    format!("agent returned an invalid shutdown response: {error}"),
                )
                .with_instance(identity)
            })?;
        if response.identity != *identity || response.state != AgentState::ShuttingDown {
            return Err(LifecycleError::new(
                LifecycleErrorCode::IdentityMismatch,
                bottle.as_str(),
                "shutdown response did not match the connected agent",
            )
            .with_instance(identity));
        }
        Ok(())
    }

    fn retire(
        &mut self,
        bottle: &BottleId,
        endpoint: &AgentEndpoint,
        reason: &str,
    ) -> Result<(), LifecycleError> {
        self.runtime
            .retire(bottle, endpoint, reason)
            .map_err(|error| {
                LifecycleError::new(
                    LifecycleErrorCode::StaleRecoveryFailed,
                    bottle.as_str(),
                    format!("failed to retire stale agent state: {error}"),
                )
            })
    }

    fn record_failed_launch_cleanup(
        &mut self,
        bottle: &BottleId,
        endpoint: &AgentEndpoint,
        error: &mut LifecycleError,
    ) {
        if let Err(cleanup) = self.retire(bottle, endpoint, "clean up failed agent launch") {
            error
                .details
                .insert("cleanup_error".to_string(), cleanup.message);
        }
    }
}

fn call_health(
    bottle: &BottleId,
    client: &mut RpcClient,
    handshake_identity: &AgentIdentity,
    context: NativeContext,
) -> Result<AgentHealth, LifecycleError> {
    let payload = client
        .call(
            OP_AGENT_HEALTH,
            serde_json::to_value(AgentHealthRequest::default())
                .expect("health request should serialize"),
            Some(context),
        )
        .map_err(|error| {
            LifecycleError::new(
                LifecycleErrorCode::HealthCheckFailed,
                bottle.as_str(),
                format!("agent health check failed: {error}"),
            )
            .with_instance(handshake_identity)
        })?;
    let health: AgentHealth = serde_json::from_value(payload).map_err(|error| {
        LifecycleError::new(
            LifecycleErrorCode::HealthCheckFailed,
            bottle.as_str(),
            format!("agent returned an invalid health response: {error}"),
        )
        .with_instance(handshake_identity)
    })?;
    if health.identity != *handshake_identity {
        return Err(LifecycleError::new(
            LifecycleErrorCode::IdentityMismatch,
            bottle.as_str(),
            "health response identity does not match the readiness handshake",
        )
        .with_instance(handshake_identity));
    }
    if health.state != AgentState::Ready {
        return Err(LifecycleError::new(
            LifecycleErrorCode::HealthCheckFailed,
            bottle.as_str(),
            "agent is shutting down and is not ready for work",
        )
        .with_instance(handshake_identity));
    }
    Ok(health)
}

fn handshake_error(bottle: &BottleId, error: RpcClientError) -> LifecycleError {
    LifecycleError::new(
        LifecycleErrorCode::HandshakeFailed,
        bottle.as_str(),
        format!("agent readiness handshake failed: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use deimos_core::lifecycle::{
        AgentHealth, AgentHealthRequest, AgentShutdownRequest, AgentShutdownResponse,
        SessionDiagnostics,
    };
    use deimos_core::rpc::{loopback_address, RpcCall, RpcError, RpcServer};
    use serde_json::Value;

    use super::*;

    #[derive(Clone)]
    struct TestRuntime {
        state: Arc<Mutex<TestRuntimeState>>,
    }

    struct TestRuntimeState {
        current: Option<AgentEndpoint>,
        agents: HashMap<SocketAddr, Arc<AtomicBool>>,
        launch_count: usize,
        retire_count: usize,
        launch_version: String,
        launch_unready: bool,
        process_exit: Arc<Mutex<Option<AgentExit>>>,
    }

    impl TestRuntime {
        fn new(version: &str) -> Self {
            Self {
                state: Arc::new(Mutex::new(TestRuntimeState {
                    current: None,
                    agents: HashMap::new(),
                    launch_count: 0,
                    retire_count: 0,
                    launch_version: version.to_string(),
                    launch_unready: false,
                    process_exit: Arc::new(Mutex::new(None)),
                })),
            }
        }

        fn install_existing(&self, version: &str) -> AgentEndpoint {
            let (endpoint, shutdown) = start_test_agent(version);
            let mut state = self.state.lock().expect("runtime state should lock");
            state.current = Some(endpoint.clone());
            state.agents.insert(endpoint.address, shutdown);
            endpoint
        }

        fn install_stale(&self) {
            let listener =
                TcpListener::bind(loopback_address(0)).expect("stale endpoint should bind");
            let address = listener
                .local_addr()
                .expect("stale endpoint should have an address");
            drop(listener);
            self.state
                .lock()
                .expect("runtime state should lock")
                .current = Some(AgentEndpoint {
                address,
                token: AuthToken::generate().expect("token should generate"),
            });
        }

        fn launch_count(&self) -> usize {
            self.state
                .lock()
                .expect("runtime state should lock")
                .launch_count
        }

        fn retire_count(&self) -> usize {
            self.state
                .lock()
                .expect("runtime state should lock")
                .retire_count
        }

        fn set_process_exit(&self, exit: AgentExit) {
            *self
                .state
                .lock()
                .expect("runtime state should lock")
                .process_exit
                .lock()
                .expect("process state should lock") = Some(exit);
        }

        fn set_launch_unready(&self) {
            self.state
                .lock()
                .expect("runtime state should lock")
                .launch_unready = true;
        }
    }

    impl AgentRuntime for TestRuntime {
        fn discover(&mut self, _bottle: &BottleId) -> Result<Option<AgentEndpoint>, String> {
            Ok(self
                .state
                .lock()
                .map_err(|error| error.to_string())?
                .current
                .clone())
        }

        fn launch(&mut self, _bottle: &BottleId) -> Result<AgentLaunch, String> {
            let (version, launch_unready, process_exit) = {
                let state = self.state.lock().map_err(|error| error.to_string())?;
                (
                    state.launch_version.clone(),
                    state.launch_unready,
                    Arc::clone(&state.process_exit),
                )
            };
            let (endpoint, shutdown) = if launch_unready {
                let listener =
                    TcpListener::bind(loopback_address(0)).map_err(|error| error.to_string())?;
                let address = listener.local_addr().map_err(|error| error.to_string())?;
                drop(listener);
                (
                    AgentEndpoint {
                        address,
                        token: AuthToken::generate().map_err(|error| error.to_string())?,
                    },
                    Arc::new(AtomicBool::new(false)),
                )
            } else {
                start_test_agent(&version)
            };
            {
                let mut state = self.state.lock().map_err(|error| error.to_string())?;
                state.launch_count += 1;
                state.current = Some(endpoint.clone());
                state.agents.insert(endpoint.address, shutdown);
            }
            Ok(AgentLaunch {
                endpoint,
                process: Box::new(TestProcess { exit: process_exit }),
            })
        }

        fn retire(
            &mut self,
            _bottle: &BottleId,
            endpoint: &AgentEndpoint,
            _reason: &str,
        ) -> Result<(), String> {
            let mut state = self.state.lock().map_err(|error| error.to_string())?;
            state.retire_count += 1;
            if let Some(shutdown) = state.agents.remove(&endpoint.address) {
                shutdown.store(true, Ordering::Release);
            }
            if state
                .current
                .as_ref()
                .is_some_and(|current| current.address == endpoint.address)
            {
                state.current = None;
            }
            Ok(())
        }
    }

    struct TestProcess {
        exit: Arc<Mutex<Option<AgentExit>>>,
    }

    impl AgentProcess for TestProcess {
        fn try_wait(&mut self) -> io::Result<Option<AgentExit>> {
            Ok(self.exit.lock().expect("process state should lock").clone())
        }
    }

    fn context() -> NativeContext {
        NativeContext {
            component: "deimos-native-test".to_string(),
            version: "test".to_string(),
            native_pid: Some(std::process::id()),
            launch_id: Some("lifecycle-test".to_string()),
        }
    }

    fn bottle() -> BottleId {
        BottleId::new("portable-test-bottle").expect("bottle ID should be valid")
    }

    fn manager(runtime: TestRuntime, version: &str) -> AgentManager<TestRuntime> {
        AgentManager::new(runtime, version, context())
            .with_timing(Duration::from_millis(100), Duration::from_millis(2))
    }

    fn start_test_agent(version: &str) -> (AgentEndpoint, Arc<AtomicBool>) {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

        let identity = AgentIdentity {
            instance_id: format!("test-agent-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            version: version.to_string(),
            process_id: std::process::id(),
        };
        let token = AuthToken::generate().expect("token should generate");
        let listener = TcpListener::bind(loopback_address(0)).expect("test agent should bind");
        let server = RpcServer::with_agent_identity(
            token.clone(),
            vec![CAPABILITY_AGENT_LIFECYCLE.to_string()],
            identity.clone(),
            RpcConfig {
                io_timeout: Duration::from_millis(100),
                ..RpcConfig::default()
            },
        );
        let address = listener
            .local_addr()
            .expect("test agent should have an address");
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("listener should become nonblocking");
            while !thread_shutdown.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("accepted stream should become blocking");
                        let identity = identity.clone();
                        let shutdown = Arc::clone(&thread_shutdown);
                        let server = &server;
                        thread::scope(|scope| {
                            scope.spawn(move || {
                                let _ = server.serve_connection(stream, |call| {
                                    handle_test_agent_call(call, &identity, &shutdown)
                                });
                            });
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        (AgentEndpoint { address, token }, shutdown)
    }

    fn handle_test_agent_call(
        call: &RpcCall,
        identity: &AgentIdentity,
        shutdown: &AtomicBool,
    ) -> Result<Value, Box<RpcError>> {
        match call.operation.as_str() {
            OP_AGENT_HEALTH => {
                let _: AgentHealthRequest =
                    serde_json::from_value(call.payload.clone()).expect("health should decode");
                Ok(serde_json::to_value(AgentHealth {
                    identity: identity.clone(),
                    state: if shutdown.load(Ordering::Acquire) {
                        AgentState::ShuttingDown
                    } else {
                        AgentState::Ready
                    },
                    sessions: SessionDiagnostics::default(),
                })
                .expect("health should encode"))
            }
            OP_AGENT_SHUTDOWN => {
                let request: AgentShutdownRequest =
                    serde_json::from_value(call.payload.clone()).expect("shutdown should decode");
                shutdown.store(true, Ordering::Release);
                Ok(serde_json::to_value(AgentShutdownResponse {
                    identity: identity.clone(),
                    state: AgentState::ShuttingDown,
                    reason: request.reason,
                })
                .expect("shutdown should encode"))
            }
            _ => unreachable!("test lifecycle agent received unexpected operation"),
        }
    }

    #[test]
    fn ensure_reports_success_only_after_handshake_and_health() {
        let runtime = TestRuntime::new("1.2.3");
        runtime.install_stale();
        let mut manager = manager(runtime.clone(), "1.2.3");

        let ready = manager
            .ensure_agent(bottle())
            .expect("stale endpoint should be replaced by a ready agent");

        assert_eq!(ready.disposition, AgentDisposition::Replaced);
        assert_eq!(runtime.launch_count(), 1);
        assert_eq!(runtime.retire_count(), 1);
        assert_eq!(
            manager
                .health(&bottle())
                .expect("ready agent should be healthy")
                .state,
            AgentState::Ready
        );
    }

    #[test]
    fn unready_launch_never_returns_success() {
        let runtime = TestRuntime::new("1.2.3");
        runtime.set_launch_unready();
        let mut manager = manager(runtime.clone(), "1.2.3");

        let error = manager
            .ensure_agent(bottle())
            .expect_err("listener metadata alone must not report readiness");

        assert_eq!(error.code, LifecycleErrorCode::HandshakeFailed);
        assert!(error.message.contains("handshake"));
        assert_eq!(runtime.launch_count(), 1);
        assert_eq!(runtime.retire_count(), 1);
    }

    #[test]
    fn duplicate_ensure_reuses_one_agent_per_bottle() {
        let runtime = TestRuntime::new("1.2.3");
        let mut manager = manager(runtime.clone(), "1.2.3");

        let first = manager
            .ensure_agent(bottle())
            .expect("first ensure should start an agent");
        let second = manager
            .ensure_agent(bottle())
            .expect("second ensure should reuse the agent");

        assert_eq!(first.disposition, AgentDisposition::Started);
        assert_eq!(second.disposition, AgentDisposition::Reused);
        assert_eq!(first.identity, second.identity);
        assert_eq!(runtime.launch_count(), 1);
    }

    #[test]
    fn host_restart_reconnects_to_the_existing_agent() {
        let runtime = TestRuntime::new("1.2.3");
        let first_identity = {
            let mut first_host = manager(runtime.clone(), "1.2.3");
            first_host
                .ensure_agent(bottle())
                .expect("first host should start the agent")
                .identity
        };

        let mut restarted_host = manager(runtime.clone(), "1.2.3");
        let reconnected = restarted_host
            .ensure_agent(bottle())
            .expect("restarted host should reconnect");

        assert_eq!(reconnected.disposition, AgentDisposition::Reconnected);
        assert_eq!(reconnected.identity, first_identity);
        assert_eq!(runtime.launch_count(), 1);
    }

    #[test]
    fn incompatible_existing_agent_is_gracefully_replaced() {
        let runtime = TestRuntime::new("2.0.0");
        runtime.install_existing("1.0.0");
        let mut manager = manager(runtime.clone(), "2.0.0");

        let ready = manager
            .ensure_agent(bottle())
            .expect("old agent should be replaced");

        assert_eq!(ready.disposition, AgentDisposition::Replaced);
        assert_eq!(ready.identity.version, "2.0.0");
        assert_eq!(runtime.retire_count(), 1);
        assert_eq!(runtime.launch_count(), 1);
    }

    #[test]
    fn newly_launched_wrong_version_is_retired_with_actionable_error() {
        let runtime = TestRuntime::new("1.0.0");
        let mut manager = manager(runtime.clone(), "2.0.0");

        let error = manager
            .ensure_agent(bottle())
            .expect_err("wrong launched artifact must not become managed");

        assert_eq!(error.code, LifecycleErrorCode::VersionMismatch);
        assert_eq!(
            error.details.get("expected_version"),
            Some(&"2.0.0".to_string())
        );
        assert_eq!(
            error.details.get("actual_version"),
            Some(&"1.0.0".to_string())
        );
        assert_eq!(runtime.retire_count(), 1);
    }

    #[test]
    fn unexpected_agent_exit_returns_actionable_structured_diagnostics() {
        let runtime = TestRuntime::new("1.2.3");
        let mut manager = manager(runtime.clone(), "1.2.3");
        manager
            .ensure_agent(bottle())
            .expect("agent should become ready");
        runtime.set_process_exit(AgentExit {
            code: Some(23),
            stderr: "wine: agent fault".to_string(),
        });

        let error = manager
            .health(&bottle())
            .expect_err("terminated agent must fail health");

        assert_eq!(error.code, LifecycleErrorCode::AgentExited);
        assert!(error.message.contains("restart"));
        assert_eq!(error.details.get("exit_code"), Some(&"23".to_string()));
        assert_eq!(
            error.details.get("stderr"),
            Some(&"wine: agent fault".to_string())
        );
        assert!(error.instance_id.is_some());
    }

    #[test]
    fn shutdown_is_graceful_and_removes_managed_state() {
        let runtime = TestRuntime::new("1.2.3");
        let mut manager = manager(runtime.clone(), "1.2.3");
        manager
            .ensure_agent(bottle())
            .expect("agent should become ready");

        manager
            .shutdown(&bottle(), "host is exiting")
            .expect("shutdown should be acknowledged");

        assert_eq!(runtime.retire_count(), 1);
        assert_eq!(
            manager
                .health(&bottle())
                .expect_err("shutdown agent should no longer be managed")
                .code,
            LifecycleErrorCode::HealthCheckFailed
        );
    }

    #[test]
    fn invalid_bottle_ids_are_rejected_without_interpreting_paths() {
        let error = BottleId::new("  ").expect_err("blank bottle ID must fail");
        assert_eq!(error.code, LifecycleErrorCode::InvalidBottleId);
    }
}
