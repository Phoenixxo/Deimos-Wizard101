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
use deimos_core::memory::CAPABILITY_MEMORY_READ_ONLY;
use deimos_core::process::CAPABILITY_PROCESS_READ_ONLY;
use deimos_core::rpc::{AuthToken, NativeContext, RpcClient, RpcClientError, RpcConfig};
use serde::Serialize;
use serde_json::Value;

const MAX_STDERR_DIAGNOSTIC_BYTES: usize = 4096;
const MAX_STDERR_INPUT_BYTES: usize = MAX_STDERR_DIAGNOSTIC_BYTES * 2;
const REDACTION_MARKER: &str = "[REDACTED]";
const TRUNCATION_MARKER: &str = "[TRUNCATED]";
const REQUIRED_AGENT_CAPABILITIES: [&str; 3] = [
    CAPABILITY_AGENT_LIFECYCLE,
    CAPABILITY_PROCESS_READ_ONLY,
    CAPABILITY_MEMORY_READ_ONLY,
];

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

#[derive(Clone)]
pub struct AgentEndpoint {
    pub address: SocketAddr,
    pub token: AuthToken,
}

impl fmt::Debug for AgentEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentEndpoint")
            .field("address", &self.address)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

pub trait AgentProcess: Send {
    /// Nonblocking process-status poll. DMS-009 implementations must bound any
    /// platform I/O and return already-captured diagnostics.
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentLaunchError {
    AlreadyRunning,
    Failed(String),
}

impl fmt::Display for AgentLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => formatter.write_str("another host started the bottle agent"),
            Self::Failed(message) => formatter.write_str(message),
        }
    }
}

pub trait AgentRuntime {
    /// Return reconnect metadata previously recorded for this opaque bottle.
    /// DMS-009 owns how that metadata is discovered and persisted.
    fn discover(&mut self, bottle: &BottleId) -> Result<Option<AgentEndpoint>, String>;

    /// Start the already-selected agent artifact in the already-selected
    /// runtime. This lifecycle layer does not choose paths or Wine binaries.
    fn launch(&mut self, bottle: &BottleId) -> Result<AgentLaunch, AgentLaunchError>;

    /// Attach a bounded, nonblocking monitor to an agent discovered after host
    /// restart. DMS-009 owns the Wine/PID-specific implementation.
    fn reconnect_monitor(
        &mut self,
        bottle: &BottleId,
        endpoint: &AgentEndpoint,
        identity: &AgentIdentity,
    ) -> Result<Box<dyn AgentProcess>, String>;

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
    MonitoringFailed,
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

#[derive(Debug)]
pub enum AgentCallError {
    Lifecycle(LifecycleError),
    Rpc {
        operation: String,
        native_context: NativeContext,
        source: Box<RpcClientError>,
    },
}

impl fmt::Display for AgentCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lifecycle(error) => error.fmt(formatter),
            Self::Rpc { source, .. } => source.fmt(formatter),
        }
    }
}

impl std::error::Error for AgentCallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lifecycle(error) => Some(error),
            Self::Rpc { source, .. } => Some(source),
        }
    }
}

impl From<LifecycleError> for AgentCallError {
    fn from(error: LifecycleError) -> Self {
        Self::Lifecycle(error)
    }
}

struct ManagedAgent {
    endpoint: AgentEndpoint,
    identity: AgentIdentity,
    client: RpcClient,
    process: Box<dyn AgentProcess>,
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
    expected_build_id: String,
    native_context: NativeContext,
    config: RpcConfig,
    readiness_timeout: Duration,
    retry_interval: Duration,
    managed: HashMap<BottleId, ManagedAgent>,
}

impl<R: AgentRuntime> AgentManager<R> {
    pub fn new(runtime: R, native_context: NativeContext) -> Self {
        Self::for_expected_artifact(
            runtime,
            env!("CARGO_PKG_VERSION"),
            deimos_core::BUILD_ID,
            native_context,
        )
    }

    pub fn for_expected_artifact(
        runtime: R,
        expected_version: impl Into<String>,
        expected_build_id: impl Into<String>,
        native_context: NativeContext,
    ) -> Self {
        Self {
            runtime,
            expected_version: expected_version.into(),
            expected_build_id: expected_build_id.into(),
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
                    return self.manage_reconnected(
                        bottle,
                        endpoint,
                        client,
                        identity,
                        AgentDisposition::Reconnected,
                    );
                }
                Ok(Candidate::VersionMismatch {
                    mut client,
                    identity,
                }) => {
                    replacement = true;
                    let reason = format!(
                        "replace agent artifact {} ({}) with {} ({})",
                        identity.version,
                        identity.build_id,
                        self.expected_version,
                        self.expected_build_id
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

        match self.runtime.launch(&bottle) {
            Ok(launch) => self.finish_launch(bottle, launch, replacement),
            Err(AgentLaunchError::AlreadyRunning) => self.converge_after_launch_race(bottle),
            Err(AgentLaunchError::Failed(error)) => Err(LifecycleError::new(
                LifecycleErrorCode::LaunchFailed,
                bottle.as_str(),
                format!("failed to launch the agent: {error}"),
            )),
        }
    }

    pub fn health(&mut self, bottle: &BottleId) -> Result<AgentHealth, LifecycleError> {
        let managed = self.managed.get_mut(bottle).ok_or_else(|| {
            LifecycleError::new(
                LifecycleErrorCode::HealthCheckFailed,
                bottle.as_str(),
                "no managed agent exists for this bottle; call ensure_agent first",
            )
        })?;

        if let Some(error) = poll_process_exit(bottle, managed)? {
            return Err(error);
        }

        let health = call_health(
            bottle,
            &mut managed.client,
            &managed.identity,
            self.native_context.clone(),
        );
        if health.is_err() {
            if let Some(error) = poll_process_exit(bottle, managed)? {
                return Err(error);
            }
        }
        health
    }

    pub fn call(
        &mut self,
        bottle: &BottleId,
        operation: &str,
        payload: Value,
    ) -> Result<Value, AgentCallError> {
        let managed = self.managed.get_mut(bottle).ok_or_else(|| {
            LifecycleError::new(
                LifecycleErrorCode::HealthCheckFailed,
                bottle.as_str(),
                "no managed agent exists for this bottle; call ensure_agent first",
            )
        })?;

        if let Some(error) = poll_process_exit(bottle, managed)? {
            return Err(error.into());
        }

        let native_context = self.native_context.clone();
        let result = managed
            .client
            .call(operation, payload, Some(native_context.clone()));
        if result.is_err() {
            if let Some(error) = poll_process_exit(bottle, managed)? {
                return Err(error.into());
            }
        }
        result.map_err(|source| AgentCallError::Rpc {
            operation: operation.to_string(),
            native_context,
            source: Box::new(source),
        })
    }

    pub fn capabilities(&mut self, bottle: &BottleId) -> Result<Vec<String>, LifecycleError> {
        let managed = self.managed.get_mut(bottle).ok_or_else(|| {
            LifecycleError::new(
                LifecycleErrorCode::HealthCheckFailed,
                bottle.as_str(),
                "no managed agent exists for this bottle; call ensure_agent first",
            )
        })?;

        if let Some(error) = poll_process_exit(bottle, managed)? {
            return Err(error);
        }

        Ok(managed.client.capabilities.clone())
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
            REQUIRED_AGENT_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect(),
            Some(self.native_context.clone()),
            self.config,
        )
        .map_err(|error| handshake_error(bottle, error))?;
        let missing_capabilities = REQUIRED_AGENT_CAPABILITIES
            .iter()
            .filter(|required| {
                !client
                    .capabilities
                    .iter()
                    .any(|negotiated| negotiated == **required)
            })
            .copied()
            .collect::<Vec<_>>();
        if !missing_capabilities.is_empty() {
            return Err(LifecycleError::new(
                LifecycleErrorCode::MissingCapability,
                bottle.as_str(),
                "agent handshake did not negotiate all required capabilities; replace the agent",
            )
            .with_detail("missing_capabilities", missing_capabilities.join(", ")));
        }
        let identity = client.agent.clone().ok_or_else(|| {
            LifecycleError::new(
                LifecycleErrorCode::HandshakeFailed,
                bottle.as_str(),
                "agent handshake omitted identity diagnostics; replace the agent",
            )
        })?;
        if identity.version != self.expected_version || identity.build_id != self.expected_build_id
        {
            return Ok(Candidate::VersionMismatch { client, identity });
        }
        call_health(bottle, &mut client, &identity, self.native_context.clone())?;
        Ok(Candidate::Ready { client, identity })
    }

    fn manage_reconnected(
        &mut self,
        bottle: BottleId,
        endpoint: AgentEndpoint,
        client: RpcClient,
        identity: AgentIdentity,
        disposition: AgentDisposition,
    ) -> Result<ReadyAgent, LifecycleError> {
        let process = self
            .runtime
            .reconnect_monitor(&bottle, &endpoint, &identity)
            .map_err(|error| {
                LifecycleError::new(
                    LifecycleErrorCode::MonitoringFailed,
                    bottle.as_str(),
                    format!(
                        "failed to monitor reconnected agent {}; restart or replace it: {error}",
                        identity.instance_id
                    ),
                )
                .with_instance(&identity)
            })?;
        let ready = ReadyAgent {
            bottle_id: bottle.0.clone(),
            identity: identity.clone(),
            disposition,
        };
        self.managed.insert(
            bottle,
            ManagedAgent {
                endpoint,
                identity,
                client,
                process,
            },
        );
        Ok(ready)
    }

    fn converge_after_launch_race(
        &mut self,
        bottle: BottleId,
    ) -> Result<ReadyAgent, LifecycleError> {
        let deadline = Instant::now() + self.readiness_timeout;
        let mut last_error = "winner rendezvous metadata is not available yet".to_string();
        loop {
            match self.runtime.discover(&bottle) {
                Ok(Some(endpoint)) => match self.connect_candidate(&bottle, &endpoint) {
                    Ok(Candidate::Ready { client, identity }) => {
                        return self.manage_reconnected(
                            bottle,
                            endpoint,
                            client,
                            identity,
                            AgentDisposition::Reconnected,
                        );
                    }
                    Ok(Candidate::VersionMismatch { identity, .. }) => {
                        return Err(artifact_mismatch_error(
                            &bottle,
                            &identity,
                            &self.expected_version,
                            &self.expected_build_id,
                            "concurrent launch produced an incompatible agent artifact",
                        ));
                    }
                    Err(error) => last_error = error.message,
                },
                Ok(None) => {}
                Err(error) => last_error = error,
            }
            if Instant::now() >= deadline {
                return Err(LifecycleError::new(
                    LifecycleErrorCode::LaunchFailed,
                    bottle.as_str(),
                    "another host won the agent launch race, but its agent did not become ready",
                )
                .with_detail("last_error", last_error));
            }
            thread::sleep(
                self.retry_interval
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
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
                let mut error = process_exit_error(
                    &bottle,
                    &launch.endpoint,
                    None,
                    exit,
                    "agent exited before completing its readiness handshake",
                );
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
                            process: launch.process,
                        },
                    );
                    return Ok(ready);
                }
                Ok(Candidate::VersionMismatch {
                    mut client,
                    identity,
                }) => {
                    let reason = format!(
                        "launched agent artifact {} ({}) does not match required artifact {} ({})",
                        identity.version,
                        identity.build_id,
                        self.expected_version,
                        self.expected_build_id
                    );
                    let _ = self.request_shutdown(&bottle, &mut client, &identity, &reason);
                    drop(client);
                    let mut error = artifact_mismatch_error(
                        &bottle,
                        &identity,
                        &self.expected_version,
                        &self.expected_build_id,
                        reason,
                    );
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

fn poll_process_exit(
    bottle: &BottleId,
    managed: &mut ManagedAgent,
) -> Result<Option<LifecycleError>, LifecycleError> {
    let exit = managed.process.try_wait().map_err(|error| {
        LifecycleError::new(
            LifecycleErrorCode::AgentExited,
            bottle.as_str(),
            format!("failed to inspect the agent process: {error}"),
        )
        .with_instance(&managed.identity)
    })?;
    Ok(exit.map(|exit| {
        process_exit_error(
            bottle,
            &managed.endpoint,
            Some(&managed.identity),
            exit,
            "agent exited unexpectedly; restart or replace it for this bottle",
        )
    }))
}

fn process_exit_error(
    bottle: &BottleId,
    endpoint: &AgentEndpoint,
    identity: Option<&AgentIdentity>,
    exit: AgentExit,
    message: &str,
) -> LifecycleError {
    let code = exit
        .code
        .map_or_else(|| "signal_or_unknown".to_string(), |code| code.to_string());
    let mut error = LifecycleError::new(
        LifecycleErrorCode::AgentExited,
        bottle.as_str(),
        format!("{message} (exit code {code})"),
    )
    .with_detail("exit_code", code)
    .with_detail(
        "stderr",
        bounded_stderr_diagnostic(&exit.stderr, endpoint.token.as_str()),
    );
    if let Some(identity) = identity {
        error = error.with_instance(identity);
    }
    error
}

fn artifact_mismatch_error(
    bottle: &BottleId,
    identity: &AgentIdentity,
    expected_version: &str,
    expected_build_id: &str,
    message: impl Into<String>,
) -> LifecycleError {
    LifecycleError::new(
        LifecycleErrorCode::VersionMismatch,
        bottle.as_str(),
        message,
    )
    .with_instance(identity)
    .with_detail("expected_version", expected_version)
    .with_detail("actual_version", identity.version.clone())
    .with_detail("expected_build_id", expected_build_id)
    .with_detail("actual_build_id", identity.build_id.clone())
}

fn bounded_stderr_diagnostic(stderr: &str, token: &str) -> String {
    let mut input_end = stderr.len().min(MAX_STDERR_INPUT_BYTES);
    while !stderr.is_char_boundary(input_end) {
        input_end -= 1;
    }
    let input = &stderr[..input_end];
    let input_was_truncated = input_end < stderr.len();
    let mut output = String::new();
    let mut index = 0;
    let mut output_was_truncated = false;
    while index < input.len() {
        let remaining = &input[index..];
        if !token.is_empty() && remaining.starts_with(token) {
            if !push_bounded(&mut output, REDACTION_MARKER, MAX_STDERR_DIAGNOSTIC_BYTES) {
                output_was_truncated = true;
                break;
            }
            index += token.len();
            continue;
        }
        if input_was_truncated
            && !token.is_empty()
            && remaining.len() < token.len()
            && token.starts_with(remaining)
        {
            if !push_bounded(&mut output, REDACTION_MARKER, MAX_STDERR_DIAGNOSTIC_BYTES) {
                output_was_truncated = true;
            }
            index = input.len();
            continue;
        }

        if input.as_bytes()[index].is_ascii_hexdigit() {
            let start = index;
            while index < input.len() && input.as_bytes()[index].is_ascii_hexdigit() {
                index += 1;
            }
            if index - start >= 64 {
                if !push_bounded(&mut output, REDACTION_MARKER, MAX_STDERR_DIAGNOSTIC_BYTES) {
                    output_was_truncated = true;
                    break;
                }
                continue;
            }
            index = start;
        }

        let character = input[index..]
            .chars()
            .next()
            .expect("index should remain inside input");
        let character = match character {
            '\n' | '\t' => character,
            character if character.is_control() => '\u{fffd}',
            character => character,
        };
        if output.len() + character.len_utf8() > MAX_STDERR_DIAGNOSTIC_BYTES {
            output_was_truncated = true;
            break;
        }
        output.push(character);
        index += input[index..]
            .chars()
            .next()
            .expect("index should remain inside input")
            .len_utf8();
    }

    if input_was_truncated || output_was_truncated {
        let maximum_prefix = MAX_STDERR_DIAGNOSTIC_BYTES - TRUNCATION_MARKER.len();
        if output.len() > maximum_prefix {
            let mut boundary = maximum_prefix;
            while !output.is_char_boundary(boundary) {
                boundary -= 1;
            }
            output.truncate(boundary);
        }
        output.push_str(TRUNCATION_MARKER);
    }
    output
}

fn push_bounded(output: &mut String, value: &str, maximum: usize) -> bool {
    for character in value.chars() {
        if output.len() + character.len_utf8() > maximum {
            return false;
        }
        output.push(character);
    }
    true
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
    use std::sync::{Arc, Barrier, Mutex};

    use deimos_core::lifecycle::{
        AgentHealth, AgentHealthRequest, AgentShutdownRequest, AgentShutdownResponse,
        SessionDiagnostics,
    };
    use deimos_core::rpc::{loopback_address, RpcCall, RpcError, RpcErrorCode, RpcServer};
    use serde_json::{json, Value};

    use super::*;

    #[derive(Clone)]
    struct TestRuntime {
        state: Arc<Mutex<TestRuntimeState>>,
        discover_barrier: Option<Arc<Barrier>>,
        discover_barrier_used: bool,
    }

    struct TestRuntimeState {
        current: Option<AgentEndpoint>,
        agents: HashMap<SocketAddr, Arc<AtomicBool>>,
        launch_count: usize,
        retire_count: usize,
        launch_version: String,
        launch_build_id: String,
        launch_unready: bool,
        launch_in_progress: bool,
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
                    launch_build_id: "test-build-current".to_string(),
                    launch_unready: false,
                    launch_in_progress: false,
                    process_exit: Arc::new(Mutex::new(None)),
                })),
                discover_barrier: None,
                discover_barrier_used: false,
            }
        }

        fn with_discover_barrier(mut self, barrier: Arc<Barrier>) -> Self {
            self.discover_barrier = Some(barrier);
            self
        }

        fn install_existing(&self, version: &str, build_id: &str) -> AgentEndpoint {
            let (endpoint, shutdown) = start_test_agent(version, build_id);
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

        fn current_token(&self) -> String {
            self.state
                .lock()
                .expect("runtime state should lock")
                .current
                .as_ref()
                .expect("runtime should have an endpoint")
                .token
                .as_str()
                .to_string()
        }
    }

    impl AgentRuntime for TestRuntime {
        fn discover(&mut self, _bottle: &BottleId) -> Result<Option<AgentEndpoint>, String> {
            let discovered = self
                .state
                .lock()
                .map_err(|error| error.to_string())?
                .current
                .clone();
            if !self.discover_barrier_used {
                if let Some(barrier) = &self.discover_barrier {
                    self.discover_barrier_used = true;
                    barrier.wait();
                }
            }
            Ok(discovered)
        }

        fn launch(&mut self, _bottle: &BottleId) -> Result<AgentLaunch, AgentLaunchError> {
            let (version, build_id, launch_unready, process_exit) = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
                if state.current.is_some() || state.launch_in_progress {
                    return Err(AgentLaunchError::AlreadyRunning);
                }
                state.launch_in_progress = true;
                (
                    state.launch_version.clone(),
                    state.launch_build_id.clone(),
                    state.launch_unready,
                    Arc::clone(&state.process_exit),
                )
            };
            let (endpoint, shutdown) = if launch_unready {
                let listener = TcpListener::bind(loopback_address(0))
                    .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
                let address = listener
                    .local_addr()
                    .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
                drop(listener);
                (
                    AgentEndpoint {
                        address,
                        token: AuthToken::generate()
                            .map_err(|error| AgentLaunchError::Failed(error.to_string()))?,
                    },
                    Arc::new(AtomicBool::new(false)),
                )
            } else {
                start_test_agent(&version, &build_id)
            };
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
                state.launch_in_progress = false;
                state.launch_count += 1;
                state.current = Some(endpoint.clone());
                state.agents.insert(endpoint.address, shutdown);
            }
            Ok(AgentLaunch {
                endpoint,
                process: Box::new(TestProcess { exit: process_exit }),
            })
        }

        fn reconnect_monitor(
            &mut self,
            _bottle: &BottleId,
            _endpoint: &AgentEndpoint,
            _identity: &AgentIdentity,
        ) -> Result<Box<dyn AgentProcess>, String> {
            let process_exit = Arc::clone(
                &self
                    .state
                    .lock()
                    .map_err(|error| error.to_string())?
                    .process_exit,
            );
            Ok(Box::new(TestProcess { exit: process_exit }))
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
        manager_with_build(runtime, version, "test-build-current")
    }

    fn manager_with_build(
        runtime: TestRuntime,
        version: &str,
        build_id: &str,
    ) -> AgentManager<TestRuntime> {
        AgentManager::for_expected_artifact(runtime, version, build_id, context())
            .with_timing(Duration::from_millis(100), Duration::from_millis(2))
    }

    fn start_test_agent(version: &str, build_id: &str) -> (AgentEndpoint, Arc<AtomicBool>) {
        start_test_agent_with_capabilities(
            version,
            build_id,
            REQUIRED_AGENT_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect(),
        )
    }

    fn start_test_agent_with_capabilities(
        version: &str,
        build_id: &str,
        capabilities: Vec<String>,
    ) -> (AgentEndpoint, Arc<AtomicBool>) {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

        let identity = AgentIdentity {
            instance_id: format!("test-agent-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            version: version.to_string(),
            build_id: build_id.to_string(),
            process_id: std::process::id(),
        };
        let token = AuthToken::generate().expect("token should generate");
        let listener = TcpListener::bind(loopback_address(0)).expect("test agent should bind");
        let server = RpcServer::with_agent_identity(
            token.clone(),
            capabilities,
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
            "test.context" => Ok(json!({
                "payload": call.payload.clone(),
                "native_context": call.native_context.clone(),
            })),
            "test.disconnect" => panic!("test agent disconnected during RPC"),
            "test.protocol_error" => {
                let mut error = RpcError::new(
                    RpcErrorCode::MemoryReadFailed,
                    "test memory read failed",
                    call.request_id,
                    call.operation.clone(),
                    call.native_context.clone(),
                );
                error
                    .details
                    .insert("address".to_string(), "0x1234".to_string());
                Err(Box::new(error))
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

        runtime.set_process_exit(AgentExit {
            code: Some(41),
            stderr: "reconnected agent terminated".to_string(),
        });
        let error = restarted_host
            .health(&bottle())
            .expect_err("reconnected process exit should remain actionable");
        assert_eq!(error.code, LifecycleErrorCode::AgentExited);
        assert_eq!(error.details.get("exit_code"), Some(&"41".to_string()));
    }

    #[test]
    fn incompatible_existing_agent_is_gracefully_replaced() {
        let runtime = TestRuntime::new("2.0.0");
        runtime.install_existing("1.0.0", "test-build-old");
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
    fn same_version_different_build_is_gracefully_replaced() {
        let runtime = TestRuntime::new("2.0.0");
        runtime.install_existing("2.0.0", "test-build-old");
        let mut manager = manager_with_build(runtime.clone(), "2.0.0", "test-build-current");

        let ready = manager
            .ensure_agent(bottle())
            .expect("old build should be replaced");

        assert_eq!(ready.disposition, AgentDisposition::Replaced);
        assert_eq!(ready.identity.version, "2.0.0");
        assert_eq!(ready.identity.build_id, "test-build-current");
        assert_eq!(runtime.retire_count(), 1);
        assert_eq!(runtime.launch_count(), 1);
    }

    #[test]
    fn concurrent_managers_converge_on_the_winning_agent() {
        let barrier = Arc::new(Barrier::new(2));
        let runtime = TestRuntime::new("1.2.3").with_discover_barrier(barrier);
        let first_runtime = runtime.clone();
        let second_runtime = runtime.clone();

        let first = thread::spawn(move || {
            let mut manager = manager(first_runtime, "1.2.3")
                .with_timing(Duration::from_millis(500), Duration::from_millis(2));
            manager.ensure_agent(bottle())
        });
        let second = thread::spawn(move || {
            let mut manager = manager(second_runtime, "1.2.3")
                .with_timing(Duration::from_millis(500), Duration::from_millis(2));
            manager.ensure_agent(bottle())
        });

        let first = first
            .join()
            .expect("first manager should not panic")
            .expect("first manager should converge");
        let second = second
            .join()
            .expect("second manager should not panic")
            .expect("second manager should converge");

        assert_eq!(first.identity, second.identity);
        assert_eq!(runtime.launch_count(), 1);
        assert!([first.disposition, second.disposition].contains(&AgentDisposition::Started));
        assert!([first.disposition, second.disposition].contains(&AgentDisposition::Reconnected));
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
    fn handshake_requires_lifecycle_process_and_memory_capabilities() {
        let runtime = TestRuntime::new("1.2.3");
        let (endpoint, shutdown) = start_test_agent_with_capabilities(
            "1.2.3",
            "test-build-current",
            vec![
                CAPABILITY_AGENT_LIFECYCLE.to_string(),
                CAPABILITY_PROCESS_READ_ONLY.to_string(),
            ],
        );
        let manager = manager(runtime, "1.2.3");

        let error = match manager.connect_candidate(&bottle(), &endpoint) {
            Ok(_) => panic!("an agent missing memory capability must not be accepted"),
            Err(error) => error,
        };

        assert_eq!(error.code, LifecycleErrorCode::MissingCapability);
        assert_eq!(
            error.details.get("missing_capabilities"),
            Some(&CAPABILITY_MEMORY_READ_ONLY.to_string())
        );
        shutdown.store(true, Ordering::Release);
    }

    #[test]
    fn managed_calls_require_ensure_and_carry_native_context() {
        let runtime = TestRuntime::new("1.2.3");
        let mut manager = manager(runtime, "1.2.3");

        let error = manager
            .call(&bottle(), "test.context", json!({"value": 7}))
            .expect_err("calls before ensure_agent must fail");
        assert!(matches!(
            error,
            AgentCallError::Lifecycle(LifecycleError {
                code: LifecycleErrorCode::HealthCheckFailed,
                ..
            })
        ));

        manager
            .ensure_agent(bottle())
            .expect("agent should become ready");
        let response = manager
            .call(&bottle(), "test.context", json!({"value": 7}))
            .expect("managed call should succeed");

        assert_eq!(response["payload"], json!({"value": 7}));
        assert_eq!(
            response["native_context"],
            serde_json::to_value(context()).expect("context should serialize")
        );
        assert_eq!(
            manager
                .capabilities(&bottle())
                .expect("capabilities should be available"),
            REQUIRED_AGENT_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn managed_calls_preserve_structured_protocol_errors() {
        let runtime = TestRuntime::new("1.2.3");
        let mut manager = manager(runtime, "1.2.3");
        manager
            .ensure_agent(bottle())
            .expect("agent should become ready");

        let error = manager
            .call(&bottle(), "test.protocol_error", Value::Null)
            .expect_err("test operation should return a protocol error");

        let AgentCallError::Rpc {
            operation,
            native_context,
            source,
        } = error
        else {
            panic!("structured protocol error should remain available");
        };
        let RpcClientError::Protocol(error) = *source else {
            panic!("structured protocol error should remain available");
        };
        assert_eq!(operation, "test.protocol_error");
        assert_eq!(native_context, context());
        assert_eq!(error.code, RpcErrorCode::MemoryReadFailed);
        assert_eq!(error.operation, "test.protocol_error");
        assert_eq!(error.native_context, Some(context()));
        assert_eq!(error.details.get("address"), Some(&"0x1234".to_string()));
    }

    #[test]
    fn managed_calls_poll_process_exit_before_rpc() {
        let runtime = TestRuntime::new("1.2.3");
        let mut manager = manager(runtime.clone(), "1.2.3");
        manager
            .ensure_agent(bottle())
            .expect("agent should become ready");
        runtime.set_process_exit(AgentExit {
            code: Some(17),
            stderr: "agent exited before call".to_string(),
        });

        let error = manager
            .call(&bottle(), "test.context", Value::Null)
            .expect_err("exited agent must be reported before RPC");

        let AgentCallError::Lifecycle(error) = error else {
            panic!("process exit should remain a lifecycle error");
        };
        assert_eq!(error.code, LifecycleErrorCode::AgentExited);
        assert_eq!(error.details.get("exit_code"), Some(&"17".to_string()));
    }

    #[test]
    fn managed_calls_poll_process_exit_again_after_rpc_failure() {
        struct ExitAfterFirstPoll {
            polled: bool,
        }

        impl AgentProcess for ExitAfterFirstPoll {
            fn try_wait(&mut self) -> io::Result<Option<AgentExit>> {
                if self.polled {
                    Ok(Some(AgentExit {
                        code: Some(19),
                        stderr: "agent exited during call".to_string(),
                    }))
                } else {
                    self.polled = true;
                    Ok(None)
                }
            }
        }

        let runtime = TestRuntime::new("1.2.3");
        let mut manager = manager(runtime, "1.2.3");
        manager
            .ensure_agent(bottle())
            .expect("agent should become ready");
        manager
            .managed
            .get_mut(&bottle())
            .expect("managed agent should exist")
            .process = Box::new(ExitAfterFirstPoll { polled: false });

        let error = manager
            .call(&bottle(), "test.disconnect", Value::Null)
            .expect_err("disconnecting call should fail");

        let AgentCallError::Lifecycle(error) = error else {
            panic!("post-failure process exit should remain a lifecycle error");
        };
        assert_eq!(error.code, LifecycleErrorCode::AgentExited);
        assert_eq!(error.details.get("exit_code"), Some(&"19".to_string()));
        assert_eq!(
            error.details.get("stderr"),
            Some(&"agent exited during call".to_string())
        );
    }

    #[test]
    fn endpoint_debug_and_exit_diagnostics_redact_tokens_and_bound_stderr() {
        let runtime = TestRuntime::new("1.2.3");
        let mut manager = manager(runtime.clone(), "1.2.3");
        manager
            .ensure_agent(bottle())
            .expect("agent should become ready");
        let token = runtime.current_token();
        let endpoint = runtime
            .state
            .lock()
            .expect("runtime state should lock")
            .current
            .clone()
            .expect("endpoint should exist");
        let endpoint_debug = format!("{endpoint:?}");
        assert!(!endpoint_debug.contains(&token));
        assert!(endpoint_debug.contains("REDACTED"));

        runtime.set_process_exit(AgentExit {
            code: Some(23),
            stderr: format!("token={token}\0{}", "x".repeat(16_000)),
        });
        let error = manager
            .health(&bottle())
            .expect_err("terminated agent must fail health");
        let stderr = error
            .details
            .get("stderr")
            .expect("stderr should be recorded");
        assert!(!stderr.contains(&token));
        assert!(!stderr.contains('\0'));
        assert!(stderr.contains("REDACTED"));
        assert!(stderr.len() <= MAX_STDERR_DIAGNOSTIC_BYTES);
        assert!(
            serde_json::to_string(&error)
                .expect("error should serialize")
                .len()
                < MAX_STDERR_DIAGNOSTIC_BYTES + 1024
        );
    }

    #[test]
    fn stderr_redaction_covers_token_prefix_at_input_boundary() {
        let token = "0123456789abcdef".repeat(4);
        assert_eq!(token.len(), 64);
        let stderr = format!("{}|{token}", token.repeat(127));

        let diagnostic = bounded_stderr_diagnostic(&stderr, &token);

        assert!(diagnostic.len() <= MAX_STDERR_DIAGNOSTIC_BYTES);
        assert!(diagnostic.ends_with(TRUNCATION_MARKER));
        for prefix_length in 16..=token.len() {
            assert!(
                !diagnostic.contains(&token[..prefix_length]),
                "diagnostic exposed a {prefix_length}-byte token prefix"
            );
        }
        assert_eq!(diagnostic.matches(REDACTION_MARKER).count(), 128);
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
