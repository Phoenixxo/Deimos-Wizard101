use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use deimos_core::lifecycle::AgentIdentity;
use deimos_core::rpc::{AuthToken, RpcClient, RpcConfig};
use serde::{Deserialize, Serialize};

use crate::lifecycle::{
    AgentEndpoint, AgentExit, AgentLaunch, AgentLaunchError, AgentProcess, AgentRuntime, BottleId,
};

pub const MANAGED_STATE_DIRECTORY: &str = ".deimos";
pub const RENDEZVOUS_FILE: &str = "agent-rendezvous.json";
pub const LAUNCH_LOCK_FILE: &str = "agent-launch.lock";
pub const STDERR_FILE: &str = "agent-stderr.log";
pub const DEPLOYMENT_DIRECTORY: &str = "Deimos";
pub const DEPLOYED_AGENT_FILE: &str = "deimos-agent.exe";

const RENDEZVOUS_SCHEMA_VERSION: u32 = 1;
const MAX_RENDEZVOUS_BYTES: u64 = 16 * 1024;
const MAX_STDERR_BYTES: u64 = 16 * 1024;
const MAX_STDERR_ON_DISK_BYTES: u64 = MAX_STDERR_BYTES * 2;
const MAX_STARTUP_STDOUT_BYTES: usize = 16 * 1024;
const LISTENER_MARKER: &str = "DEIMOS_AGENT_LISTEN=";
const SECURE_DIRECTORY_MODE: u32 = 0o700;
const SECURE_FILE_MODE: u32 = 0o600;
const EXECUTABLE_FILE_MODE: u32 = 0o700;

static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WineRuntimeErrorKind {
    InvalidConfiguration,
    InvalidBottle,
    UnsafeFilesystem,
    DeploymentFailed,
    RendezvousFailed,
    ProcessFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WineRuntimeError {
    pub kind: WineRuntimeErrorKind,
    pub message: String,
    pub path: Option<PathBuf>,
}

impl WineRuntimeError {
    fn new(kind: WineRuntimeErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            path: None,
        }
    }

    fn at_path(
        kind: WineRuntimeErrorKind,
        path: impl Into<PathBuf>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            path: Some(path.into()),
        }
    }
}

impl fmt::Display for WineRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(formatter, "{} (path {})", self.message, path.display())
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl std::error::Error for WineRuntimeError {}

#[derive(Clone, Debug)]
pub struct WineRuntimeConfig {
    pub wine_executable: PathBuf,
    pub wineserver_executable: Option<PathBuf>,
    pub agent_artifact: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub startup_timeout: Duration,
    pub poll_interval: Duration,
    pub graceful_retire_timeout: Duration,
    pub terminate_timeout: Duration,
}

impl WineRuntimeConfig {
    pub fn new(wine_executable: impl Into<PathBuf>, agent_artifact: impl Into<PathBuf>) -> Self {
        Self {
            wine_executable: wine_executable.into(),
            wineserver_executable: None,
            agent_artifact: agent_artifact.into(),
            environment: BTreeMap::new(),
            startup_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_millis(50),
            graceful_retire_timeout: Duration::from_secs(2),
            terminate_timeout: Duration::from_secs(1),
        }
    }

    pub fn with_wineserver(mut self, executable: impl Into<PathBuf>) -> Self {
        self.wineserver_executable = Some(executable.into());
        self
    }

    pub fn with_environment(
        mut self,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Self {
        self.environment.insert(name.into(), value.into());
        self
    }

    pub fn with_timing(
        mut self,
        startup_timeout: Duration,
        poll_interval: Duration,
        graceful_retire_timeout: Duration,
        terminate_timeout: Duration,
    ) -> Self {
        self.startup_timeout = startup_timeout;
        self.poll_interval = poll_interval;
        self.graceful_retire_timeout = graceful_retire_timeout;
        self.terminate_timeout = terminate_timeout;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct HostProcessIdentity {
    pid: u32,
    start_id: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct RendezvousRecord {
    schema_version: u32,
    bottle_id: String,
    address: String,
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_process: Option<HostProcessIdentity>,
    deployed_agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_process_id: Option<u32>,
}

#[derive(Clone, Debug)]
struct BottleLayout {
    bottle: PathBuf,
    state_directory: PathBuf,
    rendezvous: PathBuf,
    launch_lock: PathBuf,
    stderr: PathBuf,
    deployment_directory: PathBuf,
    deployed_agent: PathBuf,
}

impl BottleLayout {
    fn resolve(bottle: &BottleId) -> Result<Self, WineRuntimeError> {
        let requested = Path::new(bottle.as_str());
        let canonical = canonical_bottle_path(requested)?;
        if canonical.as_os_str() != OsStr::new(bottle.as_str()) {
            return Err(WineRuntimeError::at_path(
                WineRuntimeErrorKind::InvalidBottle,
                requested,
                "bottle ID is not the canonical bottle path; create it with WineAgentRuntime::bottle_id",
            ));
        }

        let state_directory = canonical.join(MANAGED_STATE_DIRECTORY);
        let drive_c = canonical.join("drive_c");
        let canonical_drive = fs::canonicalize(&drive_c).map_err(|error| {
            WineRuntimeError::at_path(
                WineRuntimeErrorKind::InvalidBottle,
                &drive_c,
                format!("Wine bottle is missing drive_c: {error}"),
            )
        })?;
        if !canonical_drive.starts_with(&canonical) {
            return Err(WineRuntimeError::at_path(
                WineRuntimeErrorKind::UnsafeFilesystem,
                &drive_c,
                "Wine bottle drive_c resolves outside the bottle",
            ));
        }
        let deployment_directory = canonical_drive.join(DEPLOYMENT_DIRECTORY);

        Ok(Self {
            bottle: canonical,
            rendezvous: state_directory.join(RENDEZVOUS_FILE),
            launch_lock: state_directory.join(LAUNCH_LOCK_FILE),
            stderr: state_directory.join(STDERR_FILE),
            state_directory,
            deployed_agent: deployment_directory.join(DEPLOYED_AGENT_FILE),
            deployment_directory,
        })
    }
}

#[derive(Debug)]
pub struct WineAgentRuntime {
    config: WineRuntimeConfig,
    owned_processes: HashMap<BottleId, SharedChild>,
}

impl WineAgentRuntime {
    pub fn new(mut config: WineRuntimeConfig) -> Result<Self, WineRuntimeError> {
        config.wine_executable = validate_executable(&config.wine_executable, "Wine executable")?;
        if let Some(wineserver) = config.wineserver_executable.take() {
            config.wineserver_executable =
                Some(validate_executable(&wineserver, "wineserver executable")?);
        }
        config.agent_artifact = validate_agent_artifact(&config.agent_artifact)?;
        config
            .environment
            .entry(OsString::from("WINEDEBUG"))
            .or_insert_with(|| OsString::from("-all"));
        validate_timing(&config)?;
        Ok(Self {
            config,
            owned_processes: HashMap::new(),
        })
    }

    pub fn config(&self) -> &WineRuntimeConfig {
        &self.config
    }

    pub fn bottle_id(path: impl AsRef<Path>) -> Result<BottleId, WineRuntimeError> {
        let canonical = canonical_bottle_path(path.as_ref())?;
        let value = canonical.to_str().ok_or_else(|| {
            WineRuntimeError::at_path(
                WineRuntimeErrorKind::InvalidBottle,
                &canonical,
                "bottle path is not valid UTF-8",
            )
        })?;
        BottleId::new(value).map_err(|error| {
            WineRuntimeError::at_path(
                WineRuntimeErrorKind::InvalidBottle,
                canonical,
                error.to_string(),
            )
        })
    }

    fn read_record(
        &self,
        layout: &BottleLayout,
    ) -> Result<Option<RendezvousRecord>, WineRuntimeError> {
        let bytes = match read_secure_file(&layout.rendezvous, MAX_RENDEZVOUS_BYTES) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(error) => return Err(error),
        };
        let record: RendezvousRecord = match serde_json::from_slice(&bytes) {
            Ok(record) => record,
            Err(error) => {
                return Err(WineRuntimeError::at_path(
                    WineRuntimeErrorKind::RendezvousFailed,
                    &layout.rendezvous,
                    format!(
                        "agent rendezvous metadata is malformed; preserving it to avoid orphaning a potentially live agent: {error}"
                    ),
                ));
            }
        };
        if let Err(validation_error) = validate_record(layout, &record) {
            let live_process = match record.host_process.as_ref() {
                Some(process) => process_identity_matches(process).map_err(|error| {
                    WineRuntimeError::at_path(
                        WineRuntimeErrorKind::RendezvousFailed,
                        &layout.rendezvous,
                        format!(
                            "failed to determine whether invalid rendezvous metadata belongs to a live process: {error}"
                        ),
                    )
                })?,
                None => endpoint_from_record(&record)
                    .ok()
                    .is_some_and(|endpoint| {
                        authenticated_agent_reachable(&endpoint, self.config.poll_interval)
                    }),
            };
            if live_process {
                return Err(WineRuntimeError::at_path(
                    WineRuntimeErrorKind::RendezvousFailed,
                    &layout.rendezvous,
                    format!(
                        "agent rendezvous metadata is invalid but still identifies a live agent; preserving it for safe recovery: {validation_error}"
                    ),
                ));
            }
            remove_owned_regular_file(&layout.rendezvous)?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn write_record(
        &self,
        layout: &BottleLayout,
        record: &RendezvousRecord,
    ) -> Result<(), WineRuntimeError> {
        let bytes = serde_json::to_vec(record).map_err(|error| {
            WineRuntimeError::new(
                WineRuntimeErrorKind::RendezvousFailed,
                format!("failed to serialize agent rendezvous metadata: {error}"),
            )
        })?;
        write_atomic_secure(&layout.state_directory, &layout.rendezvous, &bytes)
    }

    fn deploy_agent(&self, layout: &BottleLayout) -> Result<(), WineRuntimeError> {
        ensure_secure_directory(&layout.deployment_directory)?;
        let source = &self.config.agent_artifact;
        let mut input = File::open(source).map_err(|error| {
            WineRuntimeError::at_path(
                WineRuntimeErrorKind::DeploymentFailed,
                source,
                format!("failed to open the packaged Windows agent: {error}"),
            )
        })?;
        let temporary = temporary_path(&layout.deployment_directory, "agent", "exe");
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(EXECUTABLE_FILE_MODE)
            .open(&temporary)
            .map_err(|error| {
                WineRuntimeError::at_path(
                    WineRuntimeErrorKind::DeploymentFailed,
                    &temporary,
                    format!("failed to create staged agent artifact: {error}"),
                )
            })?;
        let copy_result = io::copy(&mut input, &mut output)
            .and_then(|_| output.sync_all())
            .and_then(|_| {
                fs::set_permissions(&temporary, fs::Permissions::from_mode(EXECUTABLE_FILE_MODE))
            })
            .and_then(|_| fs::rename(&temporary, &layout.deployed_agent));
        if let Err(error) = copy_result {
            let _ = fs::remove_file(&temporary);
            return Err(WineRuntimeError::at_path(
                WineRuntimeErrorKind::DeploymentFailed,
                &layout.deployed_agent,
                format!("failed to deploy the Windows agent atomically: {error}"),
            ));
        }
        sync_directory(&layout.deployment_directory)?;
        Ok(())
    }

    fn spawn_agent(
        &self,
        layout: &BottleLayout,
        token: &AuthToken,
        expected_address: SocketAddr,
    ) -> Result<(Child, SocketAddr, HostProcessIdentity), WineRuntimeError> {
        cap_diagnostic_file(&layout.stderr)?;
        let diagnostic_file = open_secure_log(&layout.stderr)?;
        let mut command = Command::new(&self.config.wine_executable);
        command
            .arg(&layout.deployed_agent)
            .arg("--token-stdin")
            .arg("--listen-port")
            .arg(expected_address.port().to_string())
            .current_dir(&layout.deployment_directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(&self.config.environment)
            .env("WINEPREFIX", &layout.bottle)
            .env("WINELOADER", &self.config.wine_executable);
        if let Some(wineserver) = &self.config.wineserver_executable {
            command.env("WINESERVER", wineserver);
        }

        let mut child = command.spawn().map_err(|error| {
            WineRuntimeError::at_path(
                WineRuntimeErrorKind::ProcessFailed,
                &self.config.wine_executable,
                format!("failed to start the Wine agent process: {error}"),
            )
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            WineRuntimeError::new(
                WineRuntimeErrorKind::ProcessFailed,
                "Wine agent stderr was not piped",
            )
        })?;
        if let Err(error) = start_diagnostic_capture(stderr, diagnostic_file, layout.stderr.clone())
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WineRuntimeError::at_path(
                WineRuntimeErrorKind::ProcessFailed,
                &layout.stderr,
                format!("failed to start bounded agent diagnostic capture: {error}"),
            ));
        }
        let process = match process_identity(child.id()) {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(WineRuntimeError::new(
                    WineRuntimeErrorKind::ProcessFailed,
                    "Wine agent process disappeared before its identity could be recorded",
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(WineRuntimeError::new(
                    WineRuntimeErrorKind::ProcessFailed,
                    format!("failed to record the Wine agent process identity: {error}"),
                ));
            }
        };

        let token_write = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("Wine agent stdin was not piped"))
            .and_then(|mut stdin| {
                stdin.write_all(token.as_str().as_bytes())?;
                stdin.write_all(b"\n")?;
                stdin.flush()
            });
        if let Err(error) = token_write {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WineRuntimeError::new(
                WineRuntimeErrorKind::ProcessFailed,
                format!("failed to deliver agent authentication over stdin: {error}"),
            ));
        }

        let stdout = child.stdout.take().ok_or_else(|| {
            WineRuntimeError::new(
                WineRuntimeErrorKind::ProcessFailed,
                "Wine agent stdout was not piped",
            )
        })?;
        let receiver = start_listener_reader(stdout);
        let deadline = Instant::now() + self.config.startup_timeout;
        loop {
            if let Some(status) = child.try_wait().map_err(|error| {
                WineRuntimeError::new(
                    WineRuntimeErrorKind::ProcessFailed,
                    format!("failed to inspect the starting Wine agent: {error}"),
                )
            })? {
                return Err(WineRuntimeError::new(
                    WineRuntimeErrorKind::ProcessFailed,
                    format!(
                        "Wine agent exited before reporting its listener{}",
                        format_exit_status(status)
                    ),
                ));
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(WineRuntimeError::new(
                    WineRuntimeErrorKind::ProcessFailed,
                    "Wine agent did not report its listener before the startup deadline",
                ));
            }
            match receiver.recv_timeout(self.config.poll_interval.min(remaining)) {
                Ok(Ok(address)) if address == expected_address => {
                    return Ok((child, address, process))
                }
                Ok(Ok(address)) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(WineRuntimeError::new(
                        WineRuntimeErrorKind::ProcessFailed,
                        format!(
                            "Wine agent reported listener {address}, expected {expected_address}"
                        ),
                    ));
                }
                Ok(Err(error)) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(WineRuntimeError::new(
                        WineRuntimeErrorKind::ProcessFailed,
                        "Wine agent closed stdout before reporting its listener",
                    ));
                }
            }
        }
    }

    fn cleanup_record_if_process(
        &self,
        path: &Path,
        expected: &HostProcessIdentity,
    ) -> Result<(), WineRuntimeError> {
        let Some(bytes) = read_secure_file(path, MAX_RENDEZVOUS_BYTES)? else {
            return Ok(());
        };
        let Ok(record) = serde_json::from_slice::<RendezvousRecord>(&bytes) else {
            return Ok(());
        };
        if record.host_process.as_ref() == Some(expected) {
            remove_owned_regular_file(path)?;
        }
        Ok(())
    }

    fn cleanup_record_if_endpoint(
        &self,
        path: &Path,
        endpoint: &AgentEndpoint,
    ) -> Result<(), WineRuntimeError> {
        let Some(bytes) = read_secure_file(path, MAX_RENDEZVOUS_BYTES)? else {
            return Ok(());
        };
        let Ok(record) = serde_json::from_slice::<RendezvousRecord>(&bytes) else {
            return Ok(());
        };
        let Ok(recorded) = endpoint_from_record(&record) else {
            return Ok(());
        };
        if recorded.address == endpoint.address && recorded.token == endpoint.token {
            remove_owned_regular_file(path)?;
        }
        Ok(())
    }

    fn wait_until_exited(
        &self,
        identity: &HostProcessIdentity,
        timeout: Duration,
    ) -> Result<bool, WineRuntimeError> {
        let deadline = Instant::now() + timeout;
        loop {
            if !process_identity_matches(identity).map_err(|error| {
                WineRuntimeError::new(
                    WineRuntimeErrorKind::ProcessFailed,
                    format!(
                        "failed to inspect Wine agent process {}: {error}",
                        identity.pid
                    ),
                )
            })? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(
                self.config
                    .poll_interval
                    .min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}

impl AgentRuntime for WineAgentRuntime {
    fn discover(&mut self, bottle: &BottleId) -> Result<Option<AgentEndpoint>, String> {
        let layout = BottleLayout::resolve(bottle).map_err(|error| error.to_string())?;
        ensure_secure_directory(&layout.state_directory).map_err(|error| error.to_string())?;
        cap_diagnostic_file(&layout.stderr).map_err(|error| error.to_string())?;
        let Some(record) = self
            .read_record(&layout)
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let endpoint = endpoint_from_record(&record).map_err(|error| error.to_string())?;
        if let Some(process) = &record.host_process {
            if !process_identity_matches(process)
                .map_err(|error| format!("failed to inspect recorded Wine agent: {error}"))?
            {
                self.cleanup_record_if_process(&layout.rendezvous, process)
                    .map_err(|error| error.to_string())?;
                self.owned_processes.remove(bottle);
                return Ok(None);
            }
            return Ok(Some(endpoint));
        }

        if launch_lock_is_held(&layout).map_err(|error| error.to_string())? {
            return Ok(None);
        }
        if wait_for_authenticated_agent(
            &endpoint,
            self.config.startup_timeout,
            self.config.poll_interval,
        ) {
            return Ok(Some(endpoint));
        }
        self.cleanup_record_if_endpoint(&layout.rendezvous, &endpoint)
            .map_err(|error| error.to_string())?;
        Ok(None)
    }

    fn launch(&mut self, bottle: &BottleId) -> Result<AgentLaunch, AgentLaunchError> {
        let layout = BottleLayout::resolve(bottle)
            .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
        ensure_secure_directory(&layout.state_directory)
            .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
        let _lock = match LaunchGuard::acquire(&layout) {
            Ok(guard) => guard,
            Err(LaunchLockError::AlreadyRunning) => return Err(AgentLaunchError::AlreadyRunning),
            Err(LaunchLockError::Failed(error)) => {
                return Err(AgentLaunchError::Failed(error.to_string()))
            }
        };
        match self.read_record(&layout) {
            Ok(Some(record)) => match record.host_process.as_ref() {
                Some(process) => match process_identity_matches(process) {
                    Ok(true) => return Err(AgentLaunchError::AlreadyRunning),
                    Ok(false) => self
                        .cleanup_record_if_process(&layout.rendezvous, process)
                        .map_err(|error| AgentLaunchError::Failed(error.to_string()))?,
                    Err(error) => {
                        return Err(AgentLaunchError::Failed(format!(
                            "failed to inspect an existing Wine agent before launch: {error}"
                        )))
                    }
                },
                None => {
                    let endpoint = endpoint_from_record(&record)
                        .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
                    if authenticated_agent_reachable(&endpoint, self.config.poll_interval) {
                        return Err(AgentLaunchError::AlreadyRunning);
                    }
                    self.cleanup_record_if_endpoint(&layout.rendezvous, &endpoint)
                        .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
                }
            },
            Ok(None) => {}
            Err(error) => return Err(AgentLaunchError::Failed(error.to_string())),
        }
        self.deploy_agent(&layout)
            .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
        let token = AuthToken::generate().map_err(|error| {
            AgentLaunchError::Failed(format!("failed to generate token: {error}"))
        })?;
        let reservation = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| {
            AgentLaunchError::Failed(format!("failed to reserve agent loopback port: {error}"))
        })?;
        let address = reservation.local_addr().map_err(|error| {
            AgentLaunchError::Failed(format!("failed to inspect reserved agent port: {error}"))
        })?;
        let endpoint = AgentEndpoint {
            address,
            token: token.clone(),
        };
        let mut record = RendezvousRecord {
            schema_version: RENDEZVOUS_SCHEMA_VERSION,
            bottle_id: bottle.as_str().to_string(),
            address: address.to_string(),
            token: token.as_str().to_string(),
            host_process: None,
            deployed_agent: layout.deployed_agent.to_string_lossy().into_owned(),
            agent_instance_id: None,
            agent_process_id: None,
        };
        self.write_record(&layout, &record)
            .map_err(|error| AgentLaunchError::Failed(error.to_string()))?;
        drop(reservation);

        let (child, reported_address, process) = match self.spawn_agent(&layout, &token, address) {
            Ok(started) => started,
            Err(error) => {
                let _ = self.cleanup_record_if_endpoint(&layout.rendezvous, &endpoint);
                return Err(AgentLaunchError::Failed(error.to_string()));
            }
        };
        record.host_process = Some(process.clone());
        if let Err(error) = self.write_record(&layout, &record) {
            let mut child = child;
            terminate_owned_child(
                &mut child,
                self.config.terminate_timeout,
                self.config.poll_interval,
            );
            let _ = self.cleanup_record_if_endpoint(&layout.rendezvous, &endpoint);
            return Err(AgentLaunchError::Failed(error.to_string()));
        }
        let child = SharedChild::new(child);
        self.owned_processes.insert(bottle.clone(), child.clone());
        Ok(AgentLaunch {
            endpoint: AgentEndpoint {
                address: reported_address,
                token,
            },
            process: Box::new(LaunchedWineProcess {
                child,
                identity: process,
                rendezvous: layout.rendezvous,
                stderr: layout.stderr,
            }),
        })
    }

    fn reconnect_monitor(
        &mut self,
        bottle: &BottleId,
        endpoint: &AgentEndpoint,
        identity: &AgentIdentity,
    ) -> Result<Box<dyn AgentProcess>, String> {
        let layout = BottleLayout::resolve(bottle).map_err(|error| error.to_string())?;
        let mut record = self
            .read_record(&layout)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "agent rendezvous metadata disappeared during reconnect".to_string())?;
        let recorded_endpoint = endpoint_from_record(&record).map_err(|error| error.to_string())?;
        if recorded_endpoint.address != endpoint.address
            || recorded_endpoint.token != endpoint.token
        {
            return Err(
                "agent rendezvous metadata changed during authenticated reconnect".to_string(),
            );
        }
        if let Some(process) = &record.host_process {
            if !process_identity_matches(process)
                .map_err(|error| format!("failed to inspect reconnected Wine agent: {error}"))?
            {
                self.cleanup_record_if_process(&layout.rendezvous, process)
                    .map_err(|error| error.to_string())?;
                self.owned_processes.remove(bottle);
                return Err("reconnected Wine agent process already exited".to_string());
            }
        }
        record.agent_instance_id = Some(identity.instance_id.clone());
        record.agent_process_id = Some(identity.process_id);
        self.write_record(&layout, &record)
            .map_err(|error| error.to_string())?;
        if let (Some(child), Some(process)) = (
            self.owned_processes.get(bottle).cloned(),
            record.host_process.clone(),
        ) {
            return Ok(Box::new(LaunchedWineProcess {
                child,
                identity: process.clone(),
                rendezvous: layout.rendezvous,
                stderr: layout.stderr,
            }));
        }
        let process = record.host_process;
        Ok(Box::new(ReconnectedWineProcess {
            identity: process.clone(),
            rendezvous: layout.rendezvous,
            stderr: layout.stderr,
        }))
    }

    fn retire(
        &mut self,
        bottle: &BottleId,
        endpoint: &AgentEndpoint,
        _reason: &str,
    ) -> Result<(), String> {
        let layout = BottleLayout::resolve(bottle).map_err(|error| error.to_string())?;
        let Some(record) = self
            .read_record(&layout)
            .map_err(|error| error.to_string())?
        else {
            return Ok(());
        };
        let recorded_endpoint = endpoint_from_record(&record).map_err(|error| error.to_string())?;
        if recorded_endpoint.address != endpoint.address
            || recorded_endpoint.token != endpoint.token
        {
            return Err(
                "refusing to retire a Wine process whose rendezvous endpoint changed".to_string(),
            );
        }

        let Some(process) = record.host_process else {
            thread::sleep(self.config.graceful_retire_timeout);
            if authenticated_agent_reachable(endpoint, self.config.poll_interval) {
                return Err(
                    "agent was recovered from an interrupted launch and remained reachable after graceful shutdown; refusing unsafe PID-only termination"
                        .to_string(),
                );
            }
            return self
                .cleanup_record_if_endpoint(&layout.rendezvous, endpoint)
                .map_err(|error| error.to_string());
        };

        if let Some(child) = self.owned_processes.remove(bottle) {
            if !child
                .wait_until_exited(
                    self.config.graceful_retire_timeout,
                    self.config.poll_interval,
                )
                .map_err(|error| error.to_string())?
            {
                child
                    .signal(libc::SIGTERM)
                    .map_err(|error| error.to_string())?;
                if !child
                    .wait_until_exited(self.config.terminate_timeout, self.config.poll_interval)
                    .map_err(|error| error.to_string())?
                {
                    child.kill().map_err(|error| error.to_string())?;
                    if !child
                        .wait_until_exited(self.config.terminate_timeout, self.config.poll_interval)
                        .map_err(|error| error.to_string())?
                    {
                        return Err(format!(
                            "Wine agent process {} did not exit after bounded termination",
                            process.pid
                        ));
                    }
                }
            }
        } else if !self
            .wait_until_exited(&process, self.config.graceful_retire_timeout)
            .map_err(|error| error.to_string())?
        {
            return Err(format!(
                "reconnected Wine agent process {} did not exit gracefully; refusing unsafe PID-only termination",
                process.pid
            ));
        }
        self.cleanup_record_if_process(&layout.rendezvous, &process)
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone)]
struct SharedChild {
    inner: Arc<SharedChildInner>,
}

struct SharedChildInner {
    state: Mutex<SharedChildState>,
}

struct SharedChildState {
    child: Option<Child>,
    exit: Option<ExitStatus>,
}

impl SharedChild {
    fn new(child: Child) -> Self {
        Self {
            inner: Arc::new(SharedChildInner {
                state: Mutex::new(SharedChildState {
                    child: Some(child),
                    exit: None,
                }),
            }),
        }
    }

    fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::other("Wine child process lock was poisoned"))?;
        if let Some(exit) = state.exit {
            return Ok(Some(exit));
        }
        let Some(child) = state.child.as_mut() else {
            return Ok(state.exit);
        };
        let Some(exit) = child.try_wait()? else {
            return Ok(None);
        };
        state.exit = Some(exit);
        state.child.take();
        Ok(Some(exit))
    }

    fn signal(&self, signal: libc::c_int) -> io::Result<()> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::other("Wine child process lock was poisoned"))?;
        if state.exit.is_some() {
            return Ok(());
        }
        let Some(child) = state.child.as_mut() else {
            return Ok(());
        };
        if let Some(exit) = child.try_wait()? {
            state.exit = Some(exit);
            state.child.take();
            return Ok(());
        }
        let pid = i32::try_from(child.id())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID exceeds i32"))?;
        if unsafe { libc::kill(pid, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn kill(&self) -> io::Result<()> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::other("Wine child process lock was poisoned"))?;
        if state.exit.is_some() {
            return Ok(());
        }
        let Some(child) = state.child.as_mut() else {
            return Ok(());
        };
        match child.try_wait()? {
            Some(exit) => {
                state.exit = Some(exit);
                state.child.take();
                Ok(())
            }
            None => child.kill(),
        }
    }

    fn wait_until_exited(&self, timeout: Duration, poll: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.try_wait()?.is_some() {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

impl fmt::Debug for SharedChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedChild(..)")
    }
}

impl Drop for SharedChildInner {
    fn drop(&mut self) {
        let Ok(state) = self.state.get_mut() else {
            return;
        };
        let Some(mut child) = state.child.take() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(exit)) => state.exit = Some(exit),
            Ok(None) => {
                thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Err(_) => {}
        }
    }
}

struct LaunchedWineProcess {
    child: SharedChild,
    identity: HostProcessIdentity,
    rendezvous: PathBuf,
    stderr: PathBuf,
}

impl AgentProcess for LaunchedWineProcess {
    fn try_wait(&mut self) -> io::Result<Option<AgentExit>> {
        cap_diagnostic_file_io(&self.stderr)?;
        let Some(status) = self.child.try_wait()? else {
            return Ok(None);
        };
        let _ = remove_rendezvous_if_process(&self.rendezvous, &self.identity);
        Ok(Some(AgentExit {
            code: status.code(),
            stderr: read_bounded_diagnostic(&self.stderr).unwrap_or_default(),
        }))
    }
}

struct ReconnectedWineProcess {
    identity: Option<HostProcessIdentity>,
    rendezvous: PathBuf,
    stderr: PathBuf,
}

impl AgentProcess for ReconnectedWineProcess {
    fn try_wait(&mut self) -> io::Result<Option<AgentExit>> {
        cap_diagnostic_file_io(&self.stderr)?;
        let Some(identity) = &self.identity else {
            return Ok(None);
        };
        if process_identity_matches(identity)? {
            return Ok(None);
        }
        let _ = remove_rendezvous_if_process(&self.rendezvous, identity);
        Ok(Some(AgentExit {
            code: None,
            stderr: read_bounded_diagnostic(&self.stderr).unwrap_or_default(),
        }))
    }
}

#[derive(Debug)]
enum LaunchLockError {
    AlreadyRunning,
    Failed(WineRuntimeError),
}

struct LaunchGuard {
    _file: File,
}

impl LaunchGuard {
    fn acquire(layout: &BottleLayout) -> Result<Self, LaunchLockError> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(SECURE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&layout.launch_lock)
            .map_err(|error| {
                LaunchLockError::Failed(WineRuntimeError::at_path(
                    WineRuntimeErrorKind::RendezvousFailed,
                    &layout.launch_lock,
                    format!("failed to open launch lock: {error}"),
                ))
            })?;
        let metadata = file.metadata().map_err(|error| {
            LaunchLockError::Failed(WineRuntimeError::at_path(
                WineRuntimeErrorKind::RendezvousFailed,
                &layout.launch_lock,
                format!("failed to inspect launch lock: {error}"),
            ))
        })?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(LaunchLockError::Failed(WineRuntimeError::at_path(
                WineRuntimeErrorKind::UnsafeFilesystem,
                &layout.launch_lock,
                "launch lock must be an owner-only regular file",
            )));
        }
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(Self { _file: file });
        }
        let error = io::Error::last_os_error();
        let code = error.raw_os_error();
        if code == Some(libc::EWOULDBLOCK) || code == Some(libc::EAGAIN) {
            Err(LaunchLockError::AlreadyRunning)
        } else {
            Err(LaunchLockError::Failed(WineRuntimeError::at_path(
                WineRuntimeErrorKind::RendezvousFailed,
                &layout.launch_lock,
                format!("failed to acquire launch lock: {error}"),
            )))
        }
    }
}

fn launch_lock_is_held(layout: &BottleLayout) -> Result<bool, WineRuntimeError> {
    match LaunchGuard::acquire(layout) {
        Ok(guard) => {
            drop(guard);
            Ok(false)
        }
        Err(LaunchLockError::AlreadyRunning) => Ok(true),
        Err(LaunchLockError::Failed(error)) => Err(error),
    }
}

fn validate_timing(config: &WineRuntimeConfig) -> Result<(), WineRuntimeError> {
    if config.startup_timeout.is_zero()
        || config.poll_interval.is_zero()
        || config.graceful_retire_timeout.is_zero()
        || config.terminate_timeout.is_zero()
    {
        return Err(WineRuntimeError::new(
            WineRuntimeErrorKind::InvalidConfiguration,
            "Wine runtime timeouts and polling interval must be non-zero",
        ));
    }
    Ok(())
}

fn validate_executable(path: &Path, label: &str) -> Result<PathBuf, WineRuntimeError> {
    let canonical = validate_regular_path(path, label)?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidConfiguration,
            &canonical,
            format!("failed to inspect {label}: {error}"),
        )
    })?;
    if metadata.mode() & 0o111 == 0 {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidConfiguration,
            &canonical,
            format!("{label} is not executable"),
        ));
    }
    Ok(canonical)
}

fn validate_agent_artifact(path: &Path) -> Result<PathBuf, WineRuntimeError> {
    let canonical = validate_regular_path(path, "packaged Windows agent")?;
    let mut file = File::open(&canonical).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidConfiguration,
            &canonical,
            format!("failed to inspect packaged Windows agent: {error}"),
        )
    })?;
    let mut signature = [0u8; 2];
    file.read_exact(&mut signature).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidConfiguration,
            &canonical,
            format!("packaged Windows agent is truncated: {error}"),
        )
    })?;
    if signature != *b"MZ" {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidConfiguration,
            &canonical,
            "packaged Windows agent is not a PE executable",
        ));
    }
    Ok(canonical)
}

fn validate_regular_path(path: &Path, label: &str) -> Result<PathBuf, WineRuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidConfiguration,
            path,
            format!("{label} is unavailable: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidConfiguration,
            path,
            format!("{label} must be a regular file, not a symlink"),
        ));
    }
    fs::canonicalize(path).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidConfiguration,
            path,
            format!("failed to canonicalize {label}: {error}"),
        )
    })
}

fn canonical_bottle_path(path: &Path) -> Result<PathBuf, WineRuntimeError> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidBottle,
            path,
            format!("failed to canonicalize Wine bottle: {error}"),
        )
    })?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidBottle,
            &canonical,
            format!("failed to inspect Wine bottle: {error}"),
        )
    })?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidBottle,
            &canonical,
            "Wine bottle must be a directory owned by the current user",
        ));
    }
    let system_registry = canonical.join("system.reg");
    let registry_metadata = fs::symlink_metadata(&system_registry).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::InvalidBottle,
            &system_registry,
            format!("Wine bottle is not initialized: {error}"),
        )
    })?;
    if registry_metadata.file_type().is_symlink() || !registry_metadata.is_file() {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::UnsafeFilesystem,
            &system_registry,
            "Wine bottle system.reg must be a regular file",
        ));
    }
    Ok(canonical)
}

fn ensure_secure_directory(path: &Path) -> Result<(), WineRuntimeError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(WineRuntimeError::at_path(
                WineRuntimeErrorKind::UnsafeFilesystem,
                path,
                format!("failed to create managed directory: {error}"),
            ))
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::UnsafeFilesystem,
            path,
            format!("failed to inspect managed directory: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::UnsafeFilesystem,
            path,
            "managed directory must be a real directory owned by the current user",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(SECURE_DIRECTORY_MODE)).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::UnsafeFilesystem,
            path,
            format!("failed to secure managed directory: {error}"),
        )
    })
}

fn read_secure_file(path: &Path, maximum: u64) -> Result<Option<Vec<u8>>, WineRuntimeError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(WineRuntimeError::at_path(
                WineRuntimeErrorKind::UnsafeFilesystem,
                path,
                format!("failed to inspect managed file: {error}"),
            ))
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::UnsafeFilesystem,
            path,
            "managed file must be an owner-only regular file",
        ));
    }
    if metadata.len() > maximum {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            path,
            format!("managed file exceeds the {maximum}-byte limit"),
        ));
    }
    fs::read(path).map(Some).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            path,
            format!("failed to read managed file: {error}"),
        )
    })
}

fn write_atomic_secure(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), WineRuntimeError> {
    if bytes.len() as u64 > MAX_RENDEZVOUS_BYTES {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            destination,
            "agent rendezvous metadata exceeds the size limit",
        ));
    }
    let temporary = temporary_path(directory, "rendezvous", "tmp");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(SECURE_FILE_MODE)
        .open(&temporary)
        .map_err(|error| {
            WineRuntimeError::at_path(
                WineRuntimeErrorKind::RendezvousFailed,
                &temporary,
                format!("failed to create staged rendezvous metadata: {error}"),
            )
        })?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.sync_all())
        .and_then(|_| fs::rename(&temporary, destination));
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            destination,
            format!("failed to persist rendezvous metadata atomically: {error}"),
        ));
    }
    sync_directory(directory)
}

fn cap_diagnostic_file(path: &Path) -> Result<(), WineRuntimeError> {
    cap_diagnostic_file_io(path).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::ProcessFailed,
            path,
            format!("failed to cap agent stderr diagnostics: {error}"),
        )
    })
}

fn cap_diagnostic_file_io(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "agent stderr log is not an owner-only regular file",
        ));
    }
    if metadata.len() <= MAX_STDERR_ON_DISK_BYTES {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.seek(SeekFrom::End(-(MAX_STDERR_BYTES as i64)))?;
    let mut tail = Vec::with_capacity(MAX_STDERR_BYTES as usize);
    file.read_to_end(&mut tail)?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(b"[TRUNCATED]\n")?;
    file.write_all(&tail)?;
    file.sync_data()
}

fn open_secure_log(path: &Path) -> Result<File, WineRuntimeError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(WineRuntimeError::at_path(
                WineRuntimeErrorKind::UnsafeFilesystem,
                path,
                "agent stderr destination must be an owned regular file",
            ));
        }
    }
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(SECURE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_APPEND)
        .open(path)
        .and_then(|file| {
            fs::set_permissions(path, fs::Permissions::from_mode(SECURE_FILE_MODE))?;
            Ok(file)
        })
        .map_err(|error| {
            WineRuntimeError::at_path(
                WineRuntimeErrorKind::ProcessFailed,
                path,
                format!("failed to open bounded agent stderr log: {error}"),
            )
        })
}

fn start_diagnostic_capture(
    mut reader: impl Read + Send + 'static,
    mut output: File,
    path: PathBuf,
) -> io::Result<()> {
    thread::Builder::new()
        .name("deimos-agent-stderr".to_string())
        .spawn(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if output.write_all(&buffer[..read]).is_err() {
                            break;
                        }
                        if cap_diagnostic_file_io(&path).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = output.flush();
            let _ = cap_diagnostic_file_io(&path);
        })
        .map(|_| ())
}

fn endpoint_from_record(record: &RendezvousRecord) -> Result<AgentEndpoint, WineRuntimeError> {
    let address: SocketAddr = record.address.parse().map_err(|error| {
        WineRuntimeError::new(
            WineRuntimeErrorKind::RendezvousFailed,
            format!("recorded agent address is invalid: {error}"),
        )
    })?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(WineRuntimeError::new(
            WineRuntimeErrorKind::RendezvousFailed,
            "recorded agent address is not a usable loopback endpoint",
        ));
    }
    let token = AuthToken::from_string(record.token.clone()).map_err(|error| {
        WineRuntimeError::new(
            WineRuntimeErrorKind::RendezvousFailed,
            format!("recorded agent token is invalid: {error}"),
        )
    })?;
    Ok(AgentEndpoint { address, token })
}

fn authenticated_agent_reachable(endpoint: &AgentEndpoint, timeout: Duration) -> bool {
    let default = RpcConfig::default();
    RpcClient::connect(
        endpoint.address,
        endpoint.token.clone(),
        Vec::new(),
        None,
        RpcConfig {
            max_message_size: default.max_message_size,
            io_timeout: timeout,
        },
    )
    .is_ok()
}

fn wait_for_authenticated_agent(
    endpoint: &AgentEndpoint,
    timeout: Duration,
    poll: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        if authenticated_agent_reachable(endpoint, poll.min(remaining)) {
            return true;
        }
        thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn validate_record(
    layout: &BottleLayout,
    record: &RendezvousRecord,
) -> Result<(), WineRuntimeError> {
    if record.schema_version != RENDEZVOUS_SCHEMA_VERSION {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            &layout.rendezvous,
            format!(
                "unsupported agent rendezvous schema {}; expected {}",
                record.schema_version, RENDEZVOUS_SCHEMA_VERSION
            ),
        ));
    }
    if record.bottle_id != layout.bottle.to_string_lossy() {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            &layout.rendezvous,
            "agent rendezvous belongs to a different bottle",
        ));
    }
    let deployed = Path::new(&record.deployed_agent);
    if deployed != layout.deployed_agent || !deployed.starts_with(&layout.bottle) {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            &layout.rendezvous,
            "recorded agent artifact path escaped the bottle",
        ));
    }
    endpoint_from_record(record)?;
    if record
        .host_process
        .as_ref()
        .is_some_and(|process| process.pid <= 1 || process.start_id == 0)
    {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            &layout.rendezvous,
            "recorded Wine process identity is invalid",
        ));
    }
    Ok(())
}

fn start_listener_reader(
    stdout: impl Read + Send + 'static,
) -> mpsc::Receiver<Result<SocketAddr, WineRuntimeError>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut reader =
            BufReader::new(stdout.take((MAX_STARTUP_STDOUT_BYTES.saturating_add(1)) as u64));
        let mut consumed = 0usize;
        let mut reported = false;
        loop {
            let mut line = Vec::new();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => {
                    if !reported {
                        let _ = sender.send(Err(WineRuntimeError::new(
                            WineRuntimeErrorKind::ProcessFailed,
                            "Wine agent closed stdout before reporting its listener",
                        )));
                    }
                    return;
                }
                Ok(read) => {
                    consumed = consumed.saturating_add(read);
                    if consumed > MAX_STARTUP_STDOUT_BYTES && !reported {
                        let _ = sender.send(Err(WineRuntimeError::new(
                            WineRuntimeErrorKind::ProcessFailed,
                            "Wine agent startup output exceeded the bounded limit",
                        )));
                        return;
                    }
                    if reported {
                        continue;
                    }
                    let Ok(line) = std::str::from_utf8(&line) else {
                        continue;
                    };
                    let Some(value) = line.trim().strip_prefix(LISTENER_MARKER) else {
                        continue;
                    };
                    let address = value.parse::<SocketAddr>().map_err(|error| {
                        WineRuntimeError::new(
                            WineRuntimeErrorKind::ProcessFailed,
                            format!("Wine agent reported an invalid listener address: {error}"),
                        )
                    });
                    let address = address.and_then(|address| {
                        if address.ip().is_loopback() && address.port() != 0 {
                            Ok(address)
                        } else {
                            Err(WineRuntimeError::new(
                                WineRuntimeErrorKind::ProcessFailed,
                                "Wine agent reported a non-loopback or zero-port listener",
                            ))
                        }
                    });
                    reported = address.is_ok();
                    let failed = address.is_err();
                    let _ = sender.send(address);
                    if failed {
                        return;
                    }
                }
                Err(error) => {
                    if !reported {
                        let _ = sender.send(Err(WineRuntimeError::new(
                            WineRuntimeErrorKind::ProcessFailed,
                            format!("failed to read Wine agent startup output: {error}"),
                        )));
                    }
                    return;
                }
            }
        }
    });
    receiver
}

fn temporary_path(directory: &Path, label: &str, extension: &str) -> PathBuf {
    let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        ".{label}-{}-{sequence}.{extension}",
        std::process::id()
    ))
}

fn sync_directory(path: &Path) -> Result<(), WineRuntimeError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            WineRuntimeError::at_path(
                WineRuntimeErrorKind::RendezvousFailed,
                path,
                format!("failed to synchronize managed directory: {error}"),
            )
        })
}

fn remove_owned_regular_file(path: &Path) -> Result<(), WineRuntimeError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(WineRuntimeError::at_path(
                WineRuntimeErrorKind::UnsafeFilesystem,
                path,
                format!("failed to inspect stale managed file: {error}"),
            ))
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(WineRuntimeError::at_path(
            WineRuntimeErrorKind::UnsafeFilesystem,
            path,
            "refusing to remove a managed path that is not an owned regular file",
        ));
    }
    fs::remove_file(path).map_err(|error| {
        WineRuntimeError::at_path(
            WineRuntimeErrorKind::RendezvousFailed,
            path,
            format!("failed to remove stale managed file: {error}"),
        )
    })
}

fn remove_rendezvous_if_process(path: &Path, expected: &HostProcessIdentity) -> io::Result<()> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let record: RendezvousRecord = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if record.host_process.as_ref() == Some(expected) {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn read_bounded_diagnostic(path: &Path) -> io::Result<String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error),
    };
    let length = file.metadata()?.len();
    let start = length.saturating_sub(MAX_STDERR_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::with_capacity((length - start) as usize);
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    if start == 0 {
        Ok(text.into_owned())
    } else {
        Ok(format!("[TRUNCATED]\n{text}"))
    }
}

fn terminate_owned_child(child: &mut Child, timeout: Duration, poll: Duration) {
    let _ = child.kill();
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => return,
            Ok(None) => thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now()))),
        }
    }
}

fn process_identity_matches(expected: &HostProcessIdentity) -> io::Result<bool> {
    Ok(process_identity(expected.pid)?.as_ref() == Some(expected))
}

#[cfg(target_os = "macos")]
fn process_identity(pid: u32) -> io::Result<Option<HostProcessIdentity>> {
    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID exceeds i32"))?;
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
        .expect("proc_bsdinfo size should fit in i32");
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if result == size {
        if info.pbi_status == libc::SZOMB {
            return Ok(None);
        }
        let start_id = info
            .pbi_start_tvsec
            .checked_mul(1_000_000)
            .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
            .ok_or_else(|| io::Error::other("process start time overflowed"))?;
        return Ok(Some(HostProcessIdentity {
            pid: info.pbi_pid,
            start_id,
        }));
    }
    if result == 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) {
            return Ok(None);
        }
        return Err(error);
    }
    Err(io::Error::other(format!(
        "proc_pidinfo returned {result} bytes; expected {size}"
    )))
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> io::Result<Option<HostProcessIdentity>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = match fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let close = stat.rfind(')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process stat omitted command terminator",
        )
    })?;
    let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    if fields.first().is_some_and(|state| *state == "Z") {
        return Ok(None);
    }
    let start_id = fields
        .get(19)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "process stat omitted start time",
            )
        })?
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(Some(HostProcessIdentity { pid, start_id }))
}

fn format_exit_status(status: ExitStatus) -> String {
    status.code().map_or_else(
        || " (signal or unknown status)".to_string(),
        |code| format!(" (exit code {code})"),
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use deimos_core::rpc::RpcServer;

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "deimos-wine-runtime-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory should be created");
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn create_bottle(root: &Path, name: &str) -> PathBuf {
        let bottle = root.join(name);
        fs::create_dir_all(bottle.join("drive_c")).expect("bottle drive should be created");
        fs::write(bottle.join("system.reg"), b"WINE REGISTRY Version 2\n")
            .expect("system registry should be created");
        bottle
    }

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).expect("test executable should be written");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("test executable should be executable");
    }

    fn fake_wine_script() -> String {
        format!(
            r#"#!/bin/sh
set -eu
IFS= read -r token
port=''
for argument in "$@"; do
  port="$argument"
done
capture="$WINEPREFIX/{MANAGED_STATE_DIRECTORY}/test-capture.txt"
{{
  printf 'prefix=%s\n' "$WINEPREFIX"
  printf 'loader=%s\n' "$WINELOADER"
  printf 'arguments='
  printf '<%s>' "$@"
  printf '\n'
  printf 'token_length=%s\n' "${{#token}}"
}} > "$capture"
printf '{LISTENER_MARKER}127.0.0.1:%s\n' "$port"
trap 'exit 0' TERM INT
while :; do
  sleep 1
done
"#
        )
    }

    fn runtime_fixture(root: &Path, port: u16) -> WineAgentRuntime {
        let wine = root.join(format!("fake-wine-{port}"));
        write_executable(&wine, &fake_wine_script());
        let artifact = root.join(format!("deimos-agent-{port}.exe"));
        fs::write(&artifact, b"MZportable-test-agent")
            .expect("test agent artifact should be written");
        WineAgentRuntime::new(WineRuntimeConfig::new(wine, artifact).with_timing(
            Duration::from_secs(2),
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_secs(2),
        ))
        .expect("test runtime should be valid")
    }

    fn wait_for_exit(process: &mut Box<dyn AgentProcess>) -> AgentExit {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(exit) = process
                .try_wait()
                .expect("process status should be readable")
            {
                return exit;
            }
            assert!(
                Instant::now() < deadline,
                "test process did not exit before deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn bottle_ids_are_canonical_and_require_initialized_owned_prefixes() {
        let root = TestDirectory::new("bottle-id");
        let bottle = create_bottle(&root.path, "wizard101");
        let alias = root.path.join("alias");
        symlink(&bottle, &alias).expect("bottle alias should be created");

        let direct = WineAgentRuntime::bottle_id(&bottle).expect("bottle should be valid");
        let through_alias =
            WineAgentRuntime::bottle_id(&alias).expect("bottle alias should canonicalize");
        assert_eq!(direct, through_alias);
        assert_eq!(
            direct.as_str(),
            fs::canonicalize(&bottle)
                .expect("bottle should canonicalize")
                .to_str()
                .expect("test path should be UTF-8")
        );

        let uninitialized = root.path.join("uninitialized");
        fs::create_dir(&uninitialized).expect("uninitialized directory should be created");
        let error = WineAgentRuntime::bottle_id(&uninitialized)
            .expect_err("uninitialized directory must not become a bottle ID");
        assert_eq!(error.kind, WineRuntimeErrorKind::InvalidBottle);
    }

    #[test]
    fn runtime_configuration_rejects_missing_non_pe_and_symlinked_artifacts() {
        let root = TestDirectory::new("configuration");
        let wine = root.path.join("wine");
        write_executable(&wine, "#!/bin/sh\nexit 0\n");
        let missing = root.path.join("missing.exe");
        let error = WineAgentRuntime::new(WineRuntimeConfig::new(&wine, &missing))
            .expect_err("missing artifact must be rejected");
        assert_eq!(error.kind, WineRuntimeErrorKind::InvalidConfiguration);

        let text = root.path.join("text.exe");
        fs::write(&text, b"not a PE").expect("text artifact should be written");
        let error = WineAgentRuntime::new(WineRuntimeConfig::new(&wine, &text))
            .expect_err("non-PE artifact must be rejected");
        assert!(error.message.contains("not a PE"));

        let artifact = root.path.join("agent.exe");
        fs::write(&artifact, b"MZagent").expect("PE-shaped artifact should be written");
        let alias = root.path.join("agent-link.exe");
        symlink(&artifact, &alias).expect("artifact symlink should be created");
        let error = WineAgentRuntime::new(WineRuntimeConfig::new(&wine, &alias))
            .expect_err("artifact symlink must be rejected");
        assert!(error.message.contains("not a symlink"));
    }

    #[test]
    fn launch_deploys_persists_and_retires_one_agent_without_token_arguments() {
        let root = TestDirectory::new("launch");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let mut runtime = runtime_fixture(&root.path, 43101);

        let mut launch = runtime.launch(&bottle).expect("agent should launch");
        assert!(launch.endpoint.address.ip().is_loopback());
        assert_ne!(launch.endpoint.address.port(), 0);
        let endpoint_debug = format!("{:?}", launch.endpoint);
        assert!(endpoint_debug.contains("REDACTED"));
        assert!(!endpoint_debug.contains(launch.endpoint.token.as_str()));

        let layout = BottleLayout::resolve(&bottle).expect("layout should resolve");
        assert_eq!(
            fs::read(&layout.deployed_agent).expect("deployed agent should be readable"),
            b"MZportable-test-agent"
        );
        assert_eq!(
            fs::metadata(&layout.state_directory)
                .expect("state directory should exist")
                .permissions()
                .mode()
                & 0o777,
            SECURE_DIRECTORY_MODE
        );
        assert_eq!(
            fs::metadata(&layout.rendezvous)
                .expect("rendezvous should exist")
                .permissions()
                .mode()
                & 0o777,
            SECURE_FILE_MODE
        );

        let capture = fs::read_to_string(layout.state_directory.join("test-capture.txt"))
            .expect("fake Wine should capture launch inputs");
        assert!(capture.contains(&format!("prefix={}", bottle.as_str())));
        assert!(capture.contains("<--token-stdin>"));
        assert!(!capture.contains("<--token>"));
        assert!(capture.contains("token_length=64"));
        assert!(!capture.contains(launch.endpoint.token.as_str()));

        let discovered = runtime
            .discover(&bottle)
            .expect("discovery should work")
            .expect("running agent should be discovered");
        assert_eq!(discovered.address, launch.endpoint.address);
        assert_eq!(discovered.token, launch.endpoint.token);

        runtime
            .retire(&bottle, &launch.endpoint, "test complete")
            .expect("agent should retire");
        let _ = wait_for_exit(&mut launch.process);
        assert!(!layout.rendezvous.exists());
    }

    #[test]
    fn active_rendezvous_makes_concurrent_launch_converge() {
        let root = TestDirectory::new("concurrent");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let mut first = runtime_fixture(&root.path, 43102);
        let mut second = runtime_fixture(&root.path, 43102);
        let mut launch = first.launch(&bottle).expect("first agent should launch");

        let error = match second.launch(&bottle) {
            Ok(_) => panic!("second runtime must converge on the active agent"),
            Err(error) => error,
        };
        assert_eq!(error, AgentLaunchError::AlreadyRunning);

        first
            .retire(&bottle, &launch.endpoint, "test complete")
            .expect("first agent should retire");
        let _ = wait_for_exit(&mut launch.process);
    }

    #[test]
    fn reconnect_monitor_records_agent_identity_and_observes_exit() {
        let root = TestDirectory::new("reconnect");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let mut launcher = runtime_fixture(&root.path, 43103);
        let mut launch = launcher.launch(&bottle).expect("agent should launch");
        let mut restarted_host = runtime_fixture(&root.path, 43103);
        let endpoint = restarted_host
            .discover(&bottle)
            .expect("discovery should work")
            .expect("agent should be discoverable");
        let identity = AgentIdentity {
            instance_id: "agent-instance".to_string(),
            version: "0.1.0".to_string(),
            build_id: "test-build".to_string(),
            process_id: 42,
        };
        let mut monitor = restarted_host
            .reconnect_monitor(&bottle, &endpoint, &identity)
            .expect("reconnect monitor should attach");

        let layout = BottleLayout::resolve(&bottle).expect("layout should resolve");
        let record: RendezvousRecord = serde_json::from_slice(
            &fs::read(&layout.rendezvous).expect("rendezvous should be readable"),
        )
        .expect("rendezvous should decode");
        assert_eq!(
            record.agent_instance_id.as_deref(),
            Some(identity.instance_id.as_str())
        );
        assert_eq!(record.agent_process_id, Some(identity.process_id));

        launcher
            .retire(&bottle, &endpoint, "host restart test complete")
            .expect("owned agent should retire");
        let exit = wait_for_exit(&mut monitor);
        assert_eq!(exit.code, None);
        let _ = wait_for_exit(&mut launch.process);
    }

    #[test]
    fn reconnected_runtime_refuses_unsafe_pid_only_termination() {
        let root = TestDirectory::new("reconnect-retire");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let mut launcher = runtime_fixture(&root.path, 43107);
        let mut launch = launcher.launch(&bottle).expect("agent should launch");
        let mut restarted_host = runtime_fixture(&root.path, 43107);
        let endpoint = restarted_host
            .discover(&bottle)
            .expect("discovery should work")
            .expect("agent should be discoverable");

        let error = restarted_host
            .retire(&bottle, &endpoint, "simulate unresponsive reconnect")
            .expect_err("reconnected host must not force-signal by PID");
        assert!(error.contains("refusing unsafe PID-only termination"));
        assert!(launcher
            .discover(&bottle)
            .expect("owned agent should remain discoverable")
            .is_some());

        launcher
            .retire(&bottle, &launch.endpoint, "test cleanup")
            .expect("owning runtime should safely retire the agent");
        let _ = wait_for_exit(&mut launch.process);
    }

    #[test]
    fn separate_bottles_keep_state_tokens_and_processes_isolated() {
        let root = TestDirectory::new("multiple-bottles");
        let first_bottle = WineAgentRuntime::bottle_id(create_bottle(&root.path, "first")).unwrap();
        let second_bottle =
            WineAgentRuntime::bottle_id(create_bottle(&root.path, "second")).unwrap();
        let mut runtime = runtime_fixture(&root.path, 43104);

        let mut first = runtime
            .launch(&first_bottle)
            .expect("first agent should launch");
        let mut second = runtime
            .launch(&second_bottle)
            .expect("second agent should launch");
        assert_ne!(first.endpoint.token, second.endpoint.token);
        assert_ne!(
            BottleLayout::resolve(&first_bottle).unwrap().rendezvous,
            BottleLayout::resolve(&second_bottle).unwrap().rendezvous
        );

        runtime
            .retire(&first_bottle, &first.endpoint, "first complete")
            .expect("first agent should retire");
        let _ = wait_for_exit(&mut first.process);
        assert!(runtime
            .discover(&second_bottle)
            .expect("second discovery should work")
            .is_some());
        runtime
            .retire(&second_bottle, &second.endpoint, "second complete")
            .expect("second agent should retire");
        let _ = wait_for_exit(&mut second.process);
    }

    #[test]
    fn malformed_and_insecure_rendezvous_state_fails_closed() {
        let root = TestDirectory::new("bad-state");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let mut runtime = runtime_fixture(&root.path, 43105);
        let layout = BottleLayout::resolve(&bottle).expect("layout should resolve");
        ensure_secure_directory(&layout.state_directory).expect("state directory should exist");

        let mut malformed = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(SECURE_FILE_MODE)
            .open(&layout.rendezvous)
            .expect("malformed state should be written");
        malformed.write_all(b"{not-json").unwrap();
        drop(malformed);
        let error = runtime
            .discover(&bottle)
            .expect_err("malformed state must fail closed without being destroyed");
        assert!(error.contains("malformed"));
        assert!(error.contains("preserving"));
        assert!(layout.rendezvous.exists());
        remove_owned_regular_file(&layout.rendezvous)
            .expect("test should remove the preserved malformed fixture");

        let invalid_schema = RendezvousRecord {
            schema_version: RENDEZVOUS_SCHEMA_VERSION + 1,
            bottle_id: bottle.as_str().to_string(),
            address: "127.0.0.1:43105".to_string(),
            token: "a".repeat(64),
            host_process: None,
            deployed_agent: layout.deployed_agent.to_string_lossy().into_owned(),
            agent_instance_id: None,
            agent_process_id: None,
        };
        runtime
            .write_record(&layout, &invalid_schema)
            .expect("invalid-schema fixture should be written");
        assert!(runtime
            .discover(&bottle)
            .expect("semantic corruption should be recovered")
            .is_none());
        assert!(!layout.rendezvous.exists());

        let live_invalid_schema = RendezvousRecord {
            host_process: process_identity(std::process::id())
                .expect("test process identity should be readable"),
            ..invalid_schema
        };
        runtime
            .write_record(&layout, &live_invalid_schema)
            .expect("live invalid-schema fixture should be written");
        let error = runtime
            .discover(&bottle)
            .expect_err("invalid live state must be preserved");
        assert!(error.contains("invalid but still identifies a live agent"));
        assert!(layout.rendezvous.exists());
        remove_owned_regular_file(&layout.rendezvous)
            .expect("test should remove the preserved live fixture");

        let outside = root.path.join("outside-state");
        fs::write(&outside, b"{}").expect("outside state should be written");
        fs::set_permissions(&outside, fs::Permissions::from_mode(SECURE_FILE_MODE)).unwrap();
        symlink(&outside, &layout.rendezvous).expect("rendezvous symlink should be created");
        let error = runtime
            .discover(&bottle)
            .expect_err("rendezvous symlink must be rejected");
        assert!(error.contains("owner-only regular file"));
        assert_eq!(
            fs::read(&outside).expect("outside file should remain unchanged"),
            b"{}"
        );
    }

    #[test]
    fn managed_state_directory_symlink_is_rejected() {
        let root = TestDirectory::new("state-symlink");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let outside = root.path.join("outside");
        fs::create_dir(&outside).expect("outside directory should be created");
        symlink(&outside, bottle_path.join(MANAGED_STATE_DIRECTORY))
            .expect("state symlink should be created");
        let mut runtime = runtime_fixture(&root.path, 43106);

        let error = runtime
            .discover(&bottle)
            .expect_err("state-directory symlink must be rejected");
        assert!(error.contains("real directory"));
    }

    #[test]
    fn interrupted_launch_state_preserves_the_endpoint_and_token() {
        let root = TestDirectory::new("interrupted-launch");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let mut runtime = runtime_fixture(&root.path, 43108);
        let layout = BottleLayout::resolve(&bottle).expect("layout should resolve");
        ensure_secure_directory(&layout.state_directory).expect("state directory should exist");
        ensure_secure_directory(&layout.deployment_directory)
            .expect("deployment directory should exist");

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        let token = AuthToken::from_string("b".repeat(64)).expect("test token should be accepted");
        let server_token = token.clone();
        let server = thread::spawn(move || {
            let rpc = RpcServer::new(server_token, Vec::new(), RpcConfig::default());
            let (stream, _) = listener.accept().expect("test server should accept");
            rpc.serve_connection(stream, |_| Ok(serde_json::Value::Null))
                .expect("test server should authenticate");
        });
        let record = RendezvousRecord {
            schema_version: RENDEZVOUS_SCHEMA_VERSION,
            bottle_id: bottle.as_str().to_string(),
            address: address.to_string(),
            token: token.as_str().to_string(),
            host_process: None,
            deployed_agent: layout.deployed_agent.to_string_lossy().into_owned(),
            agent_instance_id: None,
            agent_process_id: None,
        };
        runtime
            .write_record(&layout, &record)
            .expect("pre-launch rendezvous should persist");

        let endpoint = runtime
            .discover(&bottle)
            .expect("interrupted launch should be discoverable")
            .expect("live endpoint should be recovered");
        assert_eq!(endpoint.address, address);
        assert_eq!(endpoint.token.as_str(), record.token);

        server.join().expect("test server should stop");
        runtime
            .retire(&bottle, &endpoint, "interrupted launch cleanup")
            .expect("untracked endpoint should clean up after becoming unreachable");
        assert!(!layout.rendezvous.exists());
    }

    #[test]
    fn interrupted_launch_rejects_an_unauthenticated_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener should bind");
        let endpoint = AgentEndpoint {
            address: listener
                .local_addr()
                .expect("listener should have an address"),
            token: AuthToken::from_string("c".repeat(64)).expect("test token should be accepted"),
        };

        assert!(
            !authenticated_agent_reachable(&endpoint, Duration::from_millis(20)),
            "generic TCP reachability must not be mistaken for the managed agent"
        );
    }

    #[test]
    fn advisory_launch_lock_ignores_partial_file_contents() {
        let root = TestDirectory::new("launch-lock");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let layout = BottleLayout::resolve(&bottle).expect("layout should resolve");
        ensure_secure_directory(&layout.state_directory).expect("state directory should exist");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(SECURE_FILE_MODE)
            .open(&layout.launch_lock)
            .expect("partial lock fixture should be created");
        file.write_all(b"{partial").unwrap();
        drop(file);

        let guard =
            LaunchGuard::acquire(&layout).expect("advisory lock should ignore file contents");
        assert!(
            launch_lock_is_held(&layout).expect("held lock should be observable"),
            "a concurrent manager in the same process must observe the lock"
        );
        drop(guard);
        assert!(layout.launch_lock.exists());
    }

    #[test]
    fn diagnostic_log_is_capped_and_wine_debug_is_disabled_by_default() {
        let root = TestDirectory::new("diagnostic-cap");
        let bottle_path = create_bottle(&root.path, "wizard101");
        let bottle = WineAgentRuntime::bottle_id(&bottle_path).expect("bottle should be valid");
        let runtime = runtime_fixture(&root.path, 43109);
        assert_eq!(
            runtime.config().environment.get(OsStr::new("WINEDEBUG")),
            Some(&OsString::from("-all"))
        );
        let layout = BottleLayout::resolve(&bottle).expect("layout should resolve");
        ensure_secure_directory(&layout.state_directory).expect("state directory should exist");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(SECURE_FILE_MODE)
            .open(&layout.stderr)
            .expect("diagnostic fixture should be created");
        file.write_all(&vec![b'x'; (MAX_STDERR_ON_DISK_BYTES + 4096) as usize])
            .unwrap();
        file.write_all(b"TAIL").unwrap();
        drop(file);

        cap_diagnostic_file(&layout.stderr).expect("diagnostic file should be capped");
        let capped = fs::read(&layout.stderr).expect("capped log should be readable");
        assert!(capped.len() <= MAX_STDERR_BYTES as usize + b"[TRUNCATED]\n".len());
        assert!(capped.ends_with(b"TAIL"));

        let mut captured_input = vec![b'y'; (MAX_STDERR_ON_DISK_BYTES * 3) as usize];
        captured_input.extend_from_slice(b"CAPTURE-TAIL");
        let output = open_secure_log(&layout.stderr).expect("capture log should open securely");
        start_diagnostic_capture(
            io::Cursor::new(captured_input),
            output,
            layout.stderr.clone(),
        )
        .expect("capture thread should start");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let captured = fs::read(&layout.stderr).expect("capture log should be readable");
            if captured.ends_with(b"CAPTURE-TAIL") {
                assert!(captured.len() <= MAX_STDERR_ON_DISK_BYTES as usize);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "diagnostic capture did not finish before the deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn dropping_the_last_shared_child_handle_transfers_it_to_a_reaper() {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 0.05")
            .spawn()
            .expect("short-lived child should start");
        let pid = child.id() as libc::pid_t;
        let shared = SharedChild::new(child);
        drop(shared);
        thread::sleep(Duration::from_millis(300));

        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert_eq!(
            result, -1,
            "shared child should already have been reaped by its final owner"
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn pid_start_identity_detects_a_reused_process_id() {
        let current = process_identity(std::process::id())
            .expect("current process identity should be readable")
            .expect("current process should exist");
        let forged = HostProcessIdentity {
            pid: current.pid,
            start_id: current.start_id.saturating_add(1),
        };
        assert!(!process_identity_matches(&forged).expect("forged identity should be inspectable"));
        assert!(process_identity_matches(&current).expect("current process should remain alive"));
    }

    #[test]
    fn startup_reader_rejects_non_loopback_and_oversized_output() {
        let non_loopback =
            start_listener_reader(io::Cursor::new(b"DEIMOS_AGENT_LISTEN=192.0.2.1:10\n"));
        let error = non_loopback
            .recv_timeout(Duration::from_secs(1))
            .expect("reader should respond")
            .expect_err("non-loopback listener must be rejected");
        assert!(error.message.contains("non-loopback"));

        let oversized =
            start_listener_reader(io::Cursor::new(vec![b'x'; MAX_STARTUP_STDOUT_BYTES + 1]));
        let error = oversized
            .recv_timeout(Duration::from_secs(1))
            .expect("reader should respond")
            .expect_err("oversized output must be rejected");
        assert!(error.message.contains("bounded limit"));
    }
}
