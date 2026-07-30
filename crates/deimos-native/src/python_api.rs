use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::Duration;

use deimos_core::client::{ListClientsRequest, OP_CLIENT_LIST};
use deimos_core::memory::{
    ByteOrder, MemoryBatchReadRequest, MemoryPointerChainRequest, MemoryReadItem,
    MemoryReadRequest, MemoryReadResponse, MemoryScanRequest, MemoryScanScope,
    MemorySessionRequest, MemoryValueType, TypedMemoryReadRequest, DEFAULT_SCAN_MAX_MATCHES,
    OP_MEMORY_POINTER_CHAIN, OP_MEMORY_READ, OP_MEMORY_READ_BATCH, OP_MEMORY_READ_TYPED,
    OP_MEMORY_REGIONS, OP_MEMORY_SCAN,
};
use deimos_core::process::{
    ListProcessesRequest, OpenProcessRequest, ProcessIdentity, ProcessSessionId, SessionRequest,
    OP_MODULE_LIST, OP_PROCESS_CLOSE, OP_PROCESS_LIST, OP_PROCESS_OPEN, OP_PROCESS_STATUS,
};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use deimos_core::rpc::RpcConfig;
use deimos_core::rpc::{NativeContext, RpcClientError, RpcErrorCode};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyModule};
use serde::Serialize;
use serde_json::{json, Value};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use crate::lifecycle::{AgentEndpoint, AgentLaunch, AgentLaunchError, AgentProcess, AgentRuntime};
use crate::lifecycle::{AgentManager, BottleId, LifecycleError, LifecycleErrorCode};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::wine_runtime::{WineAgentRuntime, WineRuntimeConfig, WineRuntimeError};

create_exception!(deimos_native, DeimosNativeError, PyException);
create_exception!(deimos_native, ConfigurationError, DeimosNativeError);
create_exception!(deimos_native, UnsupportedPlatformError, DeimosNativeError);
create_exception!(deimos_native, AgentLifecycleError, DeimosNativeError);
create_exception!(deimos_native, AgentProtocolError, DeimosNativeError);
create_exception!(deimos_native, ProcessError, AgentProtocolError);
create_exception!(deimos_native, MemoryError, AgentProtocolError);
create_exception!(deimos_native, NativePanicError, DeimosNativeError);

#[cfg(any(target_os = "macos", target_os = "linux"))]
type ManagedRuntime = AgentManager<WineAgentRuntime>;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
type ManagedRuntime = AgentManager<UnsupportedRuntime>;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
struct UnsupportedRuntime;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl AgentRuntime for UnsupportedRuntime {
    fn discover(&mut self, _bottle: &BottleId) -> Result<Option<AgentEndpoint>, String> {
        Err("Wine agent management is unavailable on this platform".to_string())
    }

    fn launch(&mut self, _bottle: &BottleId) -> Result<AgentLaunch, AgentLaunchError> {
        Err(AgentLaunchError::Failed(
            "Wine agent management is unavailable on this platform".to_string(),
        ))
    }

    fn reconnect_monitor(
        &mut self,
        _bottle: &BottleId,
        _endpoint: &AgentEndpoint,
        _identity: &deimos_core::lifecycle::AgentIdentity,
    ) -> Result<Box<dyn AgentProcess>, String> {
        Err("Wine agent management is unavailable on this platform".to_string())
    }

    fn retire(
        &mut self,
        _bottle: &BottleId,
        _endpoint: &AgentEndpoint,
        _reason: &str,
    ) -> Result<(), String> {
        Err("Wine agent management is unavailable on this platform".to_string())
    }
}

#[derive(Debug)]
enum BindingError {
    Configuration {
        code: &'static str,
        message: String,
        details: Value,
    },
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    UnsupportedPlatform {
        operation: String,
    },
    Lifecycle(LifecycleError),
    Protocol(Box<ProtocolBindingError>),
    Serialization {
        operation: String,
        message: String,
    },
    State {
        operation: String,
        message: String,
    },
    Panic {
        operation: String,
        message: String,
    },
}

#[derive(Debug)]
struct ProtocolBindingError {
    code: String,
    user_message: String,
    technical_message: String,
    operation: String,
    native_context: Option<NativeContext>,
    details: Value,
    request_id: Option<u64>,
}

impl BindingError {
    fn serialization(operation: impl Into<String>, error: impl ToString) -> Self {
        Self::Serialization {
            operation: operation.into(),
            message: error.to_string(),
        }
    }

    fn state(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::State {
            operation: operation.into(),
            message: message.into(),
        }
    }

    fn into_pyerr(self, py: Python<'_>) -> PyErr {
        match self {
            Self::Configuration {
                code,
                message,
                details,
            } => {
                let user_message = configuration_user_message(code, &details);
                decorate_error(
                    py,
                    PyErr::new::<ConfigurationError, _>(user_message),
                    code,
                    "configuration",
                    None,
                    details,
                    None,
                    &message,
                )
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            Self::UnsupportedPlatform { operation } => {
                let technical_message = format!(
                    "{operation} is unavailable on {}",
                    std::env::consts::OS
                );
                decorate_error(
                    py,
                    PyErr::new::<UnsupportedPlatformError, _>(
                        "Managed Wine-agent control is only available from macOS or Linux. \
                         Use the existing Windows backend when running Deimos directly on Windows.",
                    ),
                    "unsupported_platform",
                    &operation,
                    None,
                    json!({"platform": std::env::consts::OS}),
                    None,
                    &technical_message,
                )
            }
            Self::Lifecycle(error) => {
                let serialized = serde_json::to_value(&error).unwrap_or_else(|_| json!({}));
                let code = serialized
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("lifecycle_error")
                    .to_string();
                let user_message = lifecycle_user_message(error.code);
                let technical_message = error.message;
                let python_error = PyErr::new::<AgentLifecycleError, _>(user_message);
                let value = python_error.value_bound(py);
                let _ = value.setattr("bottle_id", error.bottle_id);
                let _ = value.setattr("instance_id", error.instance_id);
                decorate_error(
                    py,
                    python_error,
                    &code,
                    "agent.lifecycle",
                    None,
                    serde_json::to_value(error.details).unwrap_or_else(|_| json!({})),
                    None,
                    &technical_message,
                )
            }
            Self::Protocol(error) => {
                let ProtocolBindingError {
                    code,
                    user_message,
                    technical_message,
                    operation,
                    native_context,
                    details,
                    request_id,
                } = *error;
                let error = if code.starts_with("process_") || code == "session_not_found" {
                    PyErr::new::<ProcessError, _>(user_message)
                } else if code.starts_with("memory_") {
                    PyErr::new::<MemoryError, _>(user_message)
                } else {
                    PyErr::new::<AgentProtocolError, _>(user_message)
                };
                decorate_error(
                    py,
                    error,
                    &code,
                    &operation,
                    native_context.as_ref(),
                    details,
                    request_id,
                    &technical_message,
                )
            }
            Self::Serialization { operation, message } => decorate_error(
                py,
                PyErr::new::<PyValueError, _>(
                    "Deimos could not prepare that request. Check the supplied values and try again.",
                ),
                "invalid_payload",
                &operation,
                None,
                json!({}),
                None,
                &message,
            ),
            Self::State { operation, message } => decorate_error(
                py,
                PyErr::new::<PyRuntimeError, _>(
                    "The native Deimos backend is not in a usable state. Restart Deimos and try again.",
                ),
                "invalid_state",
                &operation,
                None,
                json!({}),
                None,
                &message,
            ),
            Self::Panic { operation, message } => decorate_error(
                py,
                PyErr::new::<NativePanicError, _>(
                    "The native Deimos backend encountered an unexpected error. Restart Deimos; \
                     if it happens again, include the technical message in a bug report.",
                ),
                "native_panic",
                &operation,
                None,
                json!({}),
                None,
                &message,
            ),
        }
    }
}

fn configuration_user_message(code: &str, details: &Value) -> String {
    match code {
        "invalid_value_type" => {
            "That memory value type is not supported. Use u8, i32, u32, u64, f32, or f64."
                .to_string()
        }
        "invalid_byte_order" => {
            "That byte order is not supported. Use \"little\" or \"big\".".to_string()
        }
        "invalid_timeout" => {
            "The agent timeout must be greater than zero milliseconds.".to_string()
        }
        "wine_configuration" => match details.get("kind").and_then(Value::as_str) {
            Some("InvalidConfiguration") => {
                "The Wine runtime settings are incomplete or invalid. Check the Wine executable \
                 and agent file paths, then try again."
                    .to_string()
            }
            Some("InvalidBottle") => {
                "The selected Wizard101 bottle is not valid. Choose an initialized CrossOver or \
                 Wine bottle and try again."
                    .to_string()
            }
            Some("UnsafeFilesystem") => {
                "Deimos cannot safely use the selected bottle directory. Check its ownership and \
                 permissions, then try again."
                    .to_string()
            }
            Some("DeploymentFailed") => {
                "Deimos could not install the helper agent in the selected bottle. Check that the \
                 bottle is writable and has enough free space."
                    .to_string()
            }
            Some("RendezvousFailed") => {
                "Deimos could not create a secure connection point for the Wine agent. Close any \
                 stale Deimos agent, then try again."
                    .to_string()
            }
            Some("ProcessFailed") => {
                "Wine could not start or manage the Deimos agent. Verify the Wine runtime paths \
                 and try again."
                    .to_string()
            }
            _ => "The Wine agent configuration could not be used. Check the selected bottle and \
                 runtime paths, then try again."
                .to_string(),
        },
        _ => {
            "The native Deimos configuration is invalid. Check the supplied settings and try again."
                .to_string()
        }
    }
}

fn lifecycle_user_message(code: LifecycleErrorCode) -> &'static str {
    match code {
        LifecycleErrorCode::InvalidBottleId => {
            "No Wizard101 bottle was selected. Choose a valid CrossOver or Wine bottle and try again."
        }
        LifecycleErrorCode::DiscoveryFailed => {
            "Deimos could not inspect the selected bottle for an existing agent. Verify the bottle path and try again."
        }
        LifecycleErrorCode::LaunchFailed => {
            "Deimos could not start the helper agent inside the selected bottle. Verify the Wine runtime and agent file, then try again."
        }
        LifecycleErrorCode::HandshakeFailed => {
            "The helper agent started but did not become ready. Restart the agent and try again."
        }
        LifecycleErrorCode::HealthCheckFailed => {
            "The helper agent is not connected or ready. Start or restart the agent, then try again."
        }
        LifecycleErrorCode::AgentExited => {
            "The helper agent stopped unexpectedly. Restart it and try again."
        }
        LifecycleErrorCode::MonitoringFailed => {
            "The helper agent started, but Deimos could not monitor it. Restart the agent and try again."
        }
        LifecycleErrorCode::MissingCapability => {
            "The helper agent does not support everything this Deimos build needs. Rebuild and deploy a matching agent."
        }
        LifecycleErrorCode::IdentityMismatch => {
            "The connected helper agent changed unexpectedly. Restart the agent to reconnect safely."
        }
        LifecycleErrorCode::VersionMismatch => {
            "The native Deimos library and helper agent are from different builds. Rebuild and deploy them together."
        }
        LifecycleErrorCode::ShutdownFailed => {
            "The helper agent could not be stopped cleanly. Close it manually or restart the Wine bottle before trying again."
        }
        LifecycleErrorCode::StaleRecoveryFailed => {
            "Deimos found an old helper agent but could not replace it. Close the stale agent or restart the Wine bottle, then try again."
        }
    }
}

fn protocol_user_message(code: &RpcErrorCode) -> &'static str {
    match code {
        RpcErrorCode::AuthenticationFailed => {
            "Deimos could not authenticate with the helper agent. Restart the agent and try again."
        }
        RpcErrorCode::InvalidMessage => {
            "The helper agent returned an unreadable response. Restart it; if the problem continues, rebuild the native library and agent together."
        }
        RpcErrorCode::MessageTooLarge => {
            "The helper agent response was too large to process safely. Narrow the request and try again."
        }
        RpcErrorCode::VersionMismatch => {
            "The native Deimos library and helper agent use incompatible protocols. Rebuild and deploy them together."
        }
        RpcErrorCode::Timeout => {
            "The helper agent did not respond in time. Make sure the Wine bottle is still running, then try again."
        }
        RpcErrorCode::InvalidRequest => {
            "The helper agent could not understand that request. Check the supplied values and try again."
        }
        RpcErrorCode::UnsupportedOperation => {
            "This helper agent does not support that operation. Rebuild and deploy a matching agent."
        }
        RpcErrorCode::ProcessNotFound => {
            "Wizard101 is not running, or the selected process could not be found. Start the game and try again."
        }
        RpcErrorCode::ProcessAccessDenied => {
            "Deimos could not access the selected Wizard101 process. Make sure the game and agent are running in the same Wine bottle."
        }
        RpcErrorCode::ProcessExited => {
            "Wizard101 closed or restarted while Deimos was using it. Reconnect to the game and try again."
        }
        RpcErrorCode::SessionNotFound => {
            "This Wizard101 connection is no longer valid. Reconnect to the game and try again."
        }
        RpcErrorCode::MemoryInvalidAddress => {
            "That memory address is not valid for the connected Wizard101 process. Refresh the game state and try again."
        }
        RpcErrorCode::MemoryReadFailed => {
            "Deimos could not read that part of Wizard101 memory. Refresh the game state and try again."
        }
        RpcErrorCode::MemoryRequiredMatchNotFound => {
            "Deimos could not find the required memory pattern. The game may have updated; refresh signatures before trying again."
        }
        RpcErrorCode::MemoryAmbiguousMatch => {
            "The memory pattern matched more than one location. Use a more specific signature and try again."
        }
        RpcErrorCode::MemoryLimitExceeded => {
            "The memory request exceeded a safety limit. Reduce its size or scope and try again."
        }
        RpcErrorCode::MemoryPatternInvalid => {
            "The memory search pattern is invalid. Check the signature format and try again."
        }
        RpcErrorCode::Internal => {
            "The helper agent encountered an unexpected error. Restart it; if the problem continues, include the technical message in a bug report."
        }
    }
}

fn transport_user_message(error: &RpcClientError) -> &'static str {
    match error {
        RpcClientError::Io(_) => {
            "Deimos lost its connection to the helper agent. Make sure the Wine bottle is running, then restart the agent."
        }
        RpcClientError::Timeout => {
            "The helper agent did not respond in time. Make sure the Wine bottle is still running, then try again."
        }
        RpcClientError::Protocol(_) => {
            "The helper agent could not complete the request. Try again; if it continues, include the technical message in a bug report."
        }
        RpcClientError::InvalidMessage(_) => {
            "The helper agent returned an unreadable response. Restart it; if the problem continues, rebuild the native library and agent together."
        }
        RpcClientError::Token(_) => {
            "Deimos could not prepare secure credentials for the helper agent. Restart Deimos and try again."
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn decorate_error(
    py: Python<'_>,
    error: PyErr,
    code: &str,
    operation: &str,
    native_context: Option<&NativeContext>,
    details: Value,
    request_id: Option<u64>,
    technical_message: &str,
) -> PyErr {
    let value = error.value_bound(py);
    let _ = value.setattr("code", code);
    let _ = value.setattr("operation", operation);
    let _ = value.setattr("request_id", request_id);
    let _ = value.setattr("technical_message", technical_message);
    let context = native_context
        .and_then(|context| serde_json::to_value(context).ok())
        .unwrap_or(Value::Null);
    if let Ok(context) = json_to_python(py, &context) {
        let _ = value.setattr("native_context", context);
    }
    if let Ok(details) = json_to_python(py, &details) {
        let _ = value.setattr("details", details);
    }
    error
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "native operation panicked without a string message".to_string()
    }
}

fn run_without_gil<T, F>(py: Python<'_>, operation: &str, operation_fn: F) -> PyResult<T>
where
    T: Send,
    F: FnOnce() -> Result<T, BindingError> + Send,
{
    let operation_name = operation.to_string();
    let result = py.allow_threads(move || {
        catch_unwind(AssertUnwindSafe(operation_fn)).map_err(|payload| BindingError::Panic {
            operation: operation_name,
            message: panic_message(payload),
        })?
    });
    result.map_err(|error| error.into_pyerr(py))
}

fn serialize_request<T: Serialize>(operation: &str, request: T) -> Result<Value, BindingError> {
    serde_json::to_value(request).map_err(|error| BindingError::serialization(operation, error))
}

fn json_to_python(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(value) => Ok(value.into_py(py)),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(value.into_py(py))
            } else if let Some(value) = value.as_u64() {
                Ok(value.into_py(py))
            } else if let Some(value) = value.as_f64() {
                Ok(value.into_py(py))
            } else {
                Err(PyValueError::new_err("unsupported JSON number"))
            }
        }
        Value::String(value) => Ok(value.into_py(py)),
        Value::Array(values) => {
            let list = PyList::empty_bound(py);
            for value in values {
                list.append(json_to_python(py, value)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(values) => {
            let dictionary = PyDict::new_bound(py);
            for (name, value) in values {
                dictionary.set_item(name, json_to_python(py, value)?)?;
            }
            Ok(dictionary.into_any().unbind())
        }
    }
}

fn parse_identity(value: Option<&str>) -> Result<Option<ProcessIdentity>, BindingError> {
    value
        .map(|value| {
            serde_json::from_str(value)
                .map_err(|error| BindingError::serialization(OP_PROCESS_OPEN, error))
        })
        .transpose()
}

fn parse_value_type(value: &str, operation: &str) -> Result<MemoryValueType, BindingError> {
    match value.to_ascii_lowercase().as_str() {
        "u8" => Ok(MemoryValueType::U8),
        "i32" => Ok(MemoryValueType::I32),
        "u32" => Ok(MemoryValueType::U32),
        "u64" => Ok(MemoryValueType::U64),
        "f32" => Ok(MemoryValueType::F32),
        "f64" => Ok(MemoryValueType::F64),
        _ => Err(BindingError::Configuration {
            code: "invalid_value_type",
            message: format!("unsupported memory value type {value:?}"),
            details: json!({
                "operation": operation,
                "supported": ["u8", "i32", "u32", "u64", "f32", "f64"],
            }),
        }),
    }
}

fn parse_byte_order(value: &str, operation: &str) -> Result<ByteOrder, BindingError> {
    match value.to_ascii_lowercase().as_str() {
        "little" | "little_endian" => Ok(ByteOrder::LittleEndian),
        "big" | "big_endian" => Ok(ByteOrder::BigEndian),
        _ => Err(BindingError::Configuration {
            code: "invalid_byte_order",
            message: format!("unsupported byte order {value:?}"),
            details: json!({
                "operation": operation,
                "supported": ["little", "big"],
            }),
        }),
    }
}

fn scan_scope(module_name: Option<String>) -> MemoryScanScope {
    match module_name {
        Some(name) => MemoryScanScope::Module { name },
        None => MemoryScanScope::Process,
    }
}

#[pyclass(name = "AgentManager")]
pub struct PyAgentManager {
    manager: Mutex<ManagedRuntime>,
    bottle: BottleId,
}

#[pymethods]
impl PyAgentManager {
    #[new]
    #[pyo3(signature = (
        bottle_path,
        wine_executable,
        agent_artifact,
        *,
        wineserver_executable = None,
        wine_arguments = None,
        environment = None,
        wrapper_manages_wine_loader = false,
        component = "deimos-python",
        component_version = env!("CARGO_PKG_VERSION"),
        launch_id = None,
        io_timeout_ms = 5000
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        bottle_path: String,
        wine_executable: String,
        agent_artifact: String,
        wineserver_executable: Option<String>,
        wine_arguments: Option<Vec<String>>,
        environment: Option<HashMap<String, String>>,
        wrapper_manages_wine_loader: bool,
        component: &str,
        component_version: &str,
        launch_id: Option<String>,
        io_timeout_ms: u64,
    ) -> PyResult<Self> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            if io_timeout_ms == 0 {
                return Err(BindingError::Configuration {
                    code: "invalid_timeout",
                    message: "io_timeout_ms must be greater than zero".to_string(),
                    details: json!({"io_timeout_ms": io_timeout_ms}),
                }
                .into_pyerr(py));
            }
            let mut config = WineRuntimeConfig::new(wine_executable, agent_artifact);
            if let Some(wineserver) = wineserver_executable {
                config = config.with_wineserver(wineserver);
            }
            if wrapper_manages_wine_loader {
                config = config.without_wine_loader_override();
            }
            for (name, value) in environment.unwrap_or_default() {
                config = config.with_environment(name, value);
            }
            for argument in wine_arguments.unwrap_or_default() {
                config = config.with_wine_argument(argument);
            }
            let runtime = WineAgentRuntime::new(config)
                .map_err(|error| wine_configuration_error(py, error))?;
            let bottle = WineAgentRuntime::bottle_id(bottle_path)
                .map_err(|error| wine_configuration_error(py, error))?;
            let native_context = NativeContext {
                component: component.to_string(),
                version: component_version.to_string(),
                native_pid: Some(std::process::id()),
                launch_id,
            };
            let manager = AgentManager::new(runtime, native_context).with_rpc_config(RpcConfig {
                io_timeout: Duration::from_millis(io_timeout_ms),
                ..RpcConfig::default()
            });
            Ok(Self {
                manager: Mutex::new(manager),
                bottle,
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (
                bottle_path,
                wine_executable,
                agent_artifact,
                wineserver_executable,
                wine_arguments,
                environment,
                wrapper_manages_wine_loader,
                component,
                component_version,
                launch_id,
                io_timeout_ms,
            );
            Err(BindingError::UnsupportedPlatform {
                operation: "agent configuration".to_string(),
            }
            .into_pyerr(py))
        }
    }

    fn start(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let ready = self.with_manager(py, "agent.start", |manager, bottle| {
            manager
                .ensure_agent(bottle.clone())
                .map_err(BindingError::Lifecycle)
        })?;
        let ready = serde_json::to_value(ready)
            .map_err(|error| BindingError::serialization("agent.start", error).into_pyerr(py))?;
        json_to_python(py, &ready)
    }

    fn status(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let health = self.with_manager(py, "agent.status", |manager, bottle| {
            manager.health(bottle).map_err(BindingError::Lifecycle)
        })?;
        let health = serde_json::to_value(health)
            .map_err(|error| BindingError::serialization("agent.status", error).into_pyerr(py))?;
        json_to_python(py, &health)
    }

    #[pyo3(signature = (reason = "requested by Python host"))]
    fn stop(&self, py: Python<'_>, reason: &str) -> PyResult<()> {
        let reason = reason.to_string();
        self.with_manager(py, "agent.stop", move |manager, bottle| {
            manager
                .shutdown(bottle, reason)
                .map_err(BindingError::Lifecycle)
        })
    }

    fn capabilities(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        self.with_manager(py, "agent.capabilities", |manager, bottle| {
            manager
                .capabilities(bottle)
                .map_err(BindingError::Lifecycle)
        })
    }

    fn list_clients(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let request = serialize_request(OP_CLIENT_LIST, ListClientsRequest::default())
            .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, OP_CLIENT_LIST, request)
    }

    #[pyo3(signature = (names = None))]
    fn list_processes(&self, py: Python<'_>, names: Option<Vec<String>>) -> PyResult<Py<PyAny>> {
        let request = serialize_request(
            OP_PROCESS_LIST,
            ListProcessesRequest {
                names: names.unwrap_or_default(),
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, OP_PROCESS_LIST, request)
    }

    #[pyo3(signature = (pid, expected_identity_json = None))]
    fn open_process(
        &self,
        py: Python<'_>,
        pid: u32,
        expected_identity_json: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let expected_identity =
            parse_identity(expected_identity_json).map_err(|error| error.into_pyerr(py))?;
        let request = serialize_request(
            OP_PROCESS_OPEN,
            OpenProcessRequest {
                pid,
                expected_identity,
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, OP_PROCESS_OPEN, request)
    }

    fn process_status(&self, py: Python<'_>, session_id: String) -> PyResult<Py<PyAny>> {
        self.session_call_as_python(py, OP_PROCESS_STATUS, session_id)
    }

    fn close_process(&self, py: Python<'_>, session_id: String) -> PyResult<Py<PyAny>> {
        self.session_call_as_python(py, OP_PROCESS_CLOSE, session_id)
    }

    fn list_modules(&self, py: Python<'_>, session_id: String) -> PyResult<Py<PyAny>> {
        self.session_call_as_python(py, OP_MODULE_LIST, session_id)
    }

    fn memory_regions(&self, py: Python<'_>, session_id: String) -> PyResult<Py<PyAny>> {
        let request = serialize_request(
            OP_MEMORY_REGIONS,
            MemorySessionRequest {
                session_id: ProcessSessionId(session_id),
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, OP_MEMORY_REGIONS, request)
    }

    fn read_memory(
        &self,
        py: Python<'_>,
        session_id: String,
        address: String,
        size: usize,
    ) -> PyResult<Py<PyBytes>> {
        let request = serialize_request(
            OP_MEMORY_READ,
            MemoryReadRequest {
                session_id: ProcessSessionId(session_id),
                address,
                size,
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        let response = self.call_value(py, OP_MEMORY_READ, request)?;
        let response: MemoryReadResponse = serde_json::from_value(response)
            .map_err(|error| BindingError::serialization(OP_MEMORY_READ, error).into_pyerr(py))?;
        Ok(PyBytes::new_bound(py, &response.bytes).unbind())
    }

    fn read_memory_batch(
        &self,
        py: Python<'_>,
        session_id: String,
        reads: Vec<(String, usize)>,
    ) -> PyResult<Py<PyAny>> {
        let request = serialize_request(
            OP_MEMORY_READ_BATCH,
            MemoryBatchReadRequest {
                session_id: ProcessSessionId(session_id),
                reads: reads
                    .into_iter()
                    .map(|(address, size)| MemoryReadItem { address, size })
                    .collect(),
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, OP_MEMORY_READ_BATCH, request)
    }

    #[pyo3(signature = (session_id, address, value_type, byte_order = "little"))]
    fn read_typed(
        &self,
        py: Python<'_>,
        session_id: String,
        address: String,
        value_type: &str,
        byte_order: &str,
    ) -> PyResult<Py<PyAny>> {
        let request = serialize_request(
            OP_MEMORY_READ_TYPED,
            TypedMemoryReadRequest {
                session_id: ProcessSessionId(session_id),
                address,
                value_type: parse_value_type(value_type, OP_MEMORY_READ_TYPED)
                    .map_err(|error| error.into_pyerr(py))?,
                byte_order: parse_byte_order(byte_order, OP_MEMORY_READ_TYPED)
                    .map_err(|error| error.into_pyerr(py))?,
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, OP_MEMORY_READ_TYPED, request)
    }

    #[pyo3(signature = (
        session_id,
        signature,
        *,
        module_name = None,
        required = false,
        unique = false,
        max_matches = DEFAULT_SCAN_MAX_MATCHES
    ))]
    #[allow(clippy::too_many_arguments)]
    fn scan_memory(
        &self,
        py: Python<'_>,
        session_id: String,
        signature: String,
        module_name: Option<String>,
        required: bool,
        unique: bool,
        max_matches: usize,
    ) -> PyResult<Py<PyAny>> {
        let request = serialize_request(
            OP_MEMORY_SCAN,
            MemoryScanRequest {
                session_id: ProcessSessionId(session_id),
                signature,
                required,
                unique,
                max_matches,
                scope: scan_scope(module_name),
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, OP_MEMORY_SCAN, request)
    }

    #[pyo3(signature = (
        session_id,
        signature,
        offsets,
        dereference_count,
        *,
        pointer_width = 8,
        value_type = "u64",
        byte_order = "little",
        module_name = None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn resolve_pointer_chain(
        &self,
        py: Python<'_>,
        session_id: String,
        signature: String,
        offsets: Vec<u64>,
        dereference_count: usize,
        pointer_width: u8,
        value_type: &str,
        byte_order: &str,
        module_name: Option<String>,
    ) -> PyResult<Py<PyAny>> {
        let request = serialize_request(
            OP_MEMORY_POINTER_CHAIN,
            MemoryPointerChainRequest {
                session_id: ProcessSessionId(session_id),
                signature,
                offsets,
                dereference_count,
                pointer_width,
                byte_order: parse_byte_order(byte_order, OP_MEMORY_POINTER_CHAIN)
                    .map_err(|error| error.into_pyerr(py))?,
                value_type: parse_value_type(value_type, OP_MEMORY_POINTER_CHAIN)
                    .map_err(|error| error.into_pyerr(py))?,
                scope: scan_scope(module_name),
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, OP_MEMORY_POINTER_CHAIN, request)
    }
}

impl PyAgentManager {
    fn with_manager<T, F>(&self, py: Python<'_>, operation: &str, operation_fn: F) -> PyResult<T>
    where
        T: Send,
        F: FnOnce(&mut ManagedRuntime, &BottleId) -> Result<T, BindingError> + Send,
    {
        let bottle = self.bottle.clone();
        run_without_gil(py, operation, || {
            let mut manager = self
                .manager
                .lock()
                .map_err(|_| BindingError::state(operation, "agent manager lock was poisoned"))?;
            operation_fn(&mut manager, &bottle)
        })
    }

    fn session_call_as_python(
        &self,
        py: Python<'_>,
        operation: &str,
        session_id: String,
    ) -> PyResult<Py<PyAny>> {
        let request = serialize_request(
            operation,
            SessionRequest {
                session_id: ProcessSessionId(session_id),
            },
        )
        .map_err(|error| error.into_pyerr(py))?;
        self.call_as_python(py, operation, request)
    }

    fn call_as_python(
        &self,
        py: Python<'_>,
        operation: &str,
        request: Value,
    ) -> PyResult<Py<PyAny>> {
        let response = self.call_value(py, operation, request)?;
        json_to_python(py, &response)
    }

    fn call_value(&self, py: Python<'_>, operation: &str, request: Value) -> PyResult<Value> {
        let owned_operation = operation.to_string();
        self.with_manager(py, operation, move |manager, bottle| {
            manager
                .call(bottle, &owned_operation, request)
                .map_err(agent_call_error)
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn wine_configuration_error(py: Python<'_>, error: WineRuntimeError) -> PyErr {
    BindingError::Configuration {
        code: "wine_configuration",
        message: error.to_string(),
        details: json!({
            "kind": format!("{:?}", error.kind),
            "path": error.path.map(|path| path.to_string_lossy().into_owned()),
        }),
    }
    .into_pyerr(py)
}

fn agent_call_error(error: crate::lifecycle::AgentCallError) -> BindingError {
    match error {
        crate::lifecycle::AgentCallError::Lifecycle(error) => BindingError::Lifecycle(error),
        crate::lifecycle::AgentCallError::Rpc {
            operation,
            native_context,
            source,
        } => match *source {
            deimos_core::rpc::RpcClientError::Protocol(error) => {
                let serialized =
                    serde_json::to_value(&*error).unwrap_or_else(|_| json!({"details": {}}));
                let code = serialized
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("protocol_error")
                    .to_string();
                BindingError::Protocol(Box::new(ProtocolBindingError {
                    user_message: protocol_user_message(&error.code).to_string(),
                    code,
                    technical_message: error.message,
                    operation: error.operation,
                    native_context: error.native_context.or(Some(native_context)),
                    details: serde_json::to_value(error.details).unwrap_or_else(|_| json!({})),
                    request_id: Some(error.request_id),
                }))
            }
            error => {
                let user_message = transport_user_message(&error).to_string();
                let technical_message = error.to_string();
                BindingError::Protocol(Box::new(ProtocolBindingError {
                    code: "transport_error".to_string(),
                    user_message,
                    technical_message,
                    operation,
                    native_context: Some(native_context),
                    details: json!({}),
                    request_id: None,
                }))
            }
        },
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyAgentManager>()?;
    module.add(
        "DeimosNativeError",
        module.py().get_type_bound::<DeimosNativeError>(),
    )?;
    module.add(
        "ConfigurationError",
        module.py().get_type_bound::<ConfigurationError>(),
    )?;
    module.add(
        "UnsupportedPlatformError",
        module.py().get_type_bound::<UnsupportedPlatformError>(),
    )?;
    module.add(
        "AgentLifecycleError",
        module.py().get_type_bound::<AgentLifecycleError>(),
    )?;
    module.add(
        "AgentProtocolError",
        module.py().get_type_bound::<AgentProtocolError>(),
    )?;
    module.add("ProcessError", module.py().get_type_bound::<ProcessError>())?;
    module.add("MemoryError", module.py().get_type_bound::<MemoryError>())?;
    module.add(
        "NativePanicError",
        module.py().get_type_bound::<NativePanicError>(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        agent_call_error, lifecycle_user_message, panic_message, parse_byte_order,
        parse_value_type, protocol_user_message, run_without_gil, AgentLifecycleError,
        AgentProtocolError, BindingError, ConfigurationError, MemoryError, NativePanicError,
    };
    use crate::lifecycle::{AgentCallError, LifecycleError, LifecycleErrorCode};
    use deimos_core::memory::{ByteOrder, MemoryValueType};
    use deimos_core::rpc::{NativeContext, RpcClientError, RpcError, RpcErrorCode};
    use pyo3::prelude::*;
    use pyo3::types::PyDict;
    use std::collections::BTreeMap;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::time::Duration;

    #[test]
    fn parsing_accepts_stable_python_names() {
        assert_eq!(
            parse_value_type("u64", "test").expect("u64 should parse"),
            MemoryValueType::U64
        );
        assert_eq!(
            parse_byte_order("little", "test").expect("little should parse"),
            ByteOrder::LittleEndian
        );
    }

    #[test]
    fn parsing_rejects_unknown_names_as_configuration_errors() {
        assert!(matches!(
            parse_value_type("usize", "test"),
            Err(BindingError::Configuration {
                code: "invalid_value_type",
                ..
            })
        ));
        assert!(matches!(
            parse_byte_order("native", "test"),
            Err(BindingError::Configuration {
                code: "invalid_byte_order",
                ..
            })
        ));
    }

    #[test]
    fn configuration_errors_are_actionable_and_keep_technical_diagnostics() {
        Python::with_gil(|py| {
            let error = parse_value_type("usize", "test")
                .expect_err("unsupported value type should fail")
                .into_pyerr(py);

            assert!(error.is_instance_of::<ConfigurationError>(py));
            let value = error.value_bound(py);
            assert_eq!(
                value
                    .str()
                    .expect("configuration error should be printable")
                    .to_str()
                    .expect("configuration error should be text"),
                "That memory value type is not supported. Use u8, i32, u32, u64, f32, or f64."
            );
            assert_eq!(
                value
                    .getattr("technical_message")
                    .expect("technical message should exist")
                    .extract::<String>()
                    .expect("technical message should be text"),
                "unsupported memory value type \"usize\""
            );
        });
    }

    #[test]
    fn every_lifecycle_error_code_has_a_human_message() {
        let codes = [
            LifecycleErrorCode::InvalidBottleId,
            LifecycleErrorCode::DiscoveryFailed,
            LifecycleErrorCode::LaunchFailed,
            LifecycleErrorCode::HandshakeFailed,
            LifecycleErrorCode::HealthCheckFailed,
            LifecycleErrorCode::AgentExited,
            LifecycleErrorCode::MonitoringFailed,
            LifecycleErrorCode::MissingCapability,
            LifecycleErrorCode::IdentityMismatch,
            LifecycleErrorCode::VersionMismatch,
            LifecycleErrorCode::ShutdownFailed,
            LifecycleErrorCode::StaleRecoveryFailed,
        ];

        for code in codes {
            let message = lifecycle_user_message(code);
            assert!(message.starts_with(char::is_uppercase), "{message}");
            assert!(message.ends_with('.'), "{message}");
            assert!(!message.contains('_'), "{message}");
        }
    }

    #[test]
    fn lifecycle_errors_are_actionable_and_keep_native_context() {
        Python::with_gil(|py| {
            let error = BindingError::Lifecycle(LifecycleError {
                code: LifecycleErrorCode::AgentExited,
                message: "agent exited unexpectedly (exit code 53)".to_string(),
                bottle_id: "/tmp/wizard101".to_string(),
                instance_id: Some("agent-1".to_string()),
                details: BTreeMap::from([("exit_code".to_string(), "53".to_string())]),
            })
            .into_pyerr(py);

            assert!(error.is_instance_of::<AgentLifecycleError>(py));
            let value = error.value_bound(py);
            assert_eq!(
                value
                    .str()
                    .expect("lifecycle error should be printable")
                    .to_str()
                    .expect("lifecycle error should be text"),
                "The helper agent stopped unexpectedly. Restart it and try again."
            );
            assert_eq!(
                value
                    .getattr("technical_message")
                    .expect("technical message should exist")
                    .extract::<String>()
                    .expect("technical message should be text"),
                "agent exited unexpectedly (exit code 53)"
            );
            assert_eq!(
                value
                    .getattr("bottle_id")
                    .expect("bottle ID should exist")
                    .extract::<String>()
                    .expect("bottle ID should be text"),
                "/tmp/wizard101"
            );
            let details = value.getattr("details").expect("details should exist");
            assert_eq!(
                details
                    .get_item("exit_code")
                    .expect("exit code should exist")
                    .extract::<String>()
                    .expect("exit code should be text"),
                "53"
            );
        });
    }

    #[test]
    fn every_protocol_error_code_has_a_human_message() {
        let codes = [
            RpcErrorCode::AuthenticationFailed,
            RpcErrorCode::InvalidMessage,
            RpcErrorCode::MessageTooLarge,
            RpcErrorCode::VersionMismatch,
            RpcErrorCode::Timeout,
            RpcErrorCode::InvalidRequest,
            RpcErrorCode::UnsupportedOperation,
            RpcErrorCode::ProcessNotFound,
            RpcErrorCode::ProcessAccessDenied,
            RpcErrorCode::ProcessExited,
            RpcErrorCode::SessionNotFound,
            RpcErrorCode::MemoryInvalidAddress,
            RpcErrorCode::MemoryReadFailed,
            RpcErrorCode::MemoryRequiredMatchNotFound,
            RpcErrorCode::MemoryAmbiguousMatch,
            RpcErrorCode::MemoryLimitExceeded,
            RpcErrorCode::MemoryPatternInvalid,
            RpcErrorCode::Internal,
        ];

        for code in codes {
            let message = protocol_user_message(&code);
            assert!(message.starts_with(char::is_uppercase), "{message}");
            assert!(message.ends_with('.'), "{message}");
            assert!(!message.contains('_'), "{message}");
        }
    }

    #[test]
    fn panic_payloads_are_contained_as_messages() {
        let panic = catch_unwind(AssertUnwindSafe(|| panic!("contained")))
            .expect_err("test panic should be caught");
        assert_eq!(panic_message(panic), "contained");
    }

    #[test]
    fn native_panics_become_structured_python_exceptions() {
        Python::with_gil(|py| {
            let error = run_without_gil::<(), _>(py, "test.panic", || {
                panic!("contained at Python boundary")
            })
            .expect_err("native panic should become a Python error");

            assert!(error.is_instance_of::<NativePanicError>(py));
            let value = error.value_bound(py);
            assert_eq!(
                value
                    .getattr("code")
                    .expect("panic code should exist")
                    .extract::<String>()
                    .expect("panic code should be text"),
                "native_panic"
            );
            assert_eq!(
                value
                    .getattr("operation")
                    .expect("panic operation should exist")
                    .extract::<String>()
                    .expect("panic operation should be text"),
                "test.panic"
            );
            assert_eq!(
                value
                    .str()
                    .expect("panic error should be printable")
                    .to_str()
                    .expect("panic error should be text"),
                "The native Deimos backend encountered an unexpected error. Restart Deimos; if it \
                 happens again, include the technical message in a bug report."
            );
            assert_eq!(
                value
                    .getattr("technical_message")
                    .expect("technical message should exist")
                    .extract::<String>()
                    .expect("technical message should be text"),
                "contained at Python boundary"
            );
        });
    }

    #[test]
    fn blocking_native_work_releases_the_python_gil() {
        Python::with_gil(|py| {
            let locals = PyDict::new_bound(py);
            py.run_bound(
                concat!(
                    "import threading, time\n",
                    "marker = []\n",
                    "worker = threading.Thread(",
                    "target=lambda: (time.sleep(0.05), marker.append('ran')))\n",
                    "worker.start()"
                ),
                Some(&locals),
                Some(&locals),
            )
            .expect("Python worker should start");

            run_without_gil(py, "test.gil", || {
                std::thread::sleep(Duration::from_millis(200));
                Ok(())
            })
            .expect("native operation should complete");

            let marker: Vec<String> = locals
                .get_item("marker")
                .expect("marker lookup should succeed")
                .expect("marker should exist")
                .extract()
                .expect("marker should be a string list");
            assert_eq!(marker, vec!["ran"]);
        });
    }

    #[test]
    fn structured_protocol_errors_keep_python_context_and_details() {
        Python::with_gil(|py| {
            let native_context = NativeContext {
                component: "python-test".to_string(),
                version: "1".to_string(),
                native_pid: Some(42),
                launch_id: Some("launch-test".to_string()),
            };
            let mut rpc_error = RpcError::new(
                RpcErrorCode::MemoryReadFailed,
                "read failed",
                17,
                "memory.read",
                Some(native_context.clone()),
            );
            rpc_error
                .details
                .insert("address".to_string(), "0x1234".to_string());
            let error = agent_call_error(AgentCallError::Rpc {
                operation: "memory.read".to_string(),
                native_context,
                source: Box::new(RpcClientError::Protocol(Box::new(rpc_error))),
            })
            .into_pyerr(py);

            assert!(error.is_instance_of::<MemoryError>(py));
            let value = error.value_bound(py);
            assert_eq!(
                value
                    .getattr("code")
                    .expect("code should exist")
                    .extract::<String>()
                    .expect("code should be text"),
                "memory_read_failed"
            );
            assert_eq!(
                value
                    .getattr("operation")
                    .expect("operation should exist")
                    .extract::<String>()
                    .expect("operation should be text"),
                "memory.read"
            );
            assert_eq!(
                value
                    .getattr("request_id")
                    .expect("request ID should exist")
                    .extract::<u64>()
                    .expect("request ID should be an integer"),
                17
            );
            let context = value
                .getattr("native_context")
                .expect("native context should exist");
            assert_eq!(
                context
                    .get_item("launch_id")
                    .expect("launch ID should exist")
                    .extract::<String>()
                    .expect("launch ID should be text"),
                "launch-test"
            );
            let details = value.getattr("details").expect("details should exist");
            assert_eq!(
                details
                    .get_item("address")
                    .expect("address detail should exist")
                    .extract::<String>()
                    .expect("address should be text"),
                "0x1234"
            );
            assert_eq!(
                value
                    .str()
                    .expect("memory error should be printable")
                    .to_str()
                    .expect("memory error should be text"),
                "Deimos could not read that part of Wizard101 memory. Refresh the game state and try again."
            );
            assert_eq!(
                value
                    .getattr("technical_message")
                    .expect("technical message should exist")
                    .extract::<String>()
                    .expect("technical message should be text"),
                "read failed"
            );
        });
    }

    #[test]
    fn transport_errors_keep_requested_operation_and_native_context() {
        Python::with_gil(|py| {
            let native_context = NativeContext {
                component: "python-test".to_string(),
                version: "1".to_string(),
                native_pid: Some(42),
                launch_id: Some("transport-launch".to_string()),
            };
            let error = agent_call_error(AgentCallError::Rpc {
                operation: "memory.scan".to_string(),
                native_context,
                source: Box::new(RpcClientError::Timeout),
            })
            .into_pyerr(py);

            assert!(error.is_instance_of::<AgentProtocolError>(py));
            let value = error.value_bound(py);
            assert_eq!(
                value
                    .getattr("operation")
                    .expect("operation should exist")
                    .extract::<String>()
                    .expect("operation should be text"),
                "memory.scan"
            );
            let context = value
                .getattr("native_context")
                .expect("native context should exist");
            assert_eq!(
                context
                    .get_item("launch_id")
                    .expect("launch ID should exist")
                    .extract::<String>()
                    .expect("launch ID should be text"),
                "transport-launch"
            );
            assert_eq!(
                value
                    .str()
                    .expect("transport error should be printable")
                    .to_str()
                    .expect("transport error should be text"),
                "The helper agent did not respond in time. Make sure the Wine bottle is still running, then try again."
            );
            assert_eq!(
                value
                    .getattr("technical_message")
                    .expect("technical message should exist")
                    .extract::<String>()
                    .expect("technical message should be text"),
                "RPC request timed out"
            );
        });
    }
}
