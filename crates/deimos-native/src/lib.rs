#![allow(clippy::useless_conversion)]

#[cfg(feature = "python")]
use deimos_core::rpc::{AuthToken, NativeContext, RpcClient, RpcConfig};
use deimos_core::{ProbeRequest, PROTOCOL_SCHEMA_VERSION};
#[cfg(feature = "python")]
use pyo3::exceptions::{PyRuntimeError, PyValueError};
#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use serde_json::Value;
#[cfg(feature = "python")]
use std::net::SocketAddr;
#[cfg(feature = "python")]
use std::time::Duration;

#[cfg(feature = "python")]
#[pyfunction]
fn protocol_version() -> u32 {
    PROTOCOL_SCHEMA_VERSION
}

#[cfg(feature = "python")]
#[pyfunction]
fn default_probe_request_json() -> String {
    serde_json::to_string(&ProbeRequest::default()).expect("default probe request should serialize")
}

#[cfg(feature = "python")]
#[allow(clippy::useless_conversion)]
#[pyfunction]
fn new_auth_token() -> PyResult<String> {
    AuthToken::generate()
        .map(|token| token.as_str().to_string())
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))
}

#[cfg(feature = "python")]
#[allow(clippy::useless_conversion)]
#[pyfunction]
#[pyo3(signature = (address, token, operation, payload_json, timeout_ms = 5000, native_context_json = None))]
fn rpc_call_json(
    address: &str,
    token: &str,
    operation: &str,
    payload_json: &str,
    timeout_ms: u64,
    native_context_json: Option<&str>,
) -> PyResult<String> {
    let address: SocketAddr = address
        .parse()
        .map_err(|error| PyValueError::new_err(format!("invalid RPC address: {error}")))?;
    let token =
        AuthToken::from_string(token).map_err(|error| PyValueError::new_err(error.to_string()))?;
    let payload: Value = serde_json::from_str(payload_json)
        .map_err(|error| PyValueError::new_err(format!("invalid RPC payload JSON: {error}")))?;
    let native_context: Option<NativeContext> = native_context_json
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| PyValueError::new_err(format!("invalid native context JSON: {error}")))?;
    let timeout = Duration::from_millis(timeout_ms);
    let mut client = RpcClient::connect(
        address,
        token,
        Vec::new(),
        native_context.clone(),
        RpcConfig {
            io_timeout: timeout,
            ..RpcConfig::default()
        },
    )
    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let response = client
        .call(operation, payload, native_context)
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    serde_json::to_string(&response).map_err(|error| {
        PyRuntimeError::new_err(format!("failed to serialize RPC response: {error}"))
    })
}

#[cfg(feature = "python")]
#[pymodule]
fn deimos_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(protocol_version, module)?)?;
    module.add_function(wrap_pyfunction!(default_probe_request_json, module)?)?;
    module.add_function(wrap_pyfunction!(new_auth_token, module)?)?;
    module.add_function(wrap_pyfunction!(rpc_call_json, module)?)?;
    Ok(())
}
