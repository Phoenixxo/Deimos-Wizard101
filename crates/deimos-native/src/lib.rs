use deimos_core::{ProbeRequest, PROTOCOL_SCHEMA_VERSION};
#[cfg(feature = "python")]
use pyo3::prelude::*;

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
#[pymodule]
fn deimos_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(protocol_version, module)?)?;
    module.add_function(wrap_pyfunction!(default_probe_request_json, module)?)?;
    Ok(())
}
