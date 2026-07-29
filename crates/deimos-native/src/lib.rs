#![allow(clippy::useless_conversion, unexpected_cfgs)]

pub mod lifecycle;
#[cfg(feature = "python")]
mod python_api;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod wine_runtime;

#[cfg(feature = "python")]
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
    python_api::register(module)?;
    Ok(())
}

#[cfg(all(test, feature = "python"))]
mod tests {
    use pyo3::prelude::*;
    use pyo3::types::PyModule;

    #[test]
    fn python_module_registers_the_managed_read_only_api() {
        Python::with_gil(|py| {
            let module =
                PyModule::new_bound(py, "deimos_native").expect("test module should be created");
            super::deimos_native(&module).expect("Python module should register");

            for name in [
                "AgentManager",
                "DeimosNativeError",
                "ConfigurationError",
                "UnsupportedPlatformError",
                "AgentLifecycleError",
                "AgentProtocolError",
                "ProcessError",
                "MemoryError",
                "NativePanicError",
            ] {
                assert!(
                    module
                        .getattr(name)
                        .unwrap_or_else(|_| panic!("{name} should be exported"))
                        .is_callable(),
                    "{name} should be a Python type"
                );
            }

            let manager = module
                .getattr("AgentManager")
                .expect("AgentManager should be exported");
            for forbidden in ["new_auth_token", "rpc_call_json"] {
                assert!(
                    !module
                        .hasattr(forbidden)
                        .expect("module attribute lookup should succeed"),
                    "{forbidden} must not expose authentication material"
                );
            }
            for method in [
                "start",
                "status",
                "stop",
                "capabilities",
                "list_processes",
                "open_process",
                "process_status",
                "close_process",
                "list_modules",
                "memory_regions",
                "read_memory",
                "read_memory_batch",
                "read_typed",
                "scan_memory",
                "resolve_pointer_chain",
            ] {
                assert!(
                    manager
                        .getattr(method)
                        .unwrap_or_else(|_| panic!("AgentManager.{method} should be exported"))
                        .is_callable(),
                    "AgentManager.{method} should be callable"
                );
            }
        });
    }
}
