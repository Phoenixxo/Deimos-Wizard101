#![allow(clippy::useless_conversion, unexpected_cfgs)]

mod account;
mod host_hotkey;
mod host_window;
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
    fn python_module_registers_the_managed_agent_api() {
        Python::with_gil(|py| {
            let module =
                PyModule::new_bound(py, "deimos_native").expect("test module should be created");
            super::deimos_native(&module).expect("Python module should register");

            for name in [
                "AgentManager",
                "HostHotkeyManager",
                "HostWindowManager",
                "DeimosNativeError",
                "ConfigurationError",
                "UnsupportedPlatformError",
                "AgentLifecycleError",
                "AgentProtocolError",
                "ProcessError",
                "MemoryError",
                "WindowError",
                "InputError",
                "GameProcessError",
                "AccountError",
                "HostHotkeyError",
                "HostWindowError",
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
            let hotkeys = module
                .getattr("HostHotkeyManager")
                .expect("HostHotkeyManager should be exported");
            for method in [
                "register_hotkey",
                "unregister_hotkey",
                "poll_events",
                "clear",
            ] {
                assert!(
                    hotkeys
                        .getattr(method)
                        .unwrap_or_else(|_| panic!("HostHotkeyManager.{method} should be exported"))
                        .is_callable(),
                    "HostHotkeyManager.{method} should be callable"
                );
            }
            let host_windows = module
                .getattr("HostWindowManager")
                .expect("HostWindowManager should be exported");
            for method in ["client_geometry", "make_click_through", "stack_above"] {
                assert!(
                    host_windows
                        .getattr(method)
                        .unwrap_or_else(|_| panic!("HostWindowManager.{method} should be exported"))
                        .is_callable(),
                    "HostWindowManager.{method} should be callable"
                );
            }
            for forbidden in ["new_auth_token", "rpc_call_json"] {
                assert!(
                    !module
                        .hasattr(forbidden)
                        .expect("module attribute lookup should succeed"),
                    "{forbidden} must not expose authentication material"
                );
            }
            for function in [
                "prompt_save_account",
                "delete_account",
                "list_accounts",
                "reorder_accounts",
                "has_account",
                "update_player_gid",
                "get_player_gid",
                "get_nickname_by_gid",
            ] {
                assert!(
                    module
                        .getattr(function)
                        .unwrap_or_else(|_| panic!("{function} should be exported"))
                        .is_callable(),
                    "{function} should be callable"
                );
            }
            assert!(
                !module
                    .hasattr("read_credential")
                    .expect("module attribute lookup should succeed"),
                "Python must not expose stored credential values"
            );
            for method in [
                "start",
                "status",
                "stop",
                "capabilities",
                "list_clients",
                "launch_game",
                "terminate_game",
                "prompt_save_account",
                "delete_account",
                "list_accounts",
                "reorder_accounts",
                "has_account",
                "update_player_gid",
                "get_player_gid",
                "get_nickname_by_gid",
                "login_account",
                "client_window_state",
                "focus_client_window",
                "set_client_window_title",
                "client_to_screen",
                "key_down",
                "key_up",
                "send_key",
                "send_hotkey",
                "move_mouse",
                "click_mouse",
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
