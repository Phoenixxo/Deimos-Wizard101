use std::mem::size_of;

use deimos_core::process::{
    classify_process, ModuleDescriptor, ProcessDescriptor, ProcessIdentity,
};
use windows::core::PWSTR;
use windows::Win32::Foundation::{
    CloseHandle, E_ACCESSDENIED, E_INVALIDARG, FILETIME, HANDLE, STILL_ACTIVE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
};

use crate::process::{
    enumerate_modules_with_revalidation, OpenedProcess, ProcessBackend, ProcessBackendError,
    ProcessBackendErrorKind,
};

const MAX_EXECUTABLE_PATH: usize = 32_768;

struct OwnedHandle(HANDLE);

// Windows kernel handles belong to the process rather than to the thread that
// opened them. Access to this handle is serialized by the agent's session
// registry, and ownership still has a single Drop implementation.
unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub struct WindowsProcessHandle(OwnedHandle);

impl WindowsProcessHandle {
    pub(crate) fn raw(&self) -> HANDLE {
        self.0 .0
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsProcessBackend;

impl ProcessBackend for WindowsProcessBackend {
    type Handle = WindowsProcessHandle;

    fn list_processes(&self) -> Result<Vec<ProcessDescriptor>, ProcessBackendError> {
        let snapshot = process_snapshot()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        unsafe { Process32FirstW(snapshot.0, &mut entry) }
            .map_err(|error| native_error("Process32FirstW failed", error))?;

        let mut processes = Vec::new();
        loop {
            let pid = entry.th32ProcessID;
            let snapshot_name = wide_string(&entry.szExeFile);
            let inspected = open_query_handle(pid)
                .and_then(|handle| process_identity(handle.0, pid))
                .ok();
            // If inspection succeeded, every descriptive field must come from
            // that same opened process. The snapshot name is only a fallback
            // for processes whose identity cannot be inspected.
            let name = inspected
                .as_ref()
                .map(|identity| executable_name(&identity.executable_path))
                .unwrap_or(snapshot_name);
            processes.push(ProcessDescriptor {
                pid,
                name: name.clone(),
                kind: classify_process(&name),
                executable_path: inspected
                    .as_ref()
                    .map(|identity| identity.executable_path.clone()),
                identity: inspected,
            });

            if unsafe { Process32NextW(snapshot.0, &mut entry) }.is_err() {
                break;
            }
        }
        Ok(processes)
    }

    fn open_process(&self, pid: u32) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                .map(OwnedHandle)
                .map_err(|error| open_error(pid, error))?;
        let identity = process_identity(handle.0, pid)?;
        let name = executable_name(&identity.executable_path);
        let process = ProcessDescriptor {
            pid,
            name: name.clone(),
            kind: classify_process(&name),
            executable_path: Some(identity.executable_path.clone()),
            identity: Some(identity),
        };
        Ok(OpenedProcess {
            handle: WindowsProcessHandle(handle),
            process,
        })
    }

    fn validate_process(
        &self,
        handle: &Self::Handle,
        expected: &ProcessIdentity,
    ) -> Result<(), ProcessBackendError> {
        let mut exit_code = 0u32;
        unsafe { GetExitCodeProcess(handle.raw(), &mut exit_code) }.map_err(|error| {
            native_error(
                format!("GetExitCodeProcess failed for process {}", expected.pid),
                error,
            )
        })?;
        if exit_code != STILL_ACTIVE.0 as u32 {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Exited,
                format!("process {} exited with code {exit_code}", expected.pid),
            ));
        }

        let actual = process_identity(handle.raw(), expected.pid).map_err(|error| {
            if error.kind == ProcessBackendErrorKind::Native {
                ProcessBackendError::new(
                    ProcessBackendErrorKind::Exited,
                    format!(
                        "process {} could not be re-identified: {}",
                        expected.pid, error.message
                    ),
                )
            } else {
                error
            }
        })?;
        if actual.creation_time_100ns != expected.creation_time_100ns
            || !actual
                .executable_path
                .eq_ignore_ascii_case(&expected.executable_path)
        {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::IdentityMismatch,
                format!(
                    "process {} no longer matches the identity captured when the session opened",
                    expected.pid
                ),
            ));
        }
        Ok(())
    }

    fn enumerate_modules(
        &self,
        handle: &Self::Handle,
        expected: &ProcessIdentity,
    ) -> Result<Vec<ModuleDescriptor>, ProcessBackendError> {
        enumerate_modules_with_revalidation(self, handle, expected, || {
            enumerate_modules(expected.pid)
        })
    }
}

fn process_snapshot() -> Result<OwnedHandle, ProcessBackendError> {
    unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map(OwnedHandle)
        .map_err(|error| native_error("CreateToolhelp32Snapshot(processes) failed", error))
}

fn open_query_handle(pid: u32) -> Result<OwnedHandle, ProcessBackendError> {
    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map(OwnedHandle)
        .map_err(|error| open_error(pid, error))
}

fn process_identity(handle: HANDLE, pid: u32) -> Result<ProcessIdentity, ProcessBackendError> {
    let executable_path = executable_path(handle)?;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }.map_err(
        |error| native_error(format!("GetProcessTimes failed for process {pid}"), error),
    )?;
    let creation_time =
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    Ok(ProcessIdentity {
        pid,
        creation_time_100ns: creation_time.to_string(),
        executable_path,
    })
}

fn executable_path(handle: HANDLE) -> Result<String, ProcessBackendError> {
    let mut buffer = vec![0u16; MAX_EXECUTABLE_PATH];
    let mut length = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|error| native_error("QueryFullProcessImageNameW failed", error))?;
    buffer.truncate(length as usize);
    Ok(String::from_utf16_lossy(&buffer))
}

fn enumerate_modules(pid: u32) -> Result<Vec<ModuleDescriptor>, ProcessBackendError> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
            .map(OwnedHandle)
            .map_err(|error| {
                native_error(
                    format!("CreateToolhelp32Snapshot(modules) failed for process {pid}"),
                    error,
                )
            })?;
    let mut entry = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    unsafe { Module32FirstW(snapshot.0, &mut entry) }
        .map_err(|error| native_error(format!("Module32FirstW failed for process {pid}"), error))?;

    let mut modules = Vec::new();
    loop {
        modules.push(ModuleDescriptor {
            name: wide_string(&entry.szModule),
            executable_path: wide_string(&entry.szExePath),
            base_address: format!("{:#x}", entry.modBaseAddr as usize),
            size: entry.modBaseSize,
        });
        if unsafe { Module32NextW(snapshot.0, &mut entry) }.is_err() {
            break;
        }
    }
    Ok(modules)
}

fn executable_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn open_error(pid: u32, error: windows::core::Error) -> ProcessBackendError {
    let kind = if error.code() == E_ACCESSDENIED {
        ProcessBackendErrorKind::AccessDenied
    } else if error.code() == E_INVALIDARG {
        ProcessBackendErrorKind::NotFound
    } else {
        ProcessBackendErrorKind::Native
    };
    ProcessBackendError::new(
        kind,
        format!("OpenProcess failed for process {pid}: {error}"),
    )
    .with_native_code(error.code().0)
}

fn native_error(context: impl AsRef<str>, error: windows::core::Error) -> ProcessBackendError {
    ProcessBackendError::new(
        ProcessBackendErrorKind::Native,
        format!("{}: {error}", context.as_ref()),
    )
    .with_native_code(error.code().0)
}

fn wide_string<const N: usize>(buffer: &[u16; N]) -> String {
    let length = buffer.iter().position(|value| *value == 0).unwrap_or(N);
    String::from_utf16_lossy(&buffer[..length])
}
