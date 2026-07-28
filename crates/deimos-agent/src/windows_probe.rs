use std::ffi::c_void;
use std::mem::size_of;

use deimos_core::{
    parse_pe_headers, DeimosError, ModuleReport, ProbeReport, ProbeRequest, ProcessReport,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

const HEADER_READ_SIZE: usize = 4096;

#[derive(Clone, Debug)]
struct ProcessEntry {
    pid: u32,
    name: String,
}

#[derive(Clone, Debug)]
struct ModuleEntry {
    name: String,
    executable_path: String,
    base: u64,
    size: u32,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub fn run(request: &ProbeRequest) -> ProbeReport {
    let mut report = ProbeReport::new(request);

    let processes = match enumerate_processes() {
        Ok(processes) => processes,
        Err(error) => {
            report.errors.push(error.to_string());
            return report;
        }
    };

    let candidates: Vec<_> = processes
        .into_iter()
        .filter(|process| process.name.eq_ignore_ascii_case(&request.target_process))
        .collect();

    if candidates.is_empty() {
        report.errors.push(format!(
            "{} was not visible in the current Wine bottle",
            request.target_process
        ));
        return report;
    }

    for process in candidates {
        let process_report = probe_process(&process, &request.target_module);
        if process_report.error.is_none() {
            report.success = true;
        }
        report.candidates.push(process_report);
    }

    report
}

fn enumerate_processes() -> Result<Vec<ProcessEntry>, DeimosError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map(OwnedHandle)
        .map_err(|error| {
            DeimosError::process_enumeration(format!(
                "CreateToolhelp32Snapshot(processes) failed: {error}"
            ))
        })?;

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe { Process32FirstW(snapshot.0, &mut entry) }.map_err(|error| {
        DeimosError::process_enumeration(format!("Process32FirstW failed: {error}"))
    })?;

    let mut processes = Vec::new();
    loop {
        processes.push(ProcessEntry {
            pid: entry.th32ProcessID,
            name: wide_string(&entry.szExeFile),
        });

        if unsafe { Process32NextW(snapshot.0, &mut entry) }.is_err() {
            break;
        }
    }

    Ok(processes)
}

fn probe_process(process: &ProcessEntry, target_module: &str) -> ProcessReport {
    let process_handle = match unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            process.pid,
        )
    } {
        Ok(handle) => OwnedHandle(handle),
        Err(error) => {
            return ProcessReport {
                pid: process.pid,
                process_name: process.name.clone(),
                process_opened: false,
                module: None,
                error: Some(
                    DeimosError::process_access(format!("OpenProcess failed: {error}")).to_string(),
                ),
            };
        }
    };

    let module = match find_module(process.pid, target_module) {
        Ok(module) => module,
        Err(error) => return failed_process_report(process, error),
    };

    let (bytes, bytes_read) = match read_memory(process_handle.0, module.base, HEADER_READ_SIZE) {
        Ok(result) => result,
        Err(error) => return failed_process_report(process, error),
    };

    let pe = match parse_pe_headers(&bytes[..bytes_read]) {
        Ok(pe) => pe,
        Err(error) => {
            return failed_process_report(
                process,
                DeimosError::pe_parse(format!("in-memory PE validation failed: {error}")),
            )
        }
    };

    ProcessReport {
        pid: process.pid,
        process_name: process.name.clone(),
        process_opened: true,
        module: Some(ModuleReport {
            module_name: module.name,
            executable_path: module.executable_path,
            module_base: format!("{:#x}", module.base),
            module_size: module.size,
            bytes_read,
            pe,
        }),
        error: None,
    }
}

fn failed_process_report(process: &ProcessEntry, error: DeimosError) -> ProcessReport {
    ProcessReport {
        pid: process.pid,
        process_name: process.name.clone(),
        process_opened: true,
        module: None,
        error: Some(error.to_string()),
    }
}

fn find_module(pid: u32, target_module: &str) -> Result<ModuleEntry, DeimosError> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
            .map(OwnedHandle)
            .map_err(|error| {
                DeimosError::module_enumeration(format!(
                    "CreateToolhelp32Snapshot(modules) failed: {error}"
                ))
            })?;

    let mut entry = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe { Module32FirstW(snapshot.0, &mut entry) }.map_err(|error| {
        DeimosError::module_enumeration(format!("Module32FirstW failed: {error}"))
    })?;

    loop {
        let name = wide_string(&entry.szModule);
        if name.eq_ignore_ascii_case(target_module) {
            return Ok(ModuleEntry {
                name,
                executable_path: wide_string(&entry.szExePath),
                base: entry.modBaseAddr as u64,
                size: entry.modBaseSize,
            });
        }

        if unsafe { Module32NextW(snapshot.0, &mut entry) }.is_err() {
            break;
        }
    }

    Err(DeimosError::module_enumeration(format!(
        "module {target_module} was not visible in process {pid}"
    )))
}

fn read_memory(handle: HANDLE, address: u64, size: usize) -> Result<(Vec<u8>, usize), DeimosError> {
    let mut bytes = vec![0u8; size];
    let mut bytes_read = 0usize;

    unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            bytes.as_mut_ptr().cast::<c_void>(),
            bytes.len(),
            Some(&mut bytes_read),
        )
    }
    .map_err(|error| {
        DeimosError::memory_read(format!("ReadProcessMemory at {address:#x} failed: {error}"))
    })?;

    if bytes_read == 0 {
        return Err(DeimosError::memory_read(format!(
            "ReadProcessMemory at {address:#x} returned zero bytes"
        )));
    }

    Ok((bytes, bytes_read))
}

fn wide_string<const N: usize>(buffer: &[u16; N]) -> String {
    let length = buffer.iter().position(|value| *value == 0).unwrap_or(N);
    String::from_utf16_lossy(&buffer[..length])
}
