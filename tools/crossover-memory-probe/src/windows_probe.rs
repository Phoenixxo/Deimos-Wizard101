use std::ffi::c_void;
use std::mem::size_of;

use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::pe::{parse_pe_headers, PeHeaderSummary};

const HEADER_READ_SIZE: usize = 4096;

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub schema_version: u32,
    pub target_process: String,
    pub access_mode: &'static str,
    pub success: bool,
    pub candidates: Vec<ProcessReport>,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProcessReport {
    pub pid: u32,
    pub process_name: String,
    pub process_opened: bool,
    pub module: Option<ModuleReport>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ModuleReport {
    pub module_name: String,
    pub executable_path: String,
    pub module_base: String,
    pub module_size: u32,
    pub bytes_read: usize,
    pub pe: PeHeaderSummary,
}

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

pub fn run(target_process: &str) -> ProbeReport {
    let mut report = ProbeReport {
        schema_version: 1,
        target_process: target_process.to_string(),
        access_mode: "PROCESS_QUERY_INFORMATION | PROCESS_VM_READ",
        success: false,
        candidates: Vec::new(),
        errors: Vec::new(),
    };

    let processes = match enumerate_processes() {
        Ok(processes) => processes,
        Err(error) => {
            report.errors.push(error);
            return report;
        }
    };

    let candidates: Vec<_> = processes
        .into_iter()
        .filter(|process| process.name.eq_ignore_ascii_case(target_process))
        .collect();

    if candidates.is_empty() {
        report.errors.push(format!(
            "{target_process} was not visible in the current Wine bottle"
        ));
        return report;
    }

    for process in candidates {
        let process_report = probe_process(&process, target_process);
        if process_report.error.is_none() {
            report.success = true;
        }
        report.candidates.push(process_report);
    }

    report
}

fn enumerate_processes() -> Result<Vec<ProcessEntry>, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map(OwnedHandle)
        .map_err(|error| format!("CreateToolhelp32Snapshot(processes) failed: {error}"))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe { Process32FirstW(snapshot.0, &mut entry) }
        .map_err(|error| format!("Process32FirstW failed: {error}"))?;

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
                error: Some(format!("OpenProcess failed: {error}")),
            };
        }
    };

    let module = match find_module(process.pid, target_module) {
        Ok(module) => module,
        Err(error) => {
            return ProcessReport {
                pid: process.pid,
                process_name: process.name.clone(),
                process_opened: true,
                module: None,
                error: Some(error),
            };
        }
    };

    let (bytes, bytes_read) = match read_memory(process_handle.0, module.base, HEADER_READ_SIZE) {
        Ok(result) => result,
        Err(error) => {
            return ProcessReport {
                pid: process.pid,
                process_name: process.name.clone(),
                process_opened: true,
                module: None,
                error: Some(error),
            };
        }
    };

    let pe = match parse_pe_headers(&bytes[..bytes_read]) {
        Ok(pe) => pe,
        Err(error) => {
            return ProcessReport {
                pid: process.pid,
                process_name: process.name.clone(),
                process_opened: true,
                module: None,
                error: Some(format!("in-memory PE validation failed: {error}")),
            };
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

fn find_module(pid: u32, target_module: &str) -> Result<ModuleEntry, String> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
            .map(OwnedHandle)
            .map_err(|error| format!("CreateToolhelp32Snapshot(modules) failed: {error}"))?;

    let mut entry = MODULEENTRY32W {
        dwSize: size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe { Module32FirstW(snapshot.0, &mut entry) }
        .map_err(|error| format!("Module32FirstW failed: {error}"))?;

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

    Err(format!(
        "module {target_module} was not visible in process {pid}"
    ))
}

fn read_memory(handle: HANDLE, address: u64, size: usize) -> Result<(Vec<u8>, usize), String> {
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
    .map_err(|error| format!("ReadProcessMemory at {address:#x} failed: {error}"))?;

    if bytes_read == 0 {
        return Err(format!(
            "ReadProcessMemory at {address:#x} returned zero bytes"
        ));
    }

    Ok((bytes, bytes_read))
}

fn wide_string<const N: usize>(buffer: &[u16; N]) -> String {
    let length = buffer.iter().position(|value| *value == 0).unwrap_or(N);
    String::from_utf16_lossy(&buffer[..length])
}
