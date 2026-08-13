use std::ffi::c_void;

use deimos_core::{
    parse_pe_headers, DeimosError, ModuleReport, ProbeReport, ProbeRequest, ProcessReport,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::process::ProcessBackend;
use crate::windows_process::{WindowsProcessBackend, WindowsProcessHandle};

const HEADER_READ_SIZE: usize = 4096;

pub fn run(request: &ProbeRequest) -> ProbeReport {
    let mut report = ProbeReport::new(request);
    let backend = WindowsProcessBackend;
    let processes = match backend.list_processes() {
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
        let process_report =
            probe_process(&backend, process.pid, &process.name, &request.target_module);
        if process_report.error.is_none() {
            report.success = true;
        }
        report.candidates.push(process_report);
    }
    report
}

fn probe_process(
    backend: &WindowsProcessBackend,
    pid: u32,
    process_name: &str,
    target_module: &str,
) -> ProcessReport {
    let opened = match backend.open_process(pid) {
        Ok(opened) => opened,
        Err(error) => {
            return ProcessReport {
                pid,
                process_name: process_name.to_string(),
                process_opened: false,
                module: None,
                error: Some(error.to_string()),
            };
        }
    };
    let modules = match opened.process.identity.as_ref() {
        Some(identity) => backend.enumerate_modules(&opened.handle, identity),
        None => {
            return failed_process_report(
                pid,
                process_name,
                DeimosError::process_access("opened process did not provide an identity"),
            )
        }
    };
    let modules = match modules {
        Ok(modules) => modules,
        Err(error) => {
            return failed_process_report(
                pid,
                process_name,
                DeimosError::module_enumeration(error.to_string()),
            )
        }
    };
    let module = match modules
        .into_iter()
        .find(|module| module.name.eq_ignore_ascii_case(target_module))
    {
        Some(module) => module,
        None => {
            return failed_process_report(
                pid,
                process_name,
                DeimosError::module_enumeration(format!(
                    "module {target_module} was not visible in process {pid}"
                )),
            )
        }
    };
    let address = match parse_address(&module.base_address) {
        Ok(address) => address,
        Err(error) => return failed_process_report(pid, process_name, error),
    };
    let (bytes, bytes_read) = match read_memory(&opened.handle, address, HEADER_READ_SIZE) {
        Ok(result) => result,
        Err(error) => return failed_process_report(pid, process_name, error),
    };
    let pe = match parse_pe_headers(&bytes[..bytes_read]) {
        Ok(pe) => pe,
        Err(error) => {
            return failed_process_report(
                pid,
                process_name,
                DeimosError::pe_parse(format!("in-memory PE validation failed: {error}")),
            )
        }
    };

    ProcessReport {
        pid,
        process_name: process_name.to_string(),
        process_opened: true,
        module: Some(ModuleReport {
            module_name: module.name,
            executable_path: module.executable_path,
            module_base: module.base_address,
            module_size: module.size,
            bytes_read,
            pe,
        }),
        error: None,
    }
}

fn failed_process_report(pid: u32, process_name: &str, error: DeimosError) -> ProcessReport {
    ProcessReport {
        pid,
        process_name: process_name.to_string(),
        process_opened: true,
        module: None,
        error: Some(error.to_string()),
    }
}

fn parse_address(address: &str) -> Result<u64, DeimosError> {
    u64::from_str_radix(address.trim_start_matches("0x"), 16).map_err(|error| {
        DeimosError::module_enumeration(format!(
            "module base address {address} was invalid: {error}"
        ))
    })
}

fn read_memory(
    handle: &WindowsProcessHandle,
    address: u64,
    size: usize,
) -> Result<(Vec<u8>, usize), DeimosError> {
    let mut bytes = vec![0u8; size];
    let mut bytes_read = 0usize;
    unsafe {
        ReadProcessMemory(
            handle.raw(),
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
