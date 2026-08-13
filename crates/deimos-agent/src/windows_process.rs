use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::{Child, Command};

use deimos_core::client::{
    KeyAction, MessageDelivery, MouseButton, WindowPoint, WindowRectangle, WindowSize,
};
use deimos_core::memory::{MemoryProtection, MemoryRegionDescriptor};
use deimos_core::process::{
    classify_process, ModuleDescriptor, ProcessAccessMode, ProcessDescriptor, ProcessIdentity,
};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, BOOL, ERROR_NO_MORE_FILES, E_ACCESSDENIED, E_INVALIDARG, FILETIME, HANDLE, HWND,
    LPARAM, POINT, RECT, STILL_ACTIVE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Graphics::Gdi::{ClientToScreen, ScreenToClient};
use windows::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, WriteProcessMemory, CONTEXT,
    CONTEXT_CONTROL_AMD64,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION,
    MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeProcess, GetExitCodeThread, GetProcessId, GetProcessTimes,
    OpenProcess, OpenThread, QueryFullProcessImageNameW, ResumeThread, SuspendThread,
    WaitForSingleObject, LPTHREAD_START_ROUTINE, PROCESS_CREATE_THREAD, PROCESS_NAME_WIN32,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetClientRect, GetForegroundWindow, GetWindowRect,
    GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindow, PostMessageW,
    SendMessageW, SetForegroundWindow, SetWindowTextW, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_MOUSEMOVE, WM_RBUTTONDOWN, WM_RBUTTONUP,
};

use crate::process::{
    enumerate_modules_with_revalidation, ClientWindowCandidate, ClientWindowSnapshot,
    ClientWindowTarget, MemoryBackend, MutationBackend, OpenedProcess, ProcessBackend,
    ProcessBackendError, ProcessBackendErrorKind, ProcessThreadResume, RemoteThreadPoll,
    StartedRemoteThread, SuspendedProcess,
};

const MAX_EXECUTABLE_PATH: usize = 32_768;
const WIZARD_WINDOW_CLASS: &str = "Wizard Graphical Client";

struct OwnedHandle(HANDLE);

#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

const _: () = assert!(std::mem::align_of::<AlignedContext>() == 16);

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

pub struct WindowsThreadHandle(OwnedHandle);

struct SuspendedWindowsThreads(Vec<OwnedHandle>);

impl ProcessThreadResume for SuspendedWindowsThreads {
    fn resume(&mut self) -> Result<(), ProcessBackendError> {
        let mut retained = Vec::new();
        let mut first_error = None;
        while let Some(thread) = self.0.pop() {
            if unsafe { ResumeThread(thread.0) } != u32::MAX {
                continue;
            }
            let resume_error = last_error("ResumeThread failed during hook retirement");
            let mut exit_code = 0u32;
            let exited = unsafe { GetExitCodeThread(thread.0, &mut exit_code) }.is_ok()
                && exit_code != STILL_ACTIVE.0 as u32;
            if !exited {
                retained.push(thread);
                if first_error.is_none() {
                    first_error = Some(resume_error);
                }
            }
        }
        retained.reverse();
        self.0 = retained;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for SuspendedWindowsThreads {
    fn drop(&mut self) {
        let _ = self.resume();
    }
}

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

    fn list_client_windows(&self) -> Result<Vec<ClientWindowCandidate>, ProcessBackendError> {
        enumerate_client_windows()
    }

    fn launch_game(
        &self,
        game_path: &str,
        login_server: &str,
    ) -> Result<ProcessIdentity, ProcessBackendError> {
        let bin_directory = Path::new(game_path).join("Bin");
        let executable = bin_directory.join("WizardGraphicalClient.exe");
        if !executable.is_file() {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::NotFound,
                format!(
                    "Wizard101 executable was not found at {}",
                    executable.display()
                ),
            ));
        }
        let (host, port) = login_server.rsplit_once(':').ok_or_else(|| {
            ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                "login server must use host:port format",
            )
        })?;
        let mut child = Command::new(&executable)
            .arg("-L")
            .arg(host)
            .arg(port)
            .current_dir(&bin_directory)
            .spawn()
            .map_err(|error| {
                ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    format!("Windows could not create the Wizard101 process: {error}"),
                )
                .with_native_code(error.raw_os_error().unwrap_or_default())
            })?;
        match process_identity(HANDLE(child.as_raw_handle()), child.id()) {
            Ok(identity) => Ok(identity),
            Err(mut error) => {
                if let Some(cleanup_error) = stop_spawned_child(&mut child) {
                    error.message = format!(
                        "{}; the unconfirmed process could not be cleaned up: {cleanup_error}",
                        error.message
                    );
                }
                Err(error)
            }
        }
    }

    fn terminate_process_and_wait(
        &self,
        expected: &ProcessIdentity,
        timeout_ms: u32,
    ) -> Result<(), ProcessBackendError> {
        let process = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                expected.pid,
            )
        }
        .map(OwnedHandle)
        .map_err(|error| open_error(expected.pid, error))?;
        let actual = process_identity(process.0, expected.pid)?;
        if actual.pid != expected.pid
            || actual.creation_time_100ns != expected.creation_time_100ns
            || !actual
                .executable_path
                .eq_ignore_ascii_case(&expected.executable_path)
        {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::IdentityMismatch,
                format!(
                    "process {} changed identity before it could be terminated",
                    expected.pid
                ),
            ));
        }
        unsafe { windows::Win32::System::Threading::TerminateProcess(process.0, 1) }
            .map_err(|error| native_error("TerminateProcess failed", error))?;
        let wait = unsafe { WaitForSingleObject(process.0, timeout_ms) };
        if wait == WAIT_TIMEOUT {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!(
                    "timed out after {timeout_ms} ms waiting for process {} to exit",
                    expected.pid
                ),
            ));
        }
        if wait == WAIT_FAILED {
            return Err(last_error(format!(
                "WaitForSingleObject failed while waiting for process {} to exit",
                expected.pid
            )));
        }
        if wait != WAIT_OBJECT_0 {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!(
                    "process {} returned unexpected wait status {:#x}",
                    expected.pid, wait.0
                ),
            ));
        }
        Ok(())
    }

    fn open_process(&self, pid: u32) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
        self.open_process_for_access(pid, ProcessAccessMode::ReadOnly)
    }

    fn open_process_for_access(
        &self,
        pid: u32,
        access_mode: ProcessAccessMode,
    ) -> Result<OpenedProcess<Self::Handle>, ProcessBackendError> {
        let access = match access_mode {
            ProcessAccessMode::ReadOnly => PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            ProcessAccessMode::Mutation => {
                PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE
            }
        };
        let handle = unsafe { OpenProcess(access, false, pid) }
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
            let mut contextual = ProcessBackendError::new(
                error.kind,
                format!(
                    "active process {} could not be re-identified: {}",
                    expected.pid, error.message
                ),
            );
            contextual.native_code = error.native_code;
            contextual
        })?;
        if actual.creation_time_100ns != expected.creation_time_100ns
            || !actual
                .executable_path
                .eq_ignore_ascii_case(&expected.executable_path)
        {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!(
                    "active process {} could not be verified against the identity captured when the session opened",
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

    fn inspect_client_window(
        &self,
        target: &ClientWindowTarget,
    ) -> Result<ClientWindowSnapshot, ProcessBackendError> {
        let hwnd = validate_client_window(target)?;
        let title_length = unsafe { GetWindowTextLengthW(hwnd) };
        let mut title = vec![0u16; title_length.max(0) as usize + 1];
        let copied = unsafe { GetWindowTextW(hwnd, &mut title) };
        title.truncate(copied.max(0) as usize);
        let mut rectangle = RECT::default();
        unsafe { GetWindowRect(hwnd, &mut rectangle) }
            .map_err(|error| native_error("GetWindowRect failed for Wizard101 client", error))?;
        let mut client_rectangle = RECT::default();
        unsafe { GetClientRect(hwnd, &mut client_rectangle) }
            .map_err(|error| native_error("GetClientRect failed for Wizard101 client", error))?;
        let mut client_origin = POINT::default();
        if !unsafe { ClientToScreen(hwnd, &mut client_origin) }.as_bool() {
            return Err(last_error("ClientToScreen failed for Wizard101 client"));
        }
        Ok(ClientWindowSnapshot {
            title: String::from_utf16_lossy(&title),
            is_foreground: unsafe { GetForegroundWindow() } == hwnd,
            rectangle: WindowRectangle {
                left: rectangle.left,
                top: rectangle.top,
                right: rectangle.right,
                bottom: rectangle.bottom,
            },
            client_origin: WindowPoint {
                x: client_origin.x,
                y: client_origin.y,
            },
            client_size: WindowSize {
                width: client_rectangle.right - client_rectangle.left,
                height: client_rectangle.bottom - client_rectangle.top,
            },
        })
    }

    fn focus_client_window(
        &self,
        target: &ClientWindowTarget,
    ) -> Result<bool, ProcessBackendError> {
        let hwnd = validate_client_window(target)?;
        if !unsafe { SetForegroundWindow(hwnd) }.as_bool() {
            return Err(last_error(
                "SetForegroundWindow could not focus the selected Wizard101 client",
            ));
        }
        Ok(unsafe { GetForegroundWindow() } == hwnd)
    }

    fn set_client_window_title(
        &self,
        target: &ClientWindowTarget,
        title: &str,
    ) -> Result<(), ProcessBackendError> {
        let hwnd = validate_client_window(target)?;
        let mut wide = title.encode_utf16().collect::<Vec<_>>();
        wide.push(0);
        unsafe { SetWindowTextW(hwnd, PCWSTR(wide.as_ptr())) }.map_err(|error| {
            native_error(
                "SetWindowTextW failed for the selected Wizard101 client",
                error,
            )
        })
    }

    fn client_to_screen(
        &self,
        target: &ClientWindowTarget,
        point: WindowPoint,
    ) -> Result<WindowPoint, ProcessBackendError> {
        let hwnd = validate_client_window(target)?;
        let mut point = windows::Win32::Foundation::POINT {
            x: point.x,
            y: point.y,
        };
        if !unsafe { ClientToScreen(hwnd, &mut point) }.as_bool() {
            return Err(last_error(
                "ClientToScreen failed for the selected Wizard101 client",
            ));
        }
        Ok(WindowPoint {
            x: point.x,
            y: point.y,
        })
    }

    fn screen_to_client(
        &self,
        target: &ClientWindowTarget,
        point: WindowPoint,
    ) -> Result<WindowPoint, ProcessBackendError> {
        let hwnd = validate_client_window(target)?;
        let mut point = windows::Win32::Foundation::POINT {
            x: point.x,
            y: point.y,
        };
        if !unsafe { ScreenToClient(hwnd, &mut point) }.as_bool() {
            return Err(last_error(
                "ScreenToClient failed for the selected Wizard101 client",
            ));
        }
        Ok(WindowPoint {
            x: point.x,
            y: point.y,
        })
    }

    fn send_client_key_event(
        &self,
        target: &ClientWindowTarget,
        virtual_key: u16,
        action: KeyAction,
        delivery: MessageDelivery,
    ) -> Result<(), ProcessBackendError> {
        let hwnd = validate_client_window(target)?;
        let message = match action {
            KeyAction::Down => WM_KEYDOWN,
            KeyAction::Up => WM_KEYUP,
        };
        send_window_message(
            hwnd,
            message,
            windows::Win32::Foundation::WPARAM(usize::from(virtual_key)),
            LPARAM(0),
            delivery,
        )
    }

    fn send_client_mouse_move(
        &self,
        target: &ClientWindowTarget,
        point: WindowPoint,
        delivery: MessageDelivery,
    ) -> Result<(), ProcessBackendError> {
        let hwnd = validate_client_window(target)?;
        send_window_message(
            hwnd,
            WM_MOUSEMOVE,
            windows::Win32::Foundation::WPARAM(0),
            point_lparam(point),
            delivery,
        )
    }

    fn send_client_mouse_button(
        &self,
        target: &ClientWindowTarget,
        point: WindowPoint,
        button: MouseButton,
        pressed: bool,
        delivery: MessageDelivery,
    ) -> Result<(), ProcessBackendError> {
        let hwnd = validate_client_window(target)?;
        let (message, flags) = match (button, pressed) {
            (MouseButton::Left, true) => (WM_LBUTTONDOWN, 0x0001usize),
            (MouseButton::Left, false) => (WM_LBUTTONUP, 0usize),
            (MouseButton::Right, true) => (WM_RBUTTONDOWN, 0x0002usize),
            (MouseButton::Right, false) => (WM_RBUTTONUP, 0usize),
        };
        send_window_message(
            hwnd,
            message,
            windows::Win32::Foundation::WPARAM(flags),
            point_lparam(point),
            delivery,
        )
    }
}

fn stop_spawned_child(child: &mut Child) -> Option<String> {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return None;
    }
    if let Err(error) = child.kill() {
        return Some(format!("termination failed: {error}"));
    }
    child
        .wait()
        .err()
        .map(|error| format!("exit confirmation failed: {error}"))
}

fn validate_client_window(target: &ClientWindowTarget) -> Result<HWND, ProcessBackendError> {
    let hwnd = HWND(target.native_window_id as usize as *mut c_void);
    if !unsafe { IsWindow(hwnd) }.as_bool() {
        return Err(ProcessBackendError::new(
            ProcessBackendErrorKind::NotFound,
            "the selected Wizard101 window has closed",
        ));
    }

    let mut pid = 0u32;
    if unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) } == 0
        || pid != target.process_identity.pid
    {
        return Err(ProcessBackendError::new(
            ProcessBackendErrorKind::IdentityMismatch,
            "the selected window no longer belongs to the expected Wizard101 process",
        ));
    }

    let handle = open_query_handle(pid)?;
    let identity = process_identity(handle.0, pid)?;
    if identity.creation_time_100ns != target.process_identity.creation_time_100ns
        || !identity
            .executable_path
            .eq_ignore_ascii_case(&target.process_identity.executable_path)
    {
        return Err(ProcessBackendError::new(
            ProcessBackendErrorKind::IdentityMismatch,
            "the selected Wizard101 window was replaced by another process",
        ));
    }

    let mut class_name = [0u16; 256];
    let class_length = unsafe { GetClassNameW(hwnd, &mut class_name) };
    if class_length == 0
        || String::from_utf16_lossy(&class_name[..class_length as usize]) != WIZARD_WINDOW_CLASS
    {
        return Err(ProcessBackendError::new(
            ProcessBackendErrorKind::IdentityMismatch,
            "the selected window is no longer a Wizard101 game client",
        ));
    }
    Ok(hwnd)
}

fn send_window_message(
    hwnd: HWND,
    message: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: LPARAM,
    delivery: MessageDelivery,
) -> Result<(), ProcessBackendError> {
    match delivery {
        MessageDelivery::Send => {
            unsafe {
                SendMessageW(hwnd, message, wparam, lparam);
            }
            Ok(())
        }
        MessageDelivery::Post => unsafe { PostMessageW(hwnd, message, wparam, lparam) }
            .map_err(|error| native_error("PostMessageW failed for Wizard101 input", error)),
    }
}

fn point_lparam(point: WindowPoint) -> LPARAM {
    let x = point.x as i16 as u16 as u32;
    let y = point.y as i16 as u16 as u32;
    LPARAM((x | (y << 16)) as isize)
}

fn enumerate_client_windows() -> Result<Vec<ClientWindowCandidate>, ProcessBackendError> {
    let foreground = unsafe { GetForegroundWindow() };
    let mut context = ClientWindowEnumeration {
        foreground,
        windows: Vec::new(),
    };
    unsafe {
        EnumWindows(
            Some(collect_client_window),
            LPARAM((&mut context as *mut ClientWindowEnumeration) as isize),
        )
    }
    .map_err(|error| native_error("EnumWindows failed during client discovery", error))?;
    Ok(context.windows)
}

struct ClientWindowEnumeration {
    foreground: HWND,
    windows: Vec<ClientWindowCandidate>,
}

unsafe extern "system" fn collect_client_window(hwnd: HWND, context: LPARAM) -> BOOL {
    // `context` is a stack-owned value that remains alive until EnumWindows
    // returns. Keep the raw pointer confined to this synchronous callback.
    let Some(context) = (unsafe { (context.0 as *mut ClientWindowEnumeration).as_mut() }) else {
        return BOOL(1);
    };
    let mut class_name = [0u16; 256];
    let length = GetClassNameW(hwnd, &mut class_name);
    if length <= 0
        || !class_name[..length as usize]
            .iter()
            .copied()
            .eq(WIZARD_WINDOW_CLASS.encode_utf16())
    {
        return BOOL(1);
    }

    let mut pid = 0u32;
    if GetWindowThreadProcessId(hwnd, Some(&mut pid)) == 0 || pid == 0 {
        return BOOL(1);
    }
    let process_identity =
        match open_query_handle(pid).and_then(|handle| process_identity(handle.0, pid)) {
            Ok(identity) => identity,
            Err(_) => return BOOL(1),
        };
    let mut confirmed_pid = 0u32;
    if GetWindowThreadProcessId(hwnd, Some(&mut confirmed_pid)) == 0 || confirmed_pid != pid {
        return BOOL(1);
    }
    let mut rectangle = RECT::default();
    if GetWindowRect(hwnd, &mut rectangle).is_err() {
        return BOOL(1);
    }

    context.windows.push(ClientWindowCandidate {
        native_window_id: hwnd.0 as usize as u64,
        pid,
        process_identity,
        is_foreground: hwnd == context.foreground,
        left: rectangle.left,
        top: rectangle.top,
    });
    BOOL(1)
}

impl MemoryBackend for WindowsProcessBackend {
    fn enumerate_memory_regions(
        &self,
        handle: &Self::Handle,
        expected: &ProcessIdentity,
    ) -> Result<Vec<MemoryRegionDescriptor>, ProcessBackendError> {
        self.validate_process(handle, expected)?;
        let mut regions = Vec::new();
        let mut address = 0usize;
        loop {
            let mut information = MEMORY_BASIC_INFORMATION::default();
            let result = unsafe {
                VirtualQueryEx(
                    handle.raw(),
                    Some(address as *const c_void),
                    &mut information,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if result == 0 {
                break;
            }
            let base_address = information.BaseAddress as usize;
            let region_size = information.RegionSize;
            if information.State == MEM_COMMIT
                && readable_protection(information.Protect.0).is_some()
                && region_size > 0
            {
                regions.push(MemoryRegionDescriptor {
                    base_address: format!("{base_address:#x}"),
                    size: region_size,
                    protection: readable_protection(information.Protect.0)
                        .expect("readable protection was checked above"),
                });
            }
            let next = base_address.checked_add(region_size).ok_or_else(|| {
                ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    "VirtualQueryEx region address overflowed",
                )
            })?;
            if next <= address {
                break;
            }
            address = next;
        }
        Ok(regions)
    }

    fn read_memory(
        &self,
        handle: &Self::Handle,
        address: usize,
        size: usize,
    ) -> Result<Vec<u8>, ProcessBackendError> {
        validate_read_range(handle.raw(), address, size)?;
        let mut bytes = vec![0u8; size];
        let mut bytes_read = 0usize;
        unsafe {
            ReadProcessMemory(
                handle.raw(),
                address as *const c_void,
                bytes.as_mut_ptr().cast::<c_void>(),
                size,
                Some(&mut bytes_read),
            )
        }
        .map_err(|error| {
            ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!(
                    "ReadProcessMemory at {address:#x} read {bytes_read} of {size} bytes: {error}"
                ),
            )
            .with_native_code(error.code().0)
        })?;
        if bytes_read != size {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!("ReadProcessMemory at {address:#x} returned {bytes_read} of {size} bytes"),
            ));
        }
        Ok(bytes)
    }
}

impl MutationBackend for WindowsProcessBackend {
    type ThreadHandle = WindowsThreadHandle;

    fn write_memory(
        &self,
        handle: &Self::Handle,
        address: usize,
        bytes: &[u8],
    ) -> Result<(), ProcessBackendError> {
        validate_write_range(handle.raw(), address, bytes.len())?;
        let mut bytes_written = 0usize;
        unsafe {
            WriteProcessMemory(
                handle.raw(),
                address as *const c_void,
                bytes.as_ptr().cast::<c_void>(),
                bytes.len(),
                Some(&mut bytes_written),
            )
        }
        .map_err(|error| {
            native_error(
                format!(
                    "WriteProcessMemory at {address:#x} wrote {bytes_written} of {} bytes",
                    bytes.len()
                ),
                error,
            )
        })?;
        if bytes_written != bytes.len() {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!(
                    "WriteProcessMemory at {address:#x} returned {bytes_written} of {} bytes",
                    bytes.len()
                ),
            ));
        }
        flush_remote_instruction_cache(handle.raw(), address, bytes.len())
    }

    fn allocate_memory(
        &self,
        handle: &Self::Handle,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<usize, ProcessBackendError> {
        let pointer = unsafe {
            VirtualAllocEx(
                handle.raw(),
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                native_protection(protection),
            )
        };
        if pointer.is_null() {
            return Err(last_error(format!(
                "VirtualAllocEx could not allocate {size} bytes"
            )));
        }
        Ok(pointer as usize)
    }

    fn allocate_memory_near(
        &self,
        handle: &Self::Handle,
        target: usize,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<usize, ProcessBackendError> {
        const GRANULARITY: usize = 64 * 1024;
        const REL32_REACH: usize = i32::MAX as usize;

        let minimum = align_up(
            target.saturating_sub(REL32_REACH).max(GRANULARITY),
            GRANULARITY,
        )
        .ok_or_else(|| {
            ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                "near-allocation lower bound overflowed",
            )
        })?;
        let maximum = target.saturating_add(REL32_REACH);
        let mut cursor = minimum;
        while cursor < maximum {
            let mut information = MEMORY_BASIC_INFORMATION::default();
            let queried = unsafe {
                VirtualQueryEx(
                    handle.raw(),
                    Some(cursor as *const c_void),
                    &mut information,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if queried == 0 {
                break;
            }
            let region_base = information.BaseAddress as usize;
            let region_end = region_base.saturating_add(information.RegionSize);
            if information.State == MEM_FREE {
                let candidate =
                    align_up(region_base.max(minimum), GRANULARITY).ok_or_else(|| {
                        ProcessBackendError::new(
                            ProcessBackendErrorKind::Native,
                            "near-allocation candidate overflowed",
                        )
                    })?;
                if candidate
                    .checked_add(size)
                    .is_some_and(|end| end <= region_end && end <= maximum)
                {
                    let pointer = unsafe {
                        VirtualAllocEx(
                            handle.raw(),
                            Some(candidate as *const c_void),
                            size,
                            MEM_COMMIT | MEM_RESERVE,
                            native_protection(protection),
                        )
                    };
                    if !pointer.is_null() {
                        return Ok(pointer as usize);
                    }
                }
            }
            cursor = region_end.max(cursor.saturating_add(GRANULARITY));
        }
        Err(last_error(format!(
            "VirtualAllocEx could not allocate {size} bytes within rel32 reach of {target:#x}"
        )))
    }

    fn free_memory(
        &self,
        handle: &Self::Handle,
        address: usize,
    ) -> Result<(), ProcessBackendError> {
        unsafe { VirtualFreeEx(handle.raw(), address as *mut c_void, 0, MEM_RELEASE) }
            .map_err(|error| native_error(format!("VirtualFreeEx failed at {address:#x}"), error))
    }

    fn suspend_process_threads(
        &self,
        handle: &Self::Handle,
    ) -> Result<SuspendedProcess, ProcessBackendError> {
        suspend_process_threads(handle.raw())
    }

    fn protect_memory(
        &self,
        handle: &Self::Handle,
        address: usize,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<MemoryProtection, ProcessBackendError> {
        let (expected_previous, expected_previous_raw) =
            validate_protection_range(handle.raw(), address, size)?;
        let mut previous = PAGE_NOACCESS;
        unsafe {
            VirtualProtectEx(
                handle.raw(),
                address as *const c_void,
                size,
                native_protection(protection),
                &mut previous,
            )
        }
        .map_err(|error| {
            native_error(
                format!(
                    "VirtualProtectEx failed for {address:#x}..{:#x}",
                    address + size
                ),
                error,
            )
        })?;
        let actual_previous = exact_protection(previous.0);
        if previous.0 != expected_previous_raw.0 || actual_previous.is_none() {
            let mut changed_protection = PAGE_NOACCESS;
            let rollback = unsafe {
                VirtualProtectEx(
                    handle.raw(),
                    address as *const c_void,
                    size,
                    previous,
                    &mut changed_protection,
                )
            };
            return match rollback {
                Ok(()) => Err(ProcessBackendError::new(
                    ProcessBackendErrorKind::Native,
                    format!(
                        "VirtualProtectEx changed {address:#x}..{:#x}, but raw previous flags {:#x} did not match the prevalidated flags {:#x}; rollback succeeded and restored the raw previous flags",
                        address + size,
                        previous.0,
                        expected_previous_raw.0
                    ),
                )),
                Err(error) => Err(native_error(
                    format!(
                        "VirtualProtectEx changed {address:#x}..{:#x}, but raw previous flags {:#x} did not match the prevalidated flags {:#x}; rollback failed and the requested protection may remain active",
                        address + size,
                        previous.0,
                        expected_previous_raw.0
                    ),
                    error,
                )),
            };
        }
        Ok(expected_previous)
    }

    fn start_remote_thread(
        &self,
        handle: &Self::Handle,
        start_address: usize,
        parameter: Option<usize>,
    ) -> Result<StartedRemoteThread<Self::ThreadHandle>, ProcessBackendError> {
        validate_executable_address(handle.raw(), start_address)?;
        let routine: LPTHREAD_START_ROUTINE = Some(unsafe {
            std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(
                start_address,
            )
        });
        let mut thread_id = 0u32;
        let thread = unsafe {
            CreateRemoteThread(
                handle.raw(),
                None,
                0,
                routine,
                parameter.map(|value| value as *const c_void),
                0,
                Some(&mut thread_id),
            )
        }
        .map(OwnedHandle)
        .map_err(|error| {
            native_error(
                format!("CreateRemoteThread failed at {start_address:#x}"),
                error,
            )
        })?;
        Ok(StartedRemoteThread {
            thread_id,
            handle: WindowsThreadHandle(thread),
        })
    }

    fn poll_remote_thread(
        &self,
        thread: &Self::ThreadHandle,
        wait_timeout_ms: u32,
    ) -> Result<RemoteThreadPoll, ProcessBackendError> {
        let wait = unsafe { WaitForSingleObject(thread.0 .0, wait_timeout_ms) };
        if wait == WAIT_TIMEOUT {
            return Ok(RemoteThreadPoll {
                completed: false,
                exit_code: None,
            });
        }
        if wait == WAIT_FAILED {
            return Err(last_error("WaitForSingleObject failed for remote thread"));
        }
        if wait != WAIT_OBJECT_0 {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!(
                    "remote thread returned unexpected wait status {:#x}",
                    wait.0
                ),
            ));
        }
        let mut exit_code = 0u32;
        unsafe { GetExitCodeThread(thread.0 .0, &mut exit_code) }
            .map_err(|error| native_error("GetExitCodeThread failed for remote thread", error))?;
        Ok(RemoteThreadPoll {
            completed: true,
            exit_code: Some(exit_code),
        })
    }

    fn flush_instruction_cache(
        &self,
        handle: &Self::Handle,
        address: usize,
        size: usize,
    ) -> Result<(), ProcessBackendError> {
        flush_remote_instruction_cache(handle.raw(), address, size)
    }
}

fn validate_read_range(
    handle: HANDLE,
    address: usize,
    size: usize,
) -> Result<(), ProcessBackendError> {
    validate_range_with(
        handle,
        address,
        size,
        |protection| readable_protection(protection).is_some(),
        "readable",
    )
}

fn validate_write_range(
    handle: HANDLE,
    address: usize,
    size: usize,
) -> Result<(), ProcessBackendError> {
    validate_range_with(
        handle,
        address,
        size,
        |protection| {
            protection & PAGE_GUARD.0 == 0
                && matches!(
                    protection & 0xff,
                    value
                        if value == PAGE_READWRITE.0
                            || value == PAGE_EXECUTE_READWRITE.0
                            || value == PAGE_WRITECOPY.0
                            || value == PAGE_EXECUTE_WRITECOPY.0
                )
        },
        "writable",
    )
}

fn validate_range_with(
    handle: HANDLE,
    address: usize,
    size: usize,
    accepts_protection: impl Fn(u32) -> bool,
    requirement: &str,
) -> Result<(), ProcessBackendError> {
    let end = address.checked_add(size).ok_or_else(|| {
        ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "memory address plus size overflowed",
        )
    })?;
    let mut cursor = address;
    while cursor < end {
        let mut information = MEMORY_BASIC_INFORMATION::default();
        let result = unsafe {
            VirtualQueryEx(
                handle,
                Some(cursor as *const c_void),
                &mut information,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if result == 0 || information.RegionSize == 0 {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!("VirtualQueryEx could not validate address {cursor:#x}"),
            ));
        }
        let base = information.BaseAddress as usize;
        let region_end = base.checked_add(information.RegionSize).ok_or_else(|| {
            ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                "VirtualQueryEx region address overflowed",
            )
        })?;
        if cursor < base
            || region_end <= cursor
            || information.State != MEM_COMMIT
            || !accepts_protection(information.Protect.0)
        {
            return Err(ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!("memory range at {cursor:#x} is not {requirement}"),
            ));
        }
        cursor = end.min(region_end);
    }
    Ok(())
}

fn validate_executable_address(handle: HANDLE, address: usize) -> Result<(), ProcessBackendError> {
    validate_range_with(
        handle,
        address,
        1,
        |protection| {
            protection & PAGE_GUARD.0 == 0
                && matches!(
                    protection & 0xff,
                    value
                        if value == PAGE_EXECUTE_READ.0
                            || value == PAGE_EXECUTE_READWRITE.0
                            || value == PAGE_EXECUTE_WRITECOPY.0
                )
        },
        "executable and committed",
    )
}

fn validate_protection_range(
    handle: HANDLE,
    address: usize,
    size: usize,
) -> Result<(MemoryProtection, PAGE_PROTECTION_FLAGS), ProcessBackendError> {
    let end = address.checked_add(size).ok_or_else(|| {
        ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "memory protection range overflowed",
        )
    })?;
    let mut information = MEMORY_BASIC_INFORMATION::default();
    let result = unsafe {
        VirtualQueryEx(
            handle,
            Some(address as *const c_void),
            &mut information,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    let base = information.BaseAddress as usize;
    let region_end = base.checked_add(information.RegionSize).ok_or_else(|| {
        ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            "VirtualQueryEx protection region overflowed",
        )
    })?;
    if result == 0
        || information.RegionSize == 0
        || information.State != MEM_COMMIT
        || address < base
        || end > region_end
    {
        return Err(ProcessBackendError::new(
            ProcessBackendErrorKind::Native,
            format!(
                "VirtualProtectEx requires one homogeneous committed region for {address:#x}..{end:#x}"
            ),
        ));
    }
    exact_protection(information.Protect.0)
        .map(|protection| (protection, information.Protect))
        .ok_or_else(|| {
            ProcessBackendError::new(
                ProcessBackendErrorKind::Native,
                format!(
                    "memory at {address:#x} has unsupported or modified protection {:#x}",
                    information.Protect.0
                ),
            )
        })
}

fn flush_remote_instruction_cache(
    handle: HANDLE,
    address: usize,
    size: usize,
) -> Result<(), ProcessBackendError> {
    let base_address = (size != 0).then_some(address as *const c_void);
    unsafe { FlushInstructionCache(handle, base_address, size) }.map_err(|error| {
        let range = if size == 0 {
            "the entire target process".to_string()
        } else {
            format!("{address:#x}..{:#x}", address + size)
        };
        native_error(format!("FlushInstructionCache failed for {range}"), error)
    })
}

fn exact_protection(protection: u32) -> Option<MemoryProtection> {
    match protection {
        value if value == PAGE_READONLY.0 => Some(MemoryProtection::ReadOnly),
        value if value == PAGE_READWRITE.0 => Some(MemoryProtection::ReadWrite),
        value if value == PAGE_EXECUTE_READ.0 => Some(MemoryProtection::ExecuteRead),
        value if value == PAGE_EXECUTE_READWRITE.0 => Some(MemoryProtection::ExecuteReadWrite),
        value if value == PAGE_WRITECOPY.0 => Some(MemoryProtection::CopyOnWrite),
        value if value == PAGE_EXECUTE_WRITECOPY.0 => Some(MemoryProtection::ExecuteCopyOnWrite),
        _ => None,
    }
}

fn readable_protection(protection: u32) -> Option<MemoryProtection> {
    if protection & PAGE_GUARD.0 != 0 {
        return None;
    }
    match protection & 0xff {
        value if value == PAGE_READONLY.0 => Some(MemoryProtection::ReadOnly),
        value if value == PAGE_READWRITE.0 => Some(MemoryProtection::ReadWrite),
        value if value == PAGE_EXECUTE_READ.0 => Some(MemoryProtection::ExecuteRead),
        value if value == PAGE_EXECUTE_READWRITE.0 => Some(MemoryProtection::ExecuteReadWrite),
        value if value == PAGE_WRITECOPY.0 => Some(MemoryProtection::CopyOnWrite),
        value if value == PAGE_EXECUTE_WRITECOPY.0 => Some(MemoryProtection::ExecuteCopyOnWrite),
        value if value == PAGE_NOACCESS.0 => None,
        _ => None,
    }
}

fn native_protection(protection: MemoryProtection) -> PAGE_PROTECTION_FLAGS {
    match protection {
        MemoryProtection::ReadOnly => PAGE_READONLY,
        MemoryProtection::ReadWrite => PAGE_READWRITE,
        MemoryProtection::ExecuteRead => PAGE_EXECUTE_READ,
        MemoryProtection::ExecuteReadWrite => PAGE_EXECUTE_READWRITE,
        MemoryProtection::CopyOnWrite => PAGE_WRITECOPY,
        MemoryProtection::ExecuteCopyOnWrite => PAGE_EXECUTE_WRITECOPY,
    }
}

fn process_snapshot() -> Result<OwnedHandle, ProcessBackendError> {
    unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map(OwnedHandle)
        .map_err(|error| native_error("CreateToolhelp32Snapshot(processes) failed", error))
}

fn suspend_process_threads(handle: HANDLE) -> Result<SuspendedProcess, ProcessBackendError> {
    let pid = unsafe { GetProcessId(handle) };
    if pid == 0 {
        return Err(last_error("GetProcessId failed before hook retirement"));
    }
    let mut suspended = SuspendedWindowsThreads(Vec::new());
    let mut suspended_ids = HashSet::new();
    let mut instruction_pointers = Vec::new();
    loop {
        let mut discovered = false;
        for thread_id in target_thread_ids(pid)? {
            if !suspended_ids.insert(thread_id) {
                continue;
            }
            discovered = true;
            let thread = unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                    false,
                    thread_id,
                )
            }
            .map(OwnedHandle)
            .map_err(|error| {
                native_error(
                    format!("OpenThread failed for thread {thread_id} during hook retirement"),
                    error,
                )
            })?;
            if unsafe { SuspendThread(thread.0) } == u32::MAX {
                return Err(last_error(format!(
                    "SuspendThread failed for thread {thread_id} during hook retirement"
                )));
            }
            suspended.0.push(thread);
            let mut context = AlignedContext(CONTEXT {
                ContextFlags: CONTEXT_CONTROL_AMD64,
                ..Default::default()
            });
            unsafe {
                GetThreadContext(
                    suspended.0.last().expect("suspended thread is retained").0,
                    &mut context.0,
                )
            }
            .map_err(|error| {
                native_error(
                    format!(
                        "GetThreadContext failed for thread {thread_id} during hook retirement"
                    ),
                    error,
                )
            })?;
            instruction_pointers.push(context.0.Rip as usize);
        }
        if !discovered {
            break;
        }
    }
    Ok(SuspendedProcess::new(instruction_pointers, suspended))
}

fn target_thread_ids(pid: u32) -> Result<Vec<u32>, ProcessBackendError> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map(OwnedHandle)
        .map_err(|error| native_error("CreateToolhelp32Snapshot(threads) failed", error))?;
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    unsafe { Thread32First(snapshot.0, &mut entry) }
        .map_err(|error| native_error("Thread32First failed during hook retirement", error))?;
    let mut thread_ids = Vec::new();
    loop {
        if entry.th32OwnerProcessID == pid {
            thread_ids.push(entry.th32ThreadID);
        }
        match unsafe { Thread32Next(snapshot.0, &mut entry) } {
            Ok(()) => {}
            Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => break,
            Err(error) => {
                return Err(native_error(
                    "Thread32Next failed during hook retirement",
                    error,
                ))
            }
        }
    }
    Ok(thread_ids)
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

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|value| value & !(alignment - 1))
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

fn last_error(context: impl AsRef<str>) -> ProcessBackendError {
    native_error(context, windows::core::Error::from_win32())
}

fn wide_string<const N: usize>(buffer: &[u16; N]) -> String {
    let length = buffer.iter().position(|value| *value == 0).unwrap_or(N);
    String::from_utf16_lossy(&buffer[..length])
}
