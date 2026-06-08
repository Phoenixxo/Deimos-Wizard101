//! deimos-updater
//!
//! A tiny, native self-update helper for Deimos-Wizard101.
//!
//! Because a running PyInstaller one-file `Deimos.exe` holds a lock on its own
//! image, it cannot overwrite itself. Deimos extracts this helper, then spawns
//! it detached and exits. The helper:
//!
//!   1. Waits for the parent Deimos process (by PID) to fully exit.
//!   2. Copies the freshly downloaded executable over the old one (with retries
//!      to tolerate lingering file locks, which are common under Wine/Proton).
//!   3. Optionally relaunches the updated executable.
//!
//! Everything is logged to a file so failures (e.g. a read-only install
//! directory) are recoverable post-mortem rather than silent.
//!
//! Usage:
//!   deimos-updater --pid <parent_pid> --new <downloaded.exe> --target <Deimos.exe> [--relaunch] [--log <path>]

#![windows_subsystem = "windows"]

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};

/// Max time to wait for the parent process to exit before proceeding anyway.
const PARENT_WAIT: Duration = Duration::from_secs(60);
/// Grace period after the parent dies, to let the OS release the image lock.
const GRACE: Duration = Duration::from_millis(500);
/// Total time to keep retrying the file swap before giving up.
const SWAP_DEADLINE: Duration = Duration::from_secs(30);
/// Delay between swap attempts.
const SWAP_RETRY: Duration = Duration::from_millis(500);

struct Args {
    pid: Option<u32>,
    new: Option<PathBuf>,
    target: Option<PathBuf>,
    relaunch: bool,
    log: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut args = Args {
        pid: None,
        new: None,
        target: None,
        relaunch: false,
        log: None,
    };
    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pid" => args.pid = it.next().and_then(|v| v.parse().ok()),
            "--new" => args.new = it.next().map(PathBuf::from),
            "--target" => args.target = it.next().map(PathBuf::from),
            "--relaunch" => args.relaunch = true,
            "--log" => args.log = it.next().map(PathBuf::from),
            _ => {}
        }
    }
    args
}

struct Logger {
    path: PathBuf,
}

impl Logger {
    fn new(path: PathBuf) -> Self {
        Logger { path }
    }

    fn line(&self, msg: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "[{ts}] {msg}");
        }
    }
}

fn default_log_path() -> PathBuf {
    if let Ok(appdata) = env::var("APPDATA") {
        let dir = PathBuf::from(appdata).join("Deimos").join("update");
        let _ = fs::create_dir_all(&dir);
        return dir.join("updater.log");
    }
    env::temp_dir().join("deimos-updater.log")
}

/// Block until the process with `pid` exits, or `timeout` elapses.
fn wait_for_pid(pid: u32, timeout: Duration, log: &Logger) {
    // SAFETY: standard Win32 calls; the handle is closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if handle.is_null() {
            log.line("Parent process not found (already exited).");
            return;
        }
        let res = WaitForSingleObject(handle, timeout.as_millis() as u32);
        CloseHandle(handle);
        if res == WAIT_OBJECT_0 {
            log.line("Parent process exited.");
        } else {
            log.line(&format!(
                "WARN: wait returned {res} (timeout or error); proceeding anyway."
            ));
        }
    }
}

/// Copy `new` over `target`, retrying until `SWAP_DEADLINE` to ride out
/// lingering locks. Returns true on success.
fn swap_with_retries(new: &Path, target: &Path, log: &Logger) -> bool {
    let deadline = Instant::now() + SWAP_DEADLINE;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match fs::copy(new, target) {
            Ok(_) => return true,
            Err(e) => {
                log.line(&format!("Swap attempt {attempt} failed: {e}"));
                if Instant::now() >= deadline {
                    return false;
                }
                sleep(SWAP_RETRY);
            }
        }
    }
}

fn main() {
    let args = parse_args();
    let log = Logger::new(args.log.clone().unwrap_or_else(default_log_path));
    log.line("=== deimos-updater started ===");

    let new = match args.new {
        Some(ref p) => p.clone(),
        None => {
            log.line("FATAL: --new not provided.");
            std::process::exit(2);
        }
    };
    let target = match args.target {
        Some(ref p) => p.clone(),
        None => {
            log.line("FATAL: --target not provided.");
            std::process::exit(2);
        }
    };

    if !new.exists() {
        log.line(&format!("FATAL: new exe missing: {}", new.display()));
        std::process::exit(3);
    }

    if let Some(pid) = args.pid {
        log.line(&format!("Waiting for parent pid {pid} to exit..."));
        wait_for_pid(pid, PARENT_WAIT, &log);
    } else {
        log.line("No --pid provided; skipping wait.");
    }

    sleep(GRACE);

    if !swap_with_retries(&new, &target, &log) {
        log.line(&format!(
            "FATAL: could not replace target after retries: {}",
            target.display()
        ));
        std::process::exit(4);
    }
    log.line(&format!("Swap successful -> {}", target.display()));

    if args.relaunch {
        log.line(&format!("Relaunching {}", target.display()));
        match Command::new(&target).spawn() {
            Ok(_) => log.line("Relaunch spawned."),
            Err(e) => log.line(&format!("WARN: relaunch failed: {e}")),
        }
    }

    // Best-effort cleanup of the downloaded payload.
    let _ = fs::remove_file(&new);
    log.line("=== deimos-updater finished ===");
}
