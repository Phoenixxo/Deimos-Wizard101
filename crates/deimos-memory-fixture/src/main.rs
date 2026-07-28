#[cfg(windows)]
use std::io::{self, BufRead, Write};

#[cfg(windows)]
mod windows_fixture;

#[cfg(windows)]
fn main() {
    use deimos_memory_fixture::{READY_PREFIX, SHUTDOWN_COMMAND, STOPPED_LINE};
    use windows_fixture::FixtureMemory;

    let (fixture, metadata) = FixtureMemory::create()
        .unwrap_or_else(|error| exit_with_error(&format!("failed to create fixture: {error}")));
    let json = serde_json::to_string(&metadata)
        .unwrap_or_else(|error| exit_with_error(&format!("failed to serialize metadata: {error}")));

    println!("{READY_PREFIX}{json}");
    io::stdout()
        .flush()
        .unwrap_or_else(|error| exit_with_error(&format!("failed to publish metadata: {error}")));

    for line in io::stdin().lock().lines() {
        let line =
            line.unwrap_or_else(|error| exit_with_error(&format!("failed to read stdin: {error}")));
        if line.trim() == SHUTDOWN_COMMAND {
            break;
        }
        eprintln!("ignored fixture command: {}", line.trim());
    }

    drop(fixture);
    println!("{STOPPED_LINE}");
    io::stdout()
        .flush()
        .unwrap_or_else(|error| exit_with_error(&format!("failed to publish shutdown: {error}")));
}

#[cfg(not(windows))]
fn main() {
    exit_with_error("deimos-memory-fixture is supported only on Windows");
}

fn exit_with_error(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2);
}
