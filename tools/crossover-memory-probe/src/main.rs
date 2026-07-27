#[cfg(any(windows, test))]
mod pe;

#[cfg(windows)]
mod windows_probe;

#[cfg(windows)]
fn main() {
    let target_process = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "WizardGraphicalClient.exe".to_string());
    let report = windows_probe::run(&target_process);
    let success = report.success;

    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to serialize probe report: {error}");
            std::process::exit(3);
        }
    }

    if !success {
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {
    let report = serde_json::json!({
        "schema_version": 1,
        "success": false,
        "error": "This probe must be built for Windows and run inside the Wizard101 CrossOver bottle.",
        "build_target": "x86_64-pc-windows-msvc"
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("static report should serialize")
    );
    std::process::exit(2);
}
