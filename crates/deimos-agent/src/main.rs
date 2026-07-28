use deimos_agent::run;
use deimos_core::ProbeRequest;

fn main() {
    let target_process = std::env::args()
        .nth(1)
        .unwrap_or_else(|| deimos_core::DEFAULT_TARGET_PROCESS.to_string());
    let request = ProbeRequest::new(target_process);
    let report = run(&request);
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
