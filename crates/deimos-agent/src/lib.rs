use deimos_core::{ProbeReport, ProbeRequest};

#[cfg(not(windows))]
use deimos_core::WINDOWS_AGENT_TARGET;

#[cfg(windows)]
mod windows_probe;

#[cfg(windows)]
pub fn run(request: &ProbeRequest) -> ProbeReport {
    windows_probe::run(request)
}

#[cfg(not(windows))]
pub fn run(request: &ProbeRequest) -> ProbeReport {
    let mut report = ProbeReport::new(request);
    report.errors.push(
        "This probe must be built for Windows and run inside the Wizard101 CrossOver bottle."
            .to_string(),
    );
    report.build_target = Some(WINDOWS_AGENT_TARGET.to_string());
    report
}
