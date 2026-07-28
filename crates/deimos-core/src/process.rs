use serde::{Deserialize, Serialize};

pub const CAPABILITY_PROCESS_READ_ONLY: &str = "process.read_only.v1";
pub const OP_PROCESS_LIST: &str = "process.list";
pub const OP_PROCESS_OPEN: &str = "process.open";
pub const OP_PROCESS_CLOSE: &str = "process.close";
pub const OP_PROCESS_STATUS: &str = "process.status";
pub const OP_MODULE_LIST: &str = "module.list";

pub const WIZARD101_EXECUTABLE: &str = "WizardGraphicalClient.exe";
pub const MEMORY_FIXTURE_EXECUTABLE: &str = "deimos-memory-fixture.exe";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessKind {
    Wizard101,
    MemoryFixture,
    Other,
}

pub fn classify_process(name: &str) -> ProcessKind {
    if name.eq_ignore_ascii_case(WIZARD101_EXECUTABLE) {
        ProcessKind::Wizard101
    } else if name.eq_ignore_ascii_case(MEMORY_FIXTURE_EXECUTABLE) {
        ProcessKind::MemoryFixture
    } else {
        ProcessKind::Other
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessIdentity {
    /// PID in the agent's Windows process namespace. Under Wine/CrossOver this
    /// is the Wine-internal PID, not a translated macOS host PID.
    pub pid: u32,
    /// Windows FILETIME creation value encoded as decimal text to avoid JSON
    /// integer precision loss in Python or JavaScript consumers.
    pub creation_time_100ns: String,
    pub executable_path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessDescriptor {
    pub pid: u32,
    pub name: String,
    pub kind: ProcessKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ProcessIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModuleDescriptor {
    pub name: String,
    pub executable_path: String,
    pub base_address: String,
    pub size: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProcessSessionId(pub String);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSessionState {
    Open,
    Closed,
    Exited,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListProcessesRequest {
    /// Optional case-insensitive executable-name filter. An empty list returns
    /// every process visible to the Windows/Wine agent.
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListProcessesResponse {
    pub processes: Vec<ProcessDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenProcessRequest {
    pub pid: u32,
    /// When supplied from a previous listing, opening fails if the PID was
    /// reused or the executable changed between list and open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_identity: Option<ProcessIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessSessionResponse {
    pub session_id: ProcessSessionId,
    pub state: ProcessSessionState,
    pub process: ProcessDescriptor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionRequest {
    pub session_id: ProcessSessionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListModulesResponse {
    pub session_id: ProcessSessionId,
    pub process: ProcessDescriptor,
    pub modules: Vec<ModuleDescriptor>,
}

#[cfg(test)]
mod tests {
    use super::{
        classify_process, ProcessIdentity, ProcessKind, MEMORY_FIXTURE_EXECUTABLE,
        WIZARD101_EXECUTABLE,
    };

    #[test]
    fn identifies_supported_targets_case_insensitively() {
        assert_eq!(
            classify_process(&WIZARD101_EXECUTABLE.to_ascii_lowercase()),
            ProcessKind::Wizard101
        );
        assert_eq!(
            classify_process(&MEMORY_FIXTURE_EXECUTABLE.to_ascii_uppercase()),
            ProcessKind::MemoryFixture
        );
        assert_eq!(classify_process("notepad.exe"), ProcessKind::Other);
    }

    #[test]
    fn identity_creation_time_is_json_precision_safe_text() {
        let identity = ProcessIdentity {
            pid: 336,
            creation_time_100ns: "134145612345678901".to_string(),
            executable_path: r"C:\Wizard101\WizardGraphicalClient.exe".to_string(),
        };

        let json = serde_json::to_string(&identity).expect("identity should serialize");
        assert!(json.contains(r#""creation_time_100ns":"134145612345678901""#));
        assert_eq!(
            serde_json::from_str::<ProcessIdentity>(&json).expect("identity should deserialize"),
            identity
        );
    }
}
