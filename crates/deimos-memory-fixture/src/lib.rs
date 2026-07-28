use serde::{Deserialize, Serialize};

pub const FIXTURE_SCHEMA_VERSION: u32 = 1;
pub const MUTATION_ENABLED: bool = false;
pub const READY_PREFIX: &str = "DEIMOS_MEMORY_FIXTURE=";
pub const STOPPED_LINE: &str = "DEIMOS_MEMORY_FIXTURE_STOPPED";
pub const SHUTDOWN_COMMAND: &str = "shutdown";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FixtureMetadata {
    pub schema_version: u32,
    pub pid: u32,
    pub architecture: String,
    pub pointer_width: usize,
    pub mutation_enabled: bool,
    pub lifecycle: LifecycleMetadata,
    pub regions: Vec<MemoryRegionMetadata>,
    pub primitives: Vec<PrimitiveMetadata>,
    pub patterns: Vec<PatternMetadata>,
    pub pointer_chains: Vec<PointerChainMetadata>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LifecycleMetadata {
    pub ready_prefix: String,
    pub shutdown_transport: String,
    pub shutdown_command: String,
    pub stopped_line: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryProtection {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryRegionMetadata {
    pub name: String,
    pub address: String,
    pub size: usize,
    pub protection: MemoryProtection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrimitiveMetadata {
    pub name: String,
    pub data_type: String,
    pub region: String,
    pub offset: usize,
    pub size: usize,
    pub expected: String,
    pub expected_bytes: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    Exact,
    Wildcard,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatternMetadata {
    pub name: String,
    pub kind: PatternKind,
    pub region: String,
    pub offset: usize,
    pub signature: String,
    pub expected_matches: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PointerChainMetadata {
    pub name: String,
    pub root_pattern: String,
    pub offsets: Vec<usize>,
    pub dereference_count: usize,
    pub target_region: String,
    pub target_type: String,
    pub expected: String,
    pub expected_bytes: String,
}

#[cfg(test)]
mod tests {
    use super::{
        FixtureMetadata, LifecycleMetadata, FIXTURE_SCHEMA_VERSION, MUTATION_ENABLED, READY_PREFIX,
        SHUTDOWN_COMMAND, STOPPED_LINE,
    };

    #[test]
    fn lifecycle_and_mutation_contract_is_explicit() {
        let metadata = FixtureMetadata {
            schema_version: FIXTURE_SCHEMA_VERSION,
            pid: 42,
            architecture: "test".to_string(),
            pointer_width: 8,
            mutation_enabled: MUTATION_ENABLED,
            lifecycle: LifecycleMetadata {
                ready_prefix: READY_PREFIX.to_string(),
                shutdown_transport: "stdin_line".to_string(),
                shutdown_command: SHUTDOWN_COMMAND.to_string(),
                stopped_line: STOPPED_LINE.to_string(),
            },
            regions: Vec::new(),
            primitives: Vec::new(),
            patterns: Vec::new(),
            pointer_chains: Vec::new(),
        };

        let json = serde_json::to_string(&metadata).expect("metadata should serialize");
        let decoded: FixtureMetadata =
            serde_json::from_str(&json).expect("metadata should deserialize");

        assert_eq!(decoded, metadata);
        assert!(!decoded.mutation_enabled);
        assert_eq!(decoded.lifecycle.shutdown_command, SHUTDOWN_COMMAND);
    }
}
