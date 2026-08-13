use serde::{Deserialize, Serialize};

pub const FIXTURE_SCHEMA_VERSION: u32 = 1;
pub const MUTATION_ENABLED: bool = true;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FixtureMetadata {
    pub schema_version: u32,
    pub pid: u32,
    pub architecture: String,
    pub pointer_width: usize,
    pub mutation_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_boundary: Option<MutationBoundaryMetadata>,
    pub regions: Vec<MemoryRegionMetadata>,
    pub primitives: Vec<PrimitiveMetadata>,
    pub patterns: Vec<PatternMetadata>,
    pub pointer_chains: Vec<PointerChainMetadata>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MutationBoundaryMetadata {
    pub write_address: String,
    pub write_size: usize,
    pub writable_page_address: String,
    pub read_only_page_address: String,
    pub modified_page_address: String,
    pub page_size: usize,
    pub expected_byte: u8,
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
        FixtureMetadata, MutationBoundaryMetadata, FIXTURE_SCHEMA_VERSION, MUTATION_ENABLED,
    };

    #[test]
    fn metadata_round_trips_with_mutation_enabled() {
        let metadata = FixtureMetadata {
            schema_version: FIXTURE_SCHEMA_VERSION,
            pid: 42,
            architecture: "test".to_string(),
            pointer_width: 8,
            mutation_enabled: MUTATION_ENABLED,
            mutation_boundary: Some(MutationBoundaryMetadata {
                write_address: "0x2000".to_string(),
                write_size: 16,
                writable_page_address: "0x1000".to_string(),
                read_only_page_address: "0x2000".to_string(),
                modified_page_address: "0x3000".to_string(),
                page_size: 4096,
                expected_byte: 0x5a,
            }),
            regions: Vec::new(),
            primitives: Vec::new(),
            patterns: Vec::new(),
            pointer_chains: Vec::new(),
        };

        let json = serde_json::to_string(&metadata).expect("metadata should serialize");
        let decoded: FixtureMetadata =
            serde_json::from_str(&json).expect("metadata should deserialize");

        assert_eq!(decoded, metadata);
        assert!(decoded.mutation_enabled);
    }

    #[test]
    fn metadata_without_a_mutation_boundary_remains_schema_v1_compatible() {
        let legacy = serde_json::json!({
            "schema_version": FIXTURE_SCHEMA_VERSION,
            "pid": 42,
            "architecture": "test",
            "pointer_width": 8,
            "mutation_enabled": false,
            "regions": [],
            "primitives": [],
            "patterns": [],
            "pointer_chains": []
        });

        let decoded: FixtureMetadata =
            serde_json::from_value(legacy).expect("legacy schema v1 metadata should deserialize");
        assert_eq!(decoded.schema_version, FIXTURE_SCHEMA_VERSION);
        assert!(decoded.mutation_boundary.is_none());
        assert!(
            serde_json::to_value(decoded)
                .expect("legacy metadata should reserialize")
                .get("mutation_boundary")
                .is_none(),
            "absent optional mutation metadata should remain omitted"
        );
    }
}
