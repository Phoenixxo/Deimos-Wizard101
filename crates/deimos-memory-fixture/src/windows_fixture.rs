use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of};
use std::ptr::{self, NonNull};

use deimos_memory_fixture::{
    FixtureMetadata, MemoryProtection, MemoryRegionMetadata, PatternKind, PatternMetadata,
    PointerChainMetadata, PrimitiveMetadata, FIXTURE_SCHEMA_VERSION, MUTATION_ENABLED,
};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_GUARD,
    PAGE_READONLY, PAGE_READWRITE,
};

const ALLOCATION_SIZE: usize = 4096;
const BOUNDARY_ALLOCATION_SIZE: usize = ALLOCATION_SIZE * 3;
const BOUNDARY_WRITE_SIZE: usize = 16;
const BOUNDARY_BYTE: u8 = 0x5a;
const READ_ONLY_REGION: &str = "read_only_values";
const READ_WRITE_REGION: &str = "read_write_values";
const BOUNDARY_READ_WRITE_REGION: &str = "boundary_read_write";
const BOUNDARY_READ_ONLY_REGION: &str = "boundary_read_only";
const EXACT_PATTERN_NAME: &str = "exact_anchor";
const EXACT_PATTERN_SEED: u64 = 0x4d53_5f45_5841_4354;
const WILDCARD_PATTERN_SEED: u64 = 0x4d53_5f57_494c_4443;
const WILDCARD_INDICES: [usize; 3] = [2, 7, 12];

const VALUE_U8: u8 = 0xa5;
const VALUE_I32: i32 = -123_456_789;
const VALUE_U64: u64 = 0x0123_4567_89ab_cdef;
const VALUE_F32: f32 = 1234.5;
const VALUE_F64: f64 = -98_765.125;
const WRITABLE_SENTINEL: u32 = 0xdec0_adde;
const POINTER_TARGET: u64 = 0xcafe_babe_1020_3040;

#[repr(C)]
struct ReadOnlyValues {
    exact_pattern: [u8; 16],
    wildcard_pattern: [u8; 16],
    core_hook_targets: [[u8; 16]; 6],
    feature_hook_targets: [[u8; 16]; 5],
    feature_hook_auxiliary_targets: [[u8; 8]; 7],
    value_u8: u8,
    padding_after_u8: [u8; 3],
    value_i32: i32,
    value_u64: u64,
    value_f32: f32,
    padding_after_f32: [u8; 4],
    value_f64: f64,
    pointer_root: *const PointerNodeOne,
}

#[repr(C)]
struct PointerNodeOne {
    guard: u64,
    next: *const PointerNodeTwo,
}

#[repr(C)]
struct PointerNodeTwo {
    guard: u64,
    value: u64,
}

#[repr(C)]
struct ReadWriteValues {
    writable_sentinel: u32,
    padding: [u8; 4],
    node_one: PointerNodeOne,
    node_two: PointerNodeTwo,
}

struct Allocation {
    pointer: NonNull<c_void>,
}

impl Allocation {
    fn read_write() -> io::Result<Self> {
        Self::read_write_size(ALLOCATION_SIZE)
    }

    fn read_write_size(size: usize) -> io::Result<Self> {
        let pointer = unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        let pointer = NonNull::new(pointer).ok_or_else(io::Error::last_os_error)?;
        Ok(Self { pointer })
    }

    fn address(&self) -> usize {
        self.pointer.as_ptr() as usize
    }

    unsafe fn write<T>(&self, value: T) {
        debug_assert!(size_of::<T>() <= ALLOCATION_SIZE);
        unsafe {
            ptr::write(self.pointer.as_ptr().cast::<T>(), value);
        }
    }

    fn make_read_only(&self) -> io::Result<()> {
        self.make_range_read_only(0, ALLOCATION_SIZE)
    }

    fn make_range_read_only(&self, offset: usize, size: usize) -> io::Result<()> {
        self.protect_range(offset, size, PAGE_READONLY)
    }

    fn protect_range(
        &self,
        offset: usize,
        size: usize,
        protection: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    ) -> io::Result<()> {
        let mut previous = PAGE_READWRITE;
        unsafe {
            VirtualProtect(
                self.pointer.as_ptr().byte_add(offset),
                size,
                protection,
                &mut previous,
            )
        }
        .map_err(|error| io::Error::other(format!("VirtualProtect failed: {error}")))
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.pointer.as_ptr(), 0, MEM_RELEASE);
        }
    }
}

pub struct FixtureMemory {
    _read_only: Allocation,
    _read_write: Allocation,
    _boundary: Allocation,
}

impl FixtureMemory {
    pub fn create() -> io::Result<(Self, FixtureMetadata)> {
        let read_write = Allocation::read_write()?;
        let node_one_address = read_write.address() + offset_of!(ReadWriteValues, node_one);
        let node_two_address = read_write.address() + offset_of!(ReadWriteValues, node_two);
        let exact_pattern = deterministic_pattern(EXACT_PATTERN_SEED);
        let wildcard_pattern = deterministic_pattern(WILDCARD_PATTERN_SEED);
        let core_hook_targets = core_hook_targets();
        let feature_hook_targets = feature_hook_targets();
        let feature_hook_auxiliary_targets = feature_hook_auxiliary_targets();

        unsafe {
            read_write.write(ReadWriteValues {
                writable_sentinel: WRITABLE_SENTINEL,
                padding: [0; 4],
                node_one: PointerNodeOne {
                    guard: 0x1111_2222_3333_4444,
                    next: node_two_address as *const PointerNodeTwo,
                },
                node_two: PointerNodeTwo {
                    guard: 0x5555_6666_7777_8888,
                    value: POINTER_TARGET,
                },
            });
        }

        let read_only = Allocation::read_write()?;
        unsafe {
            read_only.write(ReadOnlyValues {
                exact_pattern,
                wildcard_pattern,
                core_hook_targets,
                feature_hook_targets,
                feature_hook_auxiliary_targets,
                value_u8: VALUE_U8,
                padding_after_u8: [0; 3],
                value_i32: VALUE_I32,
                value_u64: VALUE_U64,
                value_f32: VALUE_F32,
                padding_after_f32: [0; 4],
                value_f64: VALUE_F64,
                pointer_root: node_one_address as *const PointerNodeOne,
            });
        }
        read_only.make_read_only()?;

        let boundary = Allocation::read_write_size(BOUNDARY_ALLOCATION_SIZE)?;
        unsafe {
            ptr::write_bytes(
                boundary.pointer.as_ptr().cast::<u8>(),
                BOUNDARY_BYTE,
                BOUNDARY_ALLOCATION_SIZE,
            );
        }
        boundary.make_range_read_only(ALLOCATION_SIZE, ALLOCATION_SIZE)?;
        boundary.protect_range(
            ALLOCATION_SIZE * 2,
            ALLOCATION_SIZE,
            PAGE_READWRITE | PAGE_GUARD,
        )?;

        let metadata = metadata(
            read_only.address(),
            read_write.address(),
            boundary.address(),
            &exact_pattern,
            &wildcard_pattern,
        );
        Ok((
            Self {
                _read_only: read_only,
                _read_write: read_write,
                _boundary: boundary,
            },
            metadata,
        ))
    }
}

fn metadata(
    read_only_address: usize,
    read_write_address: usize,
    boundary_address: usize,
    exact_pattern: &[u8; 16],
    wildcard_pattern: &[u8; 16],
) -> FixtureMetadata {
    FixtureMetadata {
        schema_version: FIXTURE_SCHEMA_VERSION,
        pid: std::process::id(),
        architecture: std::env::consts::ARCH.to_string(),
        pointer_width: size_of::<usize>(),
        mutation_enabled: MUTATION_ENABLED,
        mutation_boundary: Some(deimos_memory_fixture::MutationBoundaryMetadata {
            write_address: format!(
                "{:#x}",
                boundary_address + ALLOCATION_SIZE - (BOUNDARY_WRITE_SIZE / 2)
            ),
            write_size: BOUNDARY_WRITE_SIZE,
            writable_page_address: format!("{boundary_address:#x}"),
            read_only_page_address: format!("{:#x}", boundary_address + ALLOCATION_SIZE),
            modified_page_address: format!("{:#x}", boundary_address + ALLOCATION_SIZE * 2),
            page_size: ALLOCATION_SIZE,
            expected_byte: BOUNDARY_BYTE,
        }),
        regions: vec![
            MemoryRegionMetadata {
                name: READ_ONLY_REGION.to_string(),
                address: format!("{read_only_address:#x}"),
                size: ALLOCATION_SIZE,
                protection: MemoryProtection::ReadOnly,
            },
            MemoryRegionMetadata {
                name: READ_WRITE_REGION.to_string(),
                address: format!("{read_write_address:#x}"),
                size: ALLOCATION_SIZE,
                protection: MemoryProtection::ReadWrite,
            },
            MemoryRegionMetadata {
                name: BOUNDARY_READ_WRITE_REGION.to_string(),
                address: format!("{boundary_address:#x}"),
                size: ALLOCATION_SIZE,
                protection: MemoryProtection::ReadWrite,
            },
            MemoryRegionMetadata {
                name: BOUNDARY_READ_ONLY_REGION.to_string(),
                address: format!("{:#x}", boundary_address + ALLOCATION_SIZE),
                size: ALLOCATION_SIZE,
                protection: MemoryProtection::ReadOnly,
            },
        ],
        primitives: vec![
            primitive(
                "unsigned_byte",
                "u8",
                READ_ONLY_REGION,
                offset_of!(ReadOnlyValues, value_u8),
                &VALUE_U8.to_le_bytes(),
                "0xa5",
            ),
            primitive(
                "signed_integer",
                "i32",
                READ_ONLY_REGION,
                offset_of!(ReadOnlyValues, value_i32),
                &VALUE_I32.to_le_bytes(),
                "-123456789",
            ),
            primitive(
                "unsigned_integer",
                "u64",
                READ_ONLY_REGION,
                offset_of!(ReadOnlyValues, value_u64),
                &VALUE_U64.to_le_bytes(),
                "0x0123456789abcdef",
            ),
            primitive(
                "single_precision",
                "f32",
                READ_ONLY_REGION,
                offset_of!(ReadOnlyValues, value_f32),
                &VALUE_F32.to_le_bytes(),
                "1234.5",
            ),
            primitive(
                "double_precision",
                "f64",
                READ_ONLY_REGION,
                offset_of!(ReadOnlyValues, value_f64),
                &VALUE_F64.to_le_bytes(),
                "-98765.125",
            ),
            primitive(
                "writable_sentinel",
                "u32",
                READ_WRITE_REGION,
                offset_of!(ReadWriteValues, writable_sentinel),
                &WRITABLE_SENTINEL.to_le_bytes(),
                "0xdec0adde",
            ),
        ],
        patterns: vec![
            PatternMetadata {
                name: EXACT_PATTERN_NAME.to_string(),
                kind: PatternKind::Exact,
                region: READ_ONLY_REGION.to_string(),
                offset: offset_of!(ReadOnlyValues, exact_pattern),
                signature: signature(exact_pattern),
                expected_matches: 1,
            },
            PatternMetadata {
                name: "wildcard_anchor".to_string(),
                kind: PatternKind::Wildcard,
                region: READ_ONLY_REGION.to_string(),
                offset: offset_of!(ReadOnlyValues, wildcard_pattern),
                signature: wildcard_signature(wildcard_pattern),
                expected_matches: 1,
            },
            core_hook_pattern("core_hook_client", 0),
            core_hook_pattern("core_hook_player", 1),
            core_hook_pattern("core_hook_quest", 2),
            core_hook_pattern("core_hook_player_stat", 3),
            core_hook_pattern("core_hook_root_window", 4),
            core_hook_pattern("core_hook_render_context", 5),
            feature_hook_pattern("feature_hook_movement_teleport", 0),
            feature_hook_pattern("feature_hook_mouseless_cursor", 1),
            feature_hook_pattern("feature_hook_chat", 2),
            feature_hook_pattern("feature_hook_chat_send", 3),
            feature_hook_pattern("feature_hook_dance_game_moves", 4),
            feature_hook_auxiliary_pattern("feature_movement_forward", 0),
            feature_hook_auxiliary_pattern("feature_movement_backward", 1),
            feature_hook_auxiliary_pattern("feature_movement_collision_one", 2),
            feature_hook_auxiliary_pattern("feature_movement_collision_two", 3),
            feature_hook_auxiliary_pattern("feature_mouse_set_cursor", 4),
            feature_hook_auxiliary_pattern("feature_mouse_toggle_one", 5),
            feature_hook_auxiliary_pattern("feature_mouse_toggle_two", 6),
        ],
        pointer_chains: vec![PointerChainMetadata {
            name: "two_hop_u64".to_string(),
            root_pattern: EXACT_PATTERN_NAME.to_string(),
            offsets: vec![
                offset_of!(ReadOnlyValues, pointer_root),
                offset_of!(PointerNodeOne, next),
                offset_of!(PointerNodeTwo, value),
            ],
            dereference_count: 2,
            target_region: READ_WRITE_REGION.to_string(),
            target_type: "u64".to_string(),
            expected: "0xcafebabe10203040".to_string(),
            expected_bytes: bytes_hex(&POINTER_TARGET.to_le_bytes()),
        }],
    }
}

fn core_hook_targets() -> [[u8; 16]; 6] {
    let mut targets = [[0u8; 16]; 6];
    for (index, target) in targets.iter_mut().enumerate() {
        target[0] = 0xb8;
        target[1] = (index + 1) as u8;
        target[2] = 0xd0;
        target[3] = 0xc0;
        target[4] = 0;
        for byte in &mut target[5..15] {
            *byte = 0x90;
        }
        target[15] = 0xc3;
    }
    targets
}

fn core_hook_pattern(name: &str, index: usize) -> PatternMetadata {
    let bytes = core_hook_targets()[index];
    PatternMetadata {
        name: name.to_string(),
        kind: PatternKind::Exact,
        region: READ_ONLY_REGION.to_string(),
        offset: offset_of!(ReadOnlyValues, core_hook_targets) + index * bytes.len(),
        signature: signature(&bytes),
        expected_matches: 1,
    }
}

fn feature_hook_targets() -> [[u8; 16]; 5] {
    let mut targets = [[0u8; 16]; 5];
    for (index, target) in targets.iter_mut().enumerate() {
        target[0] = 0xb8;
        target[1] = (index + 1) as u8;
        target[2] = 0xd1;
        target[3] = 0xc0;
        target[4] = 0;
        for byte in &mut target[5..15] {
            *byte = 0x90;
        }
        target[15] = 0xc3;
    }
    targets
}

fn feature_hook_pattern(name: &str, index: usize) -> PatternMetadata {
    let bytes = feature_hook_targets()[index];
    PatternMetadata {
        name: name.to_string(),
        kind: PatternKind::Exact,
        region: READ_ONLY_REGION.to_string(),
        offset: offset_of!(ReadOnlyValues, feature_hook_targets) + index * bytes.len(),
        signature: signature(&bytes),
        expected_matches: 1,
    }
}

fn feature_hook_auxiliary_targets() -> [[u8; 8]; 7] {
    let mut targets = [[0u8; 8]; 7];
    for (target, marker) in targets
        .iter_mut()
        .zip([0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23])
    {
        *target = [0xb8, marker, 0xf1, 0xc7, 0x00, 0x90, 0x90, 0x90];
    }
    targets
}

fn feature_hook_auxiliary_pattern(name: &str, index: usize) -> PatternMetadata {
    let bytes = feature_hook_auxiliary_targets()[index];
    PatternMetadata {
        name: name.to_string(),
        kind: PatternKind::Exact,
        region: READ_ONLY_REGION.to_string(),
        offset: offset_of!(ReadOnlyValues, feature_hook_auxiliary_targets) + index * bytes.len(),
        signature: signature(&bytes),
        expected_matches: 1,
    }
}

fn deterministic_pattern(seed: u64) -> [u8; 16] {
    // A volatile read prevents the compiler from materializing the generated
    // pattern as a contiguous constant in the executable image.
    let mut state = unsafe { ptr::read_volatile(&seed) };
    let mut bytes = [0u8; 16];
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state >> 56) as u8;
    }
    bytes
}

fn primitive(
    name: &str,
    data_type: &str,
    region: &str,
    offset: usize,
    expected_bytes: &[u8],
    expected: &str,
) -> PrimitiveMetadata {
    PrimitiveMetadata {
        name: name.to_string(),
        data_type: data_type.to_string(),
        region: region.to_string(),
        offset,
        size: expected_bytes.len(),
        expected: expected.to_string(),
        expected_bytes: bytes_hex(expected_bytes),
    }
}

fn signature(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn wildcard_signature(bytes: &[u8]) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if WILDCARD_INDICES.contains(&index) {
                "??".to_string()
            } else {
                format!("{byte:02X}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
