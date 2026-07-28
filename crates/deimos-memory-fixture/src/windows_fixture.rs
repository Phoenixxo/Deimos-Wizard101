use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of};
use std::ptr::{self, NonNull};

use deimos_memory_fixture::{
    FixtureMetadata, LifecycleMetadata, MemoryProtection, MemoryRegionMetadata, PatternKind,
    PatternMetadata, PointerChainMetadata, PrimitiveMetadata, FIXTURE_SCHEMA_VERSION,
    MUTATION_ENABLED, READY_PREFIX, SHUTDOWN_COMMAND, STOPPED_LINE,
};
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READONLY,
    PAGE_READWRITE,
};

const ALLOCATION_SIZE: usize = 4096;
const READ_ONLY_REGION: &str = "read_only_values";
const READ_WRITE_REGION: &str = "read_write_values";
const EXACT_PATTERN_NAME: &str = "exact_anchor";
const EXACT_PATTERN: [u8; 16] = [
    0x44, 0x4d, 0x53, 0x05, 0x91, 0xa7, 0x2c, 0xe3, 0x6d, 0x11, 0xb8, 0x4f, 0xca, 0x73, 0x20, 0xfe,
];
const WILDCARD_PATTERN: [u8; 16] = [
    0xf3, 0x0d, 0x8a, 0x62, 0x17, 0xcd, 0x49, 0xb0, 0xee, 0x35, 0x74, 0x9a, 0x01, 0xd6, 0xab, 0x58,
];
const WILDCARD_SIGNATURE: &str = "F3 0D ?? 62 17 CD 49 ?? EE 35 74 9A ?? D6 AB 58";

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
        let pointer = unsafe {
            VirtualAlloc(
                None,
                ALLOCATION_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
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
        let mut previous = PAGE_READWRITE;
        unsafe {
            VirtualProtect(
                self.pointer.as_ptr(),
                ALLOCATION_SIZE,
                PAGE_READONLY,
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
}

impl FixtureMemory {
    pub fn create() -> io::Result<(Self, FixtureMetadata)> {
        let read_write = Allocation::read_write()?;
        let node_one_address = read_write.address() + offset_of!(ReadWriteValues, node_one);
        let node_two_address = read_write.address() + offset_of!(ReadWriteValues, node_two);

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
                exact_pattern: EXACT_PATTERN,
                wildcard_pattern: WILDCARD_PATTERN,
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

        let metadata = metadata(read_only.address(), read_write.address());
        Ok((
            Self {
                _read_only: read_only,
                _read_write: read_write,
            },
            metadata,
        ))
    }
}

fn metadata(read_only_address: usize, read_write_address: usize) -> FixtureMetadata {
    FixtureMetadata {
        schema_version: FIXTURE_SCHEMA_VERSION,
        pid: std::process::id(),
        architecture: std::env::consts::ARCH.to_string(),
        pointer_width: size_of::<usize>(),
        mutation_enabled: MUTATION_ENABLED,
        lifecycle: LifecycleMetadata {
            ready_prefix: READY_PREFIX.to_string(),
            shutdown_transport: "stdin_line".to_string(),
            shutdown_command: SHUTDOWN_COMMAND.to_string(),
            stopped_line: STOPPED_LINE.to_string(),
        },
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
                signature: signature(&EXACT_PATTERN),
                expected_matches: 1,
            },
            PatternMetadata {
                name: "wildcard_anchor".to_string(),
                kind: PatternKind::Wildcard,
                region: READ_ONLY_REGION.to_string(),
                offset: offset_of!(ReadOnlyValues, wildcard_pattern),
                signature: WILDCARD_SIGNATURE.to_string(),
                expected_matches: 1,
            },
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

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
