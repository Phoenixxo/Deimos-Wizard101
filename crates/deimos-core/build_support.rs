use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_BUILD_ID_LENGTH: usize = 128;

/// Inputs shared by the native host and managed agent artifacts.
///
/// Keep this list source-only: watching `target` or another generated output
/// directory would create an endless Cargo rebuild loop.
const ARTIFACT_INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "crates/deimos-core/Cargo.toml",
    "crates/deimos-core/build.rs",
    "crates/deimos-core/build_support.rs",
    "crates/deimos-core/src",
    "crates/deimos-agent/Cargo.toml",
    "crates/deimos-agent/src",
    "crates/deimos-native/Cargo.toml",
    "crates/deimos-native/build.rs",
    "crates/deimos-native/src",
];

pub fn sanitize_build_id(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_BUILD_ID_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some(value.to_string())
}

pub fn artifact_watch_paths(repository: &Path) -> Vec<PathBuf> {
    ARTIFACT_INPUTS
        .iter()
        .map(|path| repository.join(path))
        .collect()
}

pub fn git_control_paths(repository: &Path) -> Vec<PathBuf> {
    let mut paths = ["HEAD", "index", "packed-refs"]
        .iter()
        .filter_map(|name| git_path(repository, name))
        .collect::<Vec<_>>();

    if let Some(reference) = command_output(repository, &["symbolic-ref", "-q", "HEAD"]) {
        if let Some(path) = git_path(repository, reference.trim()) {
            paths.push(path);
        }
    }

    paths.sort();
    paths.dedup();
    paths
}

pub fn derived_build_id(repository: &Path) -> io::Result<String> {
    let source_digest = source_digest(repository)?;
    Ok(match git_revision(repository) {
        Some(revision) => format!("git-{revision}-source-{source_digest}"),
        None => format!("source-{source_digest}"),
    })
}

pub fn source_digest(repository: &Path) -> io::Result<String> {
    let files = artifact_source_files(repository)?;
    let mut hasher = Sha256::new();
    for path in files {
        let relative = path.strip_prefix(repository).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("artifact input escaped repository: {}", path.display()),
            )
        })?;
        let relative = portable_relative_path(relative)?;
        let contents = fs::read(&path)?;
        hash_field(&mut hasher, relative.as_bytes());
        hash_field(&mut hasher, &contents);
    }
    Ok(hex_digest(hasher.finalize()))
}

fn artifact_source_files(repository: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for input in ARTIFACT_INPUTS {
        collect_files(&repository.join(input), &mut files)?;
    }
    files.sort_by(|left, right| {
        portable_relative_path(left.strip_prefix(repository).unwrap_or(left))
            .unwrap_or_else(|_| left.to_string_lossy().into_owned())
            .cmp(
                &portable_relative_path(right.strip_prefix(repository).unwrap_or(right))
                    .unwrap_or_else(|_| right.to_string_lossy().into_owned()),
            )
    });
    files.dedup();
    Ok(files)
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "artifact input is not a file or directory: {}",
                path.display()
            ),
        ));
    }

    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        collect_files(&entry.path(), files)?;
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> io::Result<String> {
    let mut result = String::new();
    for component in path.components() {
        let component = component.as_os_str().to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("artifact path is not UTF-8: {}", path.display()),
            )
        })?;
        if !result.is_empty() {
            result.push('/');
        }
        result.push_str(component);
    }
    Ok(result)
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn git_revision(repository: &Path) -> Option<String> {
    let revision = command_output(repository, &["rev-parse", "--verify", "HEAD"])?;
    let revision = revision.trim();
    (revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| revision.to_ascii_lowercase())
}

fn git_path(repository: &Path, name: &str) -> Option<PathBuf> {
    let output = command_output(repository, &["rev-parse", "--git-path", name])?;
    let path = PathBuf::from(output.trim());
    Some(if path.is_absolute() {
        path
    } else {
        repository.join(path)
    })
}

fn command_output(repository: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    message_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            message_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.message_len = self.message_len.wrapping_add(input.len() as u64);
        if self.buffer_len != 0 {
            let required = 64 - self.buffer_len;
            let copied = required.min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_len += copied;
            input = &input[copied..];
            if self.buffer_len == 64 {
                compress(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64].try_into().expect("block length is fixed");
            compress(&mut self.state, block);
            input = &input[64..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.message_len.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            compress(&mut self.state, &self.buffer);
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.buffer);

        let mut output = [0; 32];
        for (chunk, value) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        output
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const ROUND_CONSTANTS: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut schedule = [0u32; 64];
    for (index, chunk) in block.chunks_exact(4).enumerate() {
        schedule[index] = u32::from_be_bytes(chunk.try_into().expect("word length is fixed"));
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let upper = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let first = h
            .wrapping_add(upper)
            .wrapping_add(choose)
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let lower = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let second = lower.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::{
        artifact_watch_paths, derived_build_id, git_control_paths, hex_digest, sanitize_build_id,
        source_digest, Sha256, ARTIFACT_INPUTS,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn sanitizes_explicit_build_ids() {
        assert_eq!(
            sanitize_build_id(" release-2026.07_29 "),
            Some("release-2026.07_29".to_string())
        );
        assert_eq!(sanitize_build_id(""), None);
        assert_eq!(sanitize_build_id("contains spaces"), None);
        assert_eq!(sanitize_build_id("bad/slash"), None);
        assert_eq!(sanitize_build_id(&"x".repeat(129)), None);
    }

    #[test]
    fn sha256_matches_the_standard_vector() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        assert_eq!(
            hex_digest(hasher.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn gitless_identity_is_content_derived_and_core_changes_invalidate_it() {
        let first = Fixture::new("gitless-first");
        let second = Fixture::new("gitless-second");
        populate_source(first.path());
        populate_source(second.path());

        let initial = derived_build_id(first.path()).expect("identity should be derived");
        assert!(initial.starts_with("source-"));
        assert_eq!(
            initial,
            derived_build_id(second.path()).expect("same source should have the same identity")
        );

        fs::write(
            first.path().join("crates/deimos-core/src/lib.rs"),
            b"core changed",
        )
        .expect("core source should change");
        let changed = derived_build_id(first.path()).expect("changed identity should derive");
        assert_ne!(initial, changed);
    }

    #[test]
    fn source_hashing_is_sorted_and_path_stable() {
        let first = Fixture::new("ordered");
        let second = Fixture::new("reverse");
        populate_source(first.path());
        for input in ARTIFACT_INPUTS.iter().rev() {
            populate_input(second.path(), input);
        }

        assert_eq!(
            source_digest(first.path()).expect("first digest should compute"),
            source_digest(second.path()).expect("second digest should compute")
        );
        assert!(artifact_watch_paths(first.path())
            .iter()
            .all(|path| !path.ends_with("target")));
    }

    #[test]
    fn clean_and_dirty_git_sources_have_distinct_identities() {
        if !git_available() {
            return;
        }
        let fixture = Fixture::new("git-dirty");
        populate_source(fixture.path());
        initialize_git(fixture.path());

        let clean = derived_build_id(fixture.path()).expect("clean identity should derive");
        assert!(clean.starts_with("git-"));
        fs::write(
            fixture.path().join("crates/deimos-core/src/lib.rs"),
            b"dirty core source",
        )
        .expect("core source should change");
        let dirty = derived_build_id(fixture.path()).expect("dirty identity should derive");
        assert_ne!(clean, dirty);
    }

    #[test]
    fn linked_worktree_git_paths_resolve_outside_the_checkout_git_file() {
        if !git_available() {
            return;
        }
        let primary = Fixture::new("primary-worktree");
        populate_source(primary.path());
        initialize_git(primary.path());
        let linked = Fixture::new_empty("linked-worktree");
        run_git(
            primary.path(),
            &[
                "worktree",
                "add",
                "--detach",
                linked
                    .path()
                    .to_str()
                    .expect("fixture path should be UTF-8"),
                "HEAD",
            ],
        );

        let paths = git_control_paths(linked.path());
        let worktree_paths = paths
            .iter()
            .filter(|path| path.ends_with("HEAD") || path.ends_with("index"))
            .collect::<Vec<_>>();
        assert_eq!(worktree_paths.len(), 2);
        assert!(worktree_paths.iter().all(|path| path.exists()));
        assert!(worktree_paths
            .iter()
            .all(|path| path.to_string_lossy().contains("worktrees")));
    }

    fn populate_source(repository: &Path) {
        for input in ARTIFACT_INPUTS {
            populate_input(repository, input);
        }
    }

    fn populate_input(repository: &Path, input: &str) {
        let path = repository.join(input);
        if Path::new(input).extension().is_some() {
            fs::create_dir_all(path.parent().expect("input should have a parent"))
                .expect("fixture parent should be created");
            fs::write(&path, format!("fixture:{input}\n")).expect("fixture file should be written");
        } else {
            fs::create_dir_all(&path).expect("fixture source directory should be created");
            fs::write(path.join("fixture.rs"), format!("fixture:{input}\n"))
                .expect("fixture source should be written");
        }
    }

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn initialize_git(repository: &Path) {
        run_git(repository, &["init", "-q"]);
        run_git(repository, &["config", "user.name", "Deimos Test"]);
        run_git(
            repository,
            &["config", "user.email", "deimos@example.invalid"],
        );
        run_git(repository, &["add", "."]);
        run_git(repository, &["commit", "-q", "-m", "fixture"]);
    }

    fn run_git(repository: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .output()
            .expect("git should execute");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    struct Fixture {
        path: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let fixture = Self::new_empty(label);
            fs::create_dir_all(fixture.path()).expect("fixture should be created");
            fixture
        }

        fn new_empty(label: &str) -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "deimos-build-id-{label}-{}-{sequence}",
                std::process::id()
            ));
            if path.exists() {
                fs::remove_dir_all(&path).expect("stale fixture should be removed");
            }
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.path.exists() {
                fs::remove_dir_all(&self.path).expect("fixture should be removed");
            }
        }
    }
}
