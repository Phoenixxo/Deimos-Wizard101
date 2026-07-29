use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::Command;

const MAX_BUILD_ID_LENGTH: usize = 128;

fn main() {
    println!("cargo:rerun-if-env-changed=DEIMOS_BUILD_ID");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-changed=../deimos-agent");
    println!("cargo:rerun-if-changed=../deimos-native");

    let build_id = match env::var("DEIMOS_BUILD_ID") {
        Ok(value) => sanitize_build_id(&value)
            .unwrap_or_else(|| panic!("DEIMOS_BUILD_ID contains unsupported characters")),
        Err(env::VarError::NotPresent) => git_build_id().unwrap_or_else(|| {
            format!(
                "development-{}",
                env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string())
            )
        }),
        Err(env::VarError::NotUnicode(_)) => panic!("DEIMOS_BUILD_ID must be valid UTF-8"),
    };
    println!("cargo:rustc-env=DEIMOS_BUILD_ID_EMBEDDED={build_id}");
}

fn sanitize_build_id(value: &str) -> Option<String> {
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

fn git_build_id() -> Option<String> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let revision = command_output(&repository, &["rev-parse", "--verify", "HEAD"])?;
    let revision = revision.trim();
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }

    let diff = command_output_bytes(&repository, &["diff", "--binary", "HEAD", "--"])?;
    let untracked = command_output_bytes(
        &repository,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?;
    if diff.is_empty() && untracked.is_empty() {
        return Some(format!("git-{revision}"));
    }

    let mut hasher = DefaultHasher::new();
    revision.hash(&mut hasher);
    diff.hash(&mut hasher);
    for path in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        path.hash(&mut hasher);
        let path = String::from_utf8_lossy(path);
        if let Ok(contents) = fs::read(repository.join(path.as_ref())) {
            contents.hash(&mut hasher);
        }
    }
    Some(format!("git-{revision}-dirty-{:016x}", hasher.finish()))
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

fn command_output_bytes(repository: &Path, arguments: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout)
}
