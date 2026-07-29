mod build_support;

use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=DEIMOS_BUILD_ID");

    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in build_support::artifact_watch_paths(&repository) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    for path in build_support::git_control_paths(&repository) {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let build_id = match env::var("DEIMOS_BUILD_ID") {
        Ok(value) => build_support::sanitize_build_id(&value)
            .unwrap_or_else(|| panic!("DEIMOS_BUILD_ID contains unsupported characters")),
        Err(env::VarError::NotPresent) => build_support::derived_build_id(&repository)
            .unwrap_or_else(|error| panic!("failed to derive the Deimos build identity: {error}")),
        Err(env::VarError::NotUnicode(_)) => panic!("DEIMOS_BUILD_ID must be valid UTF-8"),
    };
    println!("cargo:rustc-env=DEIMOS_BUILD_ID_EMBEDDED={build_id}");
}
