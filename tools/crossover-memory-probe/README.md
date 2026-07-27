# CrossOver memory feasibility probe

This is a disposable, read-only feasibility tool. It answers one question:

> Can a Rust Windows process running inside the same CrossOver bottle find and
> read the in-memory PE headers of `WizardGraphicalClient.exe`?

The probe requests only `PROCESS_QUERY_INFORMATION` and `PROCESS_VM_READ`. It
does not write memory, allocate remote memory, inject code, send input, read
credentials, or modify the bottle.

## Build

The repository's `CrossOver memory probe` GitHub Actions workflow builds the
Windows executable on `windows-latest` and publishes
`crossover-memory-probe.exe` as an artifact.

Local portable parsing tests can run on any host:

```bash
cargo test --manifest-path tools/crossover-memory-probe/Cargo.toml
```

The Windows API path can be type-checked from macOS when the Rust Windows target
is installed:

```bash
cargo check \
  --manifest-path tools/crossover-memory-probe/Cargo.toml \
  --target x86_64-pc-windows-msvc
```

## Run in CrossOver

1. Start Wizard101 and leave it running.
2. Select the Wizard101 bottle in CrossOver.
3. Choose **Run Command**.
4. Browse to `crossover-memory-probe.exe`.
5. Run it and capture its JSON output.

The default process name is `WizardGraphicalClient.exe`. A different executable
name can be passed as the first argument.

## Success criteria

A successful report has `"success": true` and includes:

* the Wizard101 process ID;
* the main module's base address and size;
* `"dos_signature": "MZ"`;
* `"pe_signature": "PE\\0\\0"`;
* a recognized machine type;
* a non-zero `size_of_image`.

Success proves that a Wine-side Rust agent can replace the read-only portion of
`pymem`. It does not prove that remote writes, executable allocation, hooks, or
input injection are safe or viable.
