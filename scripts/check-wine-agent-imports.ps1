[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $AgentPath,

    [string] $Toolchain = "1.77.2"
)

$ErrorActionPreference = "Stop"

$rustcVersion = & rustup run $Toolchain rustc --version --verbose
if ($LASTEXITCODE -ne 0) {
    throw "Failed to inspect Rust toolchain '$Toolchain'."
}

$hostLine = $rustcVersion | Where-Object { $_ -match "^host:\s+(.+)$" } | Select-Object -First 1
if ($null -eq $hostLine) {
    throw "Rust toolchain '$Toolchain' did not report its host triple."
}
$hostTriple = [regex]::Match($hostLine, "^host:\s+(.+)$").Groups[1].Value.Trim()

$sysroot = (& rustup run $Toolchain rustc --print sysroot).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Failed to locate the sysroot for Rust toolchain '$Toolchain'."
}

$llvmObjdump = Join-Path $sysroot "lib/rustlib/$hostTriple/bin/llvm-objdump.exe"
if (-not (Test-Path -LiteralPath $llvmObjdump -PathType Leaf)) {
    throw @"
llvm-objdump was not found for Rust toolchain '$Toolchain'.
Install it with:
  rustup component add llvm-tools-preview --toolchain $Toolchain
"@
}

$importOutput = & $llvmObjdump -p $AgentPath 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "llvm-objdump could not inspect '$AgentPath'."
}

$imports = @(
    $importOutput |
        ForEach-Object {
            if ($_ -match "DLL Name:\s*(\S+)") {
                $Matches[1].ToLowerInvariant()
            }
        } |
        Sort-Object -Unique
)

if ($imports.Count -eq 0) {
    throw "No PE imports were found in '$AgentPath'; refusing to pass an inconclusive check."
}

$forbiddenImports = @(
    "api-ms-win-core-synch-l1-2-0.dll",
    "bcryptprimitives.dll"
)
$unsupportedImports = @($forbiddenImports | Where-Object { $imports -contains $_ })

if ($unsupportedImports.Count -ne 0) {
    throw "Wine-incompatible agent imports detected: $($unsupportedImports -join ', ')"
}

Write-Host "Wine agent import compatibility check passed ($($imports.Count) DLLs inspected)."
