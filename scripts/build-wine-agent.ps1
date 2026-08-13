[CmdletBinding()]
param(
    [string] $Toolchain = "1.77.2-x86_64-pc-windows-msvc",
    [string] $TargetDirectory = "target/wine-compat"
)

$ErrorActionPreference = "Stop"
$windowsTarget = "x86_64-pc-windows-msvc"

if ($env:OS -ne "Windows_NT") {
    throw "The Wine agent must be built on Windows with the MSVC toolchain."
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$targetDirectoryPath = if ([System.IO.Path]::IsPathRooted($TargetDirectory)) {
    [System.IO.Path]::GetFullPath($TargetDirectory)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $TargetDirectory))
}

$rustcVersion = & rustup run $Toolchain rustc --version --verbose 2>&1
if ($LASTEXITCODE -ne 0) {
    $diagnostic = ($rustcVersion | ForEach-Object { "$_" }) -join [Environment]::NewLine
    throw @"
Rust toolchain '$Toolchain' is not available.
Install it with:
  rustup toolchain install $Toolchain --profile minimal

$diagnostic
"@
}

$hostLine = $rustcVersion | Where-Object { $_ -match "^host:\s+(.+)$" } | Select-Object -First 1
if ($null -eq $hostLine) {
    throw "Rust toolchain '$Toolchain' did not report its host triple."
}
$hostTriple = [regex]::Match($hostLine, "^host:\s+(.+)$").Groups[1].Value.Trim()
if ($hostTriple -ne $windowsTarget) {
    throw "Rust toolchain '$Toolchain' has host '$hostTriple'; expected '$windowsTarget'."
}

$installedTargets = @(& rustup target list --installed --toolchain $Toolchain)
if ($LASTEXITCODE -ne 0 -or $installedTargets -notcontains $windowsTarget) {
    throw @"
Rust target '$windowsTarget' is not installed for '$Toolchain'.
Install it with:
  rustup target add $windowsTarget --toolchain $Toolchain
"@
}

Push-Location $repositoryRoot
try {
    & rustup run $Toolchain cargo build `
        --locked `
        --release `
        --package deimos-agent `
        --target $windowsTarget `
        --target-dir $targetDirectoryPath
    if ($LASTEXITCODE -ne 0) {
        throw "The Wine-compatible deimos-agent build failed."
    }
} finally {
    Pop-Location
}

$agentPath = Join-Path $targetDirectoryPath "$windowsTarget/release/deimos-agent.exe"
if (-not (Test-Path -LiteralPath $agentPath -PathType Leaf)) {
    throw "Cargo completed without producing '$agentPath'."
}

$stream = [System.IO.File]::OpenRead($agentPath)
$reader = [System.IO.BinaryReader]::new($stream)
try {
    if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) {
        throw "'$agentPath' does not have a valid MZ executable header."
    }

    $stream.Position = 0x3C
    $peOffset = $reader.ReadInt32()
    if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 4)) {
        throw "'$agentPath' contains an invalid PE header offset."
    }

    $stream.Position = $peOffset
    if ($reader.ReadUInt32() -ne 0x00004550) {
        throw "'$agentPath' does not have a valid PE signature."
    }
} finally {
    $reader.Dispose()
    $stream.Dispose()
}

& (Join-Path $PSScriptRoot "check-wine-agent-imports.ps1") -AgentPath $agentPath

Write-Host "Wine-compatible agent built and validated:"
Write-Output $agentPath
