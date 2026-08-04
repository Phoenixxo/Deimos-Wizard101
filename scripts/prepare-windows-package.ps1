[CmdletBinding()]
param(
    [string] $Toolchain = "1.77.2-x86_64-pc-windows-msvc",
    [string] $BuildDirectory = "target/package-build",
    [string] $PackageInputDirectory = "target/package-input"
)

$ErrorActionPreference = "Stop"
$windowsTarget = "x86_64-pc-windows-msvc"

if ($env:OS -ne "Windows_NT") {
    throw "Windows package inputs must be prepared on Windows."
}
if ([string]::IsNullOrWhiteSpace($env:DEIMOS_BUILD_ID)) {
    throw "DEIMOS_BUILD_ID must identify the package build."
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $repositoryRoot ".venv/Scripts/python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    $pythonCommand = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand) {
        throw "Python 3.13 could not be found for the native package build."
    }
    $python = $pythonCommand.Source
}

$buildDirectoryPath = if ([System.IO.Path]::IsPathRooted($BuildDirectory)) {
    [System.IO.Path]::GetFullPath($BuildDirectory)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $BuildDirectory))
}
$packageInputPath = if ([System.IO.Path]::IsPathRooted($PackageInputDirectory)) {
    [System.IO.Path]::GetFullPath($PackageInputDirectory)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $PackageInputDirectory))
}

& (Join-Path $PSScriptRoot "build-wine-agent.ps1") `
    -Toolchain $Toolchain `
    -TargetDirectory $buildDirectoryPath
if ($LASTEXITCODE -ne 0) {
    throw "The Windows helper package build failed."
}

Push-Location $repositoryRoot
try {
    $env:PYO3_PYTHON = $python
    & rustup run $Toolchain cargo build `
        --locked `
        --release `
        --package deimos-native `
        --target $windowsTarget `
        --target-dir $buildDirectoryPath `
        --features extension-module
    if ($LASTEXITCODE -ne 0) {
        throw "The native Python extension package build failed."
    }
} finally {
    Pop-Location
}

$suffix = (& $python -c "import sysconfig; print(sysconfig.get_config_var('EXT_SUFFIX'))").Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($suffix)) {
    throw "Python did not report an extension-module suffix."
}

New-Item -ItemType Directory -Path $packageInputPath -Force | Out-Null
$agent = Join-Path $buildDirectoryPath "$windowsTarget/release/deimos-agent.exe"
$nativeSource = Join-Path $buildDirectoryPath "$windowsTarget/release/deimos_native.dll"
$packagedAgent = Join-Path $packageInputPath "deimos-agent.exe"
$manifest = Join-Path $packageInputPath "deimos-agent.json"
$nativeModule = Join-Path $packageInputPath "deimos_native$suffix"

Copy-Item -LiteralPath $agent -Destination $packagedAgent -Force
Copy-Item -LiteralPath $nativeSource -Destination $nativeModule -Force
& $python (Join-Path $PSScriptRoot "package_artifacts.py") create-manifest `
    --agent $packagedAgent `
    --output $manifest `
    --expected-build-id $env:DEIMOS_BUILD_ID
if ($LASTEXITCODE -ne 0) {
    throw "The Windows helper identity manifest could not be created."
}
& $python (Join-Path $PSScriptRoot "package_artifacts.py") verify-inputs `
    --agent $packagedAgent `
    --manifest $manifest `
    --native-module $nativeModule `
    --expected-build-id $env:DEIMOS_BUILD_ID
if ($LASTEXITCODE -ne 0) {
    throw "The Windows package inputs did not share one build identity."
}

$env:DEIMOS_AGENT_ARTIFACT_PATH = $packagedAgent
$env:DEIMOS_AGENT_MANIFEST_PATH = $manifest
$env:DEIMOS_NATIVE_MODULE_PATH = $nativeModule
$env:PYTHONPATH = $packageInputPath

if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
    Add-Content -LiteralPath $env:GITHUB_ENV -Encoding utf8 -Value @(
        "DEIMOS_AGENT_ARTIFACT_PATH=$packagedAgent"
        "DEIMOS_AGENT_MANIFEST_PATH=$manifest"
        "DEIMOS_NATIVE_MODULE_PATH=$nativeModule"
        "PYTHONPATH=$packageInputPath"
    )
}

Write-Host "Matching Windows package inputs prepared:"
Write-Host "  native: $nativeModule"
Write-Host "  helper: $packagedAgent"
Write-Host "  manifest: $manifest"
