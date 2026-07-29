[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $AgentPath
)

$ErrorActionPreference = "Stop"

function Resolve-Dumpbin {
    $command = Get-Command "dumpbin.exe" -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio/Installer/vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw "dumpbin.exe is not on PATH and vswhere.exe could not be found."
    }

    $installationPath = (
        & $vswhere `
            -latest `
            -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath
    ) | Select-Object -First 1
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
        throw "Visual Studio C++ build tools could not be located with vswhere.exe."
    }

    $toolsetsRoot = Join-Path $installationPath "VC/Tools/MSVC"
    $toolsets = @(Get-ChildItem -LiteralPath $toolsetsRoot -Directory | Sort-Object Name -Descending)
    foreach ($toolset in $toolsets) {
        $candidate = Join-Path $toolset.FullName "bin/Hostx64/x64/dumpbin.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    throw "dumpbin.exe was not found in the installed Visual Studio C++ build tools."
}

$resolvedAgentPath = (Resolve-Path -LiteralPath $AgentPath).Path
$dumpbin = Resolve-Dumpbin
$importOutput = & $dumpbin /NOLOGO /DEPENDENTS $resolvedAgentPath 2>&1
if ($LASTEXITCODE -ne 0) {
    $diagnostic = ($importOutput | ForEach-Object { "$_" }) -join [Environment]::NewLine
    throw @"
dumpbin could not inspect '$resolvedAgentPath' (exit code $LASTEXITCODE).
$diagnostic
"@
}

$imports = @(
    $importOutput |
        ForEach-Object {
            if ($_ -match "^\s*([A-Za-z0-9_.-]+\.dll)\s*$") {
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
