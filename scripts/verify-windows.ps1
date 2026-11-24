[CmdletBinding()]
param(
    [string]$BuildDirectory = "build",
    [string]$Generator = "",
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "This verification script is intended for Windows PowerShell."
}

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$PreviousLocation = Get-Location
$PreviousDataDirectory = $env:CYBERGUARD_DATA_DIR
$VerificationDataDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("cyberguard-verification-" + [guid]::NewGuid().ToString("N"))

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )
    Write-Host ""
    Write-Host "==> $Description" -ForegroundColor Cyan
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

try {
    Set-Location $RepositoryRoot

    foreach ($tool in @("cmake", "python")) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "Required tool '$tool' was not found on PATH. Install it and reopen PowerShell."
        }
    }

    $pythonVersion = & python --version
    Write-Host "Python: $pythonVersion"
    $cmakeVersion = & cmake --version | Select-Object -First 1
    Write-Host "CMake: $cmakeVersion"

    $cachePath = Join-Path $BuildDirectory "CMakeCache.txt"
    $resolvedGenerator = $null
    if (Test-Path $cachePath) {
        $generatorLine = Select-String -Path $cachePath -Pattern "^CMAKE_GENERATOR:INTERNAL=" | Select-Object -First 1
        if ($generatorLine) {
            $resolvedGenerator = $generatorLine.Line.Substring("CMAKE_GENERATOR:INTERNAL=".Length)
            if ($Generator -and $Generator -ne $resolvedGenerator) {
                throw "Build directory '$BuildDirectory' already uses '$resolvedGenerator'. Choose a fresh build directory to use '$Generator'."
            }
            Write-Host "Reusing existing CMake generator: $resolvedGenerator"
        }
    } elseif ($Generator) {
        $resolvedGenerator = $Generator
    }

    $configureArguments = @("-S", ".", "-B", $BuildDirectory, "-DCYBERGUARD_BUILD_TESTS=ON")
    if ($resolvedGenerator) {
        $configureArguments += @("-G", $resolvedGenerator)
    } else {
        Write-Host "Using CMake's default generator for this Windows environment."
    }
    Invoke-CheckedCommand -Executable "cmake" -Arguments $configureArguments -Description "Configure C++20 project"

    Invoke-CheckedCommand -Executable "cmake" -Arguments @("--build", $BuildDirectory, "--config", $Configuration, "--parallel") -Description "Build CyberGuard"
    Invoke-CheckedCommand -Executable "ctest" -Arguments @("--test-dir", $BuildDirectory, "-C", $Configuration, "--output-on-failure") -Description "Run C++ tests"

    $env:CYBERGUARD_DATA_DIR = $VerificationDataDirectory
    Invoke-CheckedCommand -Executable "python" -Arguments @("-m", "compileall", "-q", "backend") -Description "Compile Python backend and tests"
    Invoke-CheckedCommand -Executable "python" -Arguments @("-m", "unittest", "discover", "-s", "backend/tests", "-v") -Description "Run Python backend tests"

    $node = Get-Command "node" -ErrorAction SilentlyContinue
    if ($node) {
        Invoke-CheckedCommand -Executable $node.Source -Arguments @("--check", "app.js") -Description "Validate dashboard JavaScript"
    } else {
        Write-Warning "Node.js is not installed; dashboard JavaScript syntax check was skipped. Install Node.js to run this check."
    }

    Invoke-CheckedCommand -Executable "python" -Arguments @("backend/run_simulation.py") -Description "Run C++ to SQLite integration"
    Invoke-CheckedCommand -Executable "python" -Arguments @("backend/cli.py", "doctor") -Description "Check local CyberGuard readiness"

    Write-Host ""
    Write-Host "All required local verification steps passed." -ForegroundColor Green
    Write-Host "Optional Scapy, Ollama, and model readiness are reported by doctor; they are not required for the core simulator."
}
finally {
    if ($null -eq $PreviousDataDirectory) {
        Remove-Item Env:CYBERGUARD_DATA_DIR -ErrorAction SilentlyContinue
    } else {
        $env:CYBERGUARD_DATA_DIR = $PreviousDataDirectory
    }
    if (Test-Path $VerificationDataDirectory) {
        Remove-Item -LiteralPath $VerificationDataDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    Set-Location $PreviousLocation
}
