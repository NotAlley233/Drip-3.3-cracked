param(
    [ValidateSet('nice', '123', 'all')][string]$Variant = 'all',
    [string]$Python = 'python',
    [string]$InputDir = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = 'Stop'
$InputDir = (Resolve-Path -LiteralPath $InputDir).Path
Push-Location $PSScriptRoot
try {
    $venvPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $venvPython)) {
        & $Python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Failed to create build environment' }
    }
    & $venvPython -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Failed to install build dependencies' }
    & $venvPython build.py --variant $Variant --input-dir $InputDir
    if ($LASTEXITCODE -ne 0) { throw 'Build or executable self-test failed' }
} finally {
    Pop-Location
}
