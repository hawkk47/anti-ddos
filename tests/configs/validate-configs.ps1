# tests/configs/validate-configs.ps1
# Equivalent PowerShell de validate-configs.sh.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location (Join-Path $repoRoot 'control')

if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
    Write-Warning '[validate-configs] pnpm absent, skip'
    exit 0
}

& pnpm --silent validate-configs
exit $LASTEXITCODE
