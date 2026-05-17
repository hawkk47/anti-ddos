# tests/attacks/http2-rapid-reset/scenario.ps1
#
# Equivalent PowerShell de scenario.sh.
# Loopback only.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
Set-Location (Join-Path $repoRoot 'proxy')

$env:CGO_ENABLED = '0'
& go test -count=1 -run '^TestReproducer_RapidReset' ./mitigations/http2reset/...
exit $LASTEXITCODE
