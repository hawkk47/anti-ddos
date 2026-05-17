# tests/attacks/concurrency-saturation/scenario.ps1
#
# Equivalent PowerShell de scenario.sh.
# Loopback only.
#
# AVERTISSEMENT : load shedding global, pas per-tenant. Filet en
# complement du rate-limit per-IP, pas en remplacement.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
Set-Location (Join-Path $repoRoot 'proxy')

$env:CGO_ENABLED = '0'
& go test -count=1 -run '^TestReproducer_ConcurrencyCap' ./mitigations/concurrency/...
exit $LASTEXITCODE
