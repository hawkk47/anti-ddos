# tests/attacks/credential-stuffing/scenario.ps1
#
# Equivalent PowerShell de scenario.sh.
# Loopback only.
#
# AVERTISSEMENT : rate-limit per-IP, inefficace contre stuffing distribué.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
Set-Location (Join-Path $repoRoot 'proxy')

$env:CGO_ENABLED = '0'
& go test -count=1 -run '^TestReproducer_CredStuff' ./mitigations/credstuff/...
exit $LASTEXITCODE
