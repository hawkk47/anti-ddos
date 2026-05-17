# tests/attacks/ja3-ja4-fingerprint/scenario.ps1
#
# Equivalent PowerShell de scenario.sh.
# Loopback only : tests Go en memoire, pas de socket reseau.
#
# AVERTISSEMENT : mitigation dormante tant que le data plane ne
# termine pas TLS. Voir docs/threat-model.md#ja3-ja4-fingerprint.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
Set-Location (Join-Path $repoRoot 'proxy')

$env:CGO_ENABLED = '0'
& go test -count=1 -run '^TestReproducer_TLSFingerprint' ./mitigations/tlsfingerprint/...
exit $LASTEXITCODE
