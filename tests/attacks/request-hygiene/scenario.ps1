# tests/attacks/request-hygiene/scenario.ps1
#
# Equivalent PowerShell de scenario.sh.
# Loopback only.
#
# AVERTISSEMENT : gate binaire (pas de normalisation). Pour un
# upstream legacy potentiellement vulnerable au smuggling malgre le
# front Go, prevoir une normalisation additionnelle.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
Set-Location (Join-Path $repoRoot 'proxy')

$env:CGO_ENABLED = '0'
& go test -count=1 -run '^TestReproducer_RequestHygiene' ./mitigations/requesthygiene/...
exit $LASTEXITCODE
