# tests/attacks/scraping-aggressif/scenario.ps1
#
# Equivalent PowerShell de scenario.sh.
# Loopback only.
#
# AVERTISSEMENT : détection signature-only, trivialement contournable.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..\..')
Set-Location (Join-Path $repoRoot 'proxy')

$env:CGO_ENABLED = '0'
& go test -count=1 -run '^TestReproducer_Scraping' ./mitigations/scraping/...
exit $LASTEXITCODE
