#requires -Version 5.1
<#
.SYNOPSIS
  Désinstalle les services Windows anti-ddos.

.DESCRIPTION
  Arrête et supprime les services, supprime $Prefix. Avec -Purge,
  supprime aussi %ProgramData%\anti-ddos (configs + état + logs)
  après confirmation interactive.
#>
[CmdletBinding()]
param(
  [switch] $DryRun = $true,
  [switch] $Yes,
  [switch] $Purge,
  [string] $Prefix = "$env:ProgramFiles\anti-ddos"
)

$ErrorActionPreference = 'Stop'
if ($Yes) { $DryRun = $false }

function Write-Log { param([string] $m) Write-Host ("[{0:s}Z] [info] {1}" -f (Get-Date).ToUniversalTime(), $m) }
function Die       { param([string] $m) Write-Error "$m"; exit 1 }

$adm = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $adm.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Die "Doit être lancé en administrateur."
}

# Validation forte avant tout rm.
if (-not $Prefix) { Die "Prefix vide." }
if ($Prefix -notmatch '^[A-Z]:\\Program Files\\anti-ddos' -and
    $Prefix -notmatch '^[A-Z]:\\opt\\anti-ddos') {
  Die "Préfixe refusé pour suppression : $Prefix"
}

function Invoke-Step {
  param([string] $Description, [scriptblock] $Action)
  if ($DryRun) { Write-Log "[dry-run] $Description" }
  else { Write-Log "+ $Description"; & $Action }
}

foreach ($name in @('anti-ddos-control','anti-ddos-proxy')) {
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($svc) {
    Invoke-Step "stop + delete $name" {
      if ($svc.Status -ne 'Stopped') { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue }
      sc.exe delete $name | Out-Null
    }
  }
}

if (Test-Path $Prefix) {
  Invoke-Step "remove $Prefix" { Remove-Item -Recurse -Force $Prefix }
}

if ($Purge) {
  $dataDir = Join-Path $env:ProgramData 'anti-ddos'
  if (Test-Path $dataDir) {
    if (-not $DryRun) {
      $ans = Read-Host "Confirmer la suppression de $dataDir (configs + état + logs) ? [yes/N]"
      if ($ans -ne 'yes') { Die "annulé" }
    }
    Invoke-Step "remove $dataDir" { Remove-Item -Recurse -Force $dataDir }
  }
}

Write-Log ("désinstallation " + $(if ($DryRun) { '(dry-run)' } else { 'terminée' }))
