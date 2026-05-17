#requires -Version 5.1
<#
.SYNOPSIS
  Installer serveur anti-ddos pour Windows 10+/Server.

.DESCRIPTION
  Compile et installe le data plane (Go) et optionnellement le control
  plane (Node.js) comme services Windows via sc.exe. Idempotent —
  peut être relancé pour mettre à jour les binaires. AUCUN secret
  n'est écrit ici ; les tokens vont dans les fichiers .env situés
  sous %ProgramData%\anti-ddos\ et lus par l'application.

.PARAMETER DryRun
  Affiche les actions sans rien modifier (défaut : $true).

.PARAMETER Yes
  Applique réellement les actions.

.PARAMETER Prefix
  Préfixe d'installation. Défaut : C:\Program Files\anti-ddos.

.PARAMETER NoControl
  N'installe pas le control plane.

.EXAMPLE
  PS> .\install-server.ps1 -DryRun
  PS> .\install-server.ps1 -Yes
#>
[CmdletBinding()]
param(
  [switch] $DryRun = $true,
  [switch] $Yes,
  [string] $Prefix = "$env:ProgramFiles\anti-ddos",
  [switch] $NoControl
)

$ErrorActionPreference = 'Stop'
if ($Yes) { $DryRun = $false }

function Write-Log  { param([string] $m) Write-Host  ("[{0:s}Z] [info]  {1}" -f (Get-Date).ToUniversalTime(), $m) }
function Write-Warn { param([string] $m) Write-Warning ("[{0:s}Z] [warn]  {1}" -f (Get-Date).ToUniversalTime(), $m) }
function Die        { param([string] $m) Write-Error   ("[{0:s}Z] [error] {1}" -f (Get-Date).ToUniversalTime(), $m); exit 1 }

function Invoke-Step {
  param([string] $Description, [scriptblock] $Action)
  if ($DryRun) {
    Write-Log "[dry-run] $Description"
  } else {
    Write-Log "+ $Description"
    & $Action
  }
}

# -------- prerequis --------
$adm = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $adm.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Die "Doit être lancé en administrateur."
}
if (-not (Get-Command go -ErrorAction SilentlyContinue))   { Die "go >= 1.22 requis dans le PATH." }
if (-not $NoControl) {
  if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Die "node >= 20 requis (ou passez -NoControl)." }
  if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) { Die "pnpm requis (ou passez -NoControl)." }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Resolve-Path (Join-Path $scriptDir '..\..')

$DataDir = Join-Path $env:ProgramData 'anti-ddos'
$EtcDir  = Join-Path $DataDir 'etc'
$StateDir = Join-Path $DataDir 'state'
$LogDir   = Join-Path $DataDir 'logs'

# -------- build --------
Write-Log "build data plane (CGO_ENABLED=0)"
$env:CGO_ENABLED = '0'
Push-Location (Join-Path $repoRoot 'proxy')
try {
  & go build -trimpath -ldflags '-s -w' -o "$repoRoot\proxy\anti-ddos-proxy.exe" ./cmd/proxy
  if ($LASTEXITCODE -ne 0) { Die "build data plane échoué" }
} finally { Pop-Location }

if (-not $NoControl) {
  Write-Log "build control plane"
  Push-Location (Join-Path $repoRoot 'control')
  try {
    & pnpm install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { Die "pnpm install échoué" }
    & pnpm build
    if ($LASTEXITCODE -ne 0) { Die "pnpm build échoué" }
  } finally { Pop-Location }
}

# -------- arborescence --------
foreach ($d in @($Prefix, (Join-Path $Prefix 'bin'), $DataDir, $EtcDir, $StateDir, $LogDir)) {
  if (-not (Test-Path $d)) {
    Invoke-Step "mkdir $d" { New-Item -ItemType Directory -Force -Path $d | Out-Null }
  }
}

# -------- copie binaires --------
Invoke-Step "copy anti-ddos-proxy.exe" {
  Copy-Item -Force "$repoRoot\proxy\anti-ddos-proxy.exe" (Join-Path $Prefix 'bin\anti-ddos-proxy.exe')
}
if (-not $NoControl) {
  $ctrlDst = Join-Path $Prefix 'control'
  Invoke-Step "copy control plane (dist + package.json + node_modules)" {
    if (-not (Test-Path $ctrlDst)) { New-Item -ItemType Directory -Force -Path $ctrlDst | Out-Null }
    foreach ($item in 'dist','package.json','node_modules') {
      $src = Join-Path $repoRoot "control\$item"
      if (Test-Path $src) {
        Copy-Item -Recurse -Force $src (Join-Path $ctrlDst $item)
      }
    }
  }
}

# -------- .env (sans secret) --------
$proxyEnv = Join-Path $EtcDir 'proxy.env'
if (-not (Test-Path $proxyEnv)) {
  Invoke-Step "install proxy.env (sans secret)" {
    Copy-Item -Force (Join-Path $scriptDir 'proxy.env.example') $proxyEnv
  }
} else { Write-Log "$proxyEnv existe déjà — non modifié" }

if (-not $NoControl) {
  $ctrlEnv = Join-Path $EtcDir 'control.env'
  if (-not (Test-Path $ctrlEnv)) {
    Invoke-Step "install control.env (sans secret)" {
      Copy-Item -Force (Join-Path $scriptDir 'control.env.example') $ctrlEnv
    }
  } else { Write-Log "$ctrlEnv existe déjà — non modifié" }
}

# -------- helper : charge un .env puis lance un binaire --------
# Les services Windows n'ont pas d'équivalent natif à EnvironmentFile=
# de systemd. On installe un petit wrapper PowerShell qui charge le
# .env puis exécute le binaire en avant-plan (le SCM le supervise).
$wrapper = @'
param([Parameter(Mandatory)][string]$EnvFile,[Parameter(Mandatory)][string]$Exe,[string[]]$Args)
$ErrorActionPreference = 'Stop'
if (Test-Path $EnvFile) {
  Get-Content -LiteralPath $EnvFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { return }
    $kv = $line -split '=', 2
    if ($kv.Count -eq 2) {
      [Environment]::SetEnvironmentVariable($kv[0].Trim(), $kv[1].Trim(), 'Process')
    }
  }
}
& $Exe @Args
exit $LASTEXITCODE
'@
$wrapperPath = Join-Path $Prefix 'bin\run-with-env.ps1'
Invoke-Step "install wrapper run-with-env.ps1" {
  Set-Content -LiteralPath $wrapperPath -Value $wrapper -Encoding UTF8
}

# -------- services Windows --------
function Install-Service {
  param(
    [string] $Name, [string] $DisplayName, [string] $Description,
    [string] $EnvFile, [string] $Exe, [string[]] $ArgsList
  )
  $existing = Get-Service -Name $Name -ErrorAction SilentlyContinue
  $binPath = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "' +
    $wrapperPath + '" -EnvFile "' + $EnvFile + '" -Exe "' + $Exe + '"'
  if ($ArgsList -and $ArgsList.Count -gt 0) {
    $binPath += ' -Args ' + ($ArgsList -join ',')
  }
  if ($existing) {
    Invoke-Step "update service $Name" {
      sc.exe stop $Name | Out-Null
      sc.exe config $Name binPath= "$binPath" start= auto | Out-Null
      sc.exe description $Name "$Description" | Out-Null
    }
  } else {
    Invoke-Step "create service $Name" {
      sc.exe create $Name binPath= "$binPath" DisplayName= "$DisplayName" start= auto | Out-Null
      sc.exe description $Name "$Description" | Out-Null
    }
  }
}

Install-Service `
  -Name 'anti-ddos-proxy' `
  -DisplayName 'anti-ddos data plane' `
  -Description 'Reverse proxy avec mitigations L3/L4 + L7.' `
  -EnvFile $proxyEnv `
  -Exe (Join-Path $Prefix 'bin\anti-ddos-proxy.exe')

if (-not $NoControl) {
  Install-Service `
    -Name 'anti-ddos-control' `
    -DisplayName 'anti-ddos control plane' `
    -Description 'API d''administration + WAF rules store.' `
    -EnvFile (Join-Path $EtcDir 'control.env') `
    -Exe (Get-Command node).Path `
    -ArgsList @((Join-Path $Prefix 'control\dist\index.js'))
}

# -------- résumé --------
$mode = if ($DryRun) { '(dry-run)' } else { 'appliquée' }
Write-Host @"

  Installation $mode sous $Prefix.

  Prochaines étapes :
    1. Éditer $proxyEnv (et $(Join-Path $EtcDir 'control.env') si applicable).
    2. Si exposé hors loopback : renseigner ANTIDDOS_CTRL_API_TOKEN
       et ANTIDDOS_PROXY_ADMIN_TOKEN (>= 16 caractères).
    3. Start-Service anti-ddos-proxy$( if (-not $NoControl) { ', anti-ddos-control' } )
    4. Get-Service anti-ddos-*
    5. Get-EventLog -LogName Application -Source anti-ddos-* -Newest 50

"@
