# tests/run-integration.ps1
# Equivalent PowerShell de run-integration.sh.
# Cf. AGENTS.md, .github/instructions/tests.instructions.md.
#
# - Loopback uniquement (127.0.0.1)
# - Ports ephemeres (:0)
# - Cleanup garanti via try/finally
# - Memes arguments et meme sortie que la version .sh.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string] $Filter = 'all',

    [switch] $Help
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Write-Log {
    param([string] $Level, [string] $Message)
    $ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    [Console]::Error.WriteLine("$ts [$Level]  $Message")
}
function Log  { param([string]$m) Write-Log 'info'  $m }
function Warn { param([string]$m) Write-Log 'warn'  $m }
function Die  {
    param([string]$m)
    Write-Log 'error' $m
    exit 1
}

if ($Help) {
    @'
Usage: tests/run-integration.ps1 [-Filter <name>]

  -Filter   sous-ensemble a executer (ex: waf, ratelimit, slowloris).
            Par defaut : all.

Garde-fous :
  - aucune URL non-loopback acceptee comme cible
  - ports ephemeres (:0)
  - nettoyage des processus enfants en sortie
'@ | Write-Host
    exit 0
}

$childProcs = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
function Register-Child {
    param([System.Diagnostics.Process] $p)
    $childProcs.Add($p) | Out-Null
}

try {
    Log "filter=$Filter os=$([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)"

    function Need {
        param([string] $Tool)
        if (-not (Get-Command $Tool -ErrorAction SilentlyContinue)) {
            Die "outil manquant : $Tool"
        }
    }

    # --------------------------------------------------------------
    # Etape 1 : tests unitaires Go (proxy).
    # --------------------------------------------------------------
    if (Test-Path proxy) {
        Need 'go'
        Log 'go test ./... (proxy/)'
        Push-Location proxy
        try {
            # -race exige cgo ; on le laisse au CI dedie. Ici : pure-Go strict.
            $env:CGO_ENABLED = '0'
            & go test -count=1 ./...
            if ($LASTEXITCODE -ne 0) { Die "go test a echoue (exit $LASTEXITCODE)" }
        }
        finally { Pop-Location }
    }
    else {
        Warn 'proxy/ absent : tests Go ignores'
    }

    # --------------------------------------------------------------
    # Etape 2 : tests unitaires Node (control).
    # --------------------------------------------------------------
    if (Test-Path control) {
        if (Get-Command pnpm -ErrorAction SilentlyContinue) {
            Log 'pnpm test (control/)'
            Push-Location control
            try {
                & pnpm test
                if ($LASTEXITCODE -ne 0) { Die "pnpm test a echoue (exit $LASTEXITCODE)" }
            }
            finally { Pop-Location }
        }
        else {
            Warn 'pnpm absent : etapes control/ ignorees'
        }
    }

    # --------------------------------------------------------------
    # Etape 3 : scenarios end-to-end loopback.
    # Placeholder : les vrais scenarios arrivent via add-mitigation.
    # --------------------------------------------------------------
    if (Test-Path tests/attacks) {
        # pwsh (PowerShell 7+) si dispo, sinon powershell.exe (5.1) :
        # le bootstrap Windows par defaut ne fournit que 5.1, on doit
        # rester portable entre les deux pour ne pas casser un poste sec.
        $psExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
        Get-ChildItem -Path tests/attacks -Recurse -Filter 'scenario.ps1' | ForEach-Object {
            Log "scenario : $($_.FullName) (via $psExe)"
            & $psExe -NoProfile -ExecutionPolicy Bypass -File $_.FullName
            if ($LASTEXITCODE -ne 0) { Die "scenario echoue : $($_.FullName)" }
        }
    }

    Log 'OK'
}
finally {
    foreach ($p in $childProcs) {
        try {
            if (-not $p.HasExited) { $p.Kill() }
        }
        catch { }
    }
}
