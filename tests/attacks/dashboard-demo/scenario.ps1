# tests/attacks/dashboard-demo/scenario.ps1
#
# Genere du trafic mixte loopback vers le data plane (127.0.0.1:8080)
# pour faire bouger plusieurs compteurs de mitigations a la fois :
#   - cachepoison       : X-Forwarded-Host / X-Original-URL
#   - requesthygiene    : methodes/headers suspects
#   - largeheader       : header de ~12 KB
#   - scrapingbot       : User-Agent type scraper
#   - httpflood         : rafale rapide
#   - credentialstuffing: POST /login avec mots de passe communs
#
# Tout reste sur 127.0.0.1 (cf. AGENTS.md regle 1).
#
# Usage :
#   powershell -File tests/attacks/dashboard-demo/scenario.ps1
#   powershell -File tests/attacks/dashboard-demo/scenario.ps1 -Rounds 5
#   powershell -File tests/attacks/dashboard-demo/scenario.ps1 -Loop

[CmdletBinding()]
param(
    [int]$Rounds = 1,
    [switch]$Loop,
    [string]$Target = 'http://127.0.0.1:8080'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Garde-fou : refuse toute autre cible que loopback.
$uri = [Uri]$Target
$loopback = @('127.0.0.1', '::1', 'localhost')
if ($loopback -notcontains $uri.Host) {
    Write-Error "Refuse : Target doit etre loopback (vu: $($uri.Host))"
    exit 2
}

function Send-Quiet {
    param(
        [string]$Method = 'GET',
        [string]$Path = '/',
        [hashtable]$Headers,
        [string]$Body
    )
    try {
        $iwrArgs = @{
            Uri             = "$Target$Path"
            Method          = $Method
            UseBasicParsing = $true
            TimeoutSec      = 3
            ErrorAction     = 'Stop'
        }
        if ($Headers) { $iwrArgs.Headers = $Headers }
        if ($Body)    { $iwrArgs.Body    = $Body; $iwrArgs.ContentType = 'application/x-www-form-urlencoded' }
        Invoke-WebRequest @iwrArgs | Out-Null
    } catch {
        # On veut juste declencher les compteurs, peu importe le verdict.
    }
}

function Invoke-Round {
    Write-Host "[demo] round start" -ForegroundColor Cyan

    # --- cachepoison : 60 req avec headers reflectifs ---
    Write-Host "  cachepoison..." -NoNewline
    1..60 | ForEach-Object {
        Send-Quiet -Path "/page-$_" -Headers @{
            'X-Forwarded-Host' = "evil$_.example"
            'X-Original-URL'   = '/admin'
        }
    }
    Write-Host " ok"

    # --- requesthygiene : methodes/paths bizarres ---
    Write-Host "  requesthygiene..." -NoNewline
    foreach ($m in @('TRACE', 'OPTIONS', 'PROPFIND')) {
        1..10 | ForEach-Object { Send-Quiet -Method $m -Path '/' }
    }
    Write-Host " ok"

    # --- largeheader : ~12 KB de cookies ---
    Write-Host "  largeheader..." -NoNewline
    $big = ('A' * 12000)
    1..20 | ForEach-Object {
        Send-Quiet -Path '/' -Headers @{ 'Cookie' = "junk=$big" }
    }
    Write-Host " ok"

    # --- scrapingbot : User-Agent de scraper connus ---
    Write-Host "  scrapingbot..." -NoNewline
    $uas = @(
        'python-requests/2.31.0',
        'curl/7.88.1',
        'Wget/1.21',
        'Scrapy/2.11.0',
        'Go-http-client/1.1',
        'Java/17.0.1'
    )
    foreach ($ua in $uas) {
        1..15 | ForEach-Object {
            Send-Quiet -Path "/api/items?p=$_" -Headers @{ 'User-Agent' = $ua }
        }
    }
    Write-Host " ok"

    # --- credentialstuffing : POST /login ---
    Write-Host "  credentialstuffing..." -NoNewline
    $pwds = @('123456','password','admin','qwerty','letmein','welcome','iloveyou','12345678')
    foreach ($p in $pwds) {
        1..10 | ForEach-Object {
            Send-Quiet -Method 'POST' -Path '/login' -Body "user=u$_&password=$p"
        }
    }
    Write-Host " ok"

    # --- httpflood : 300 GET sequentiels rapides ---
    Write-Host "  httpflood..." -NoNewline
    1..300 | ForEach-Object {
        Send-Quiet -Path "/?q=$_"
    }
    Write-Host " ok"

    Write-Host "[demo] round done" -ForegroundColor Green
}

if ($Loop) {
    Write-Host "[demo] boucle infinie (Ctrl+C pour stopper)" -ForegroundColor Yellow
    while ($true) { Invoke-Round }
} else {
    1..$Rounds | ForEach-Object { Invoke-Round }
}

Write-Host "[demo] fini." -ForegroundColor Cyan
