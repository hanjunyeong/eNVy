param()

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $projectRoot ".env"

if (Test-Path -LiteralPath $destination) {
    throw ".env already exists. It was not overwritten. Keep its passwords for existing database volumes."
}

function New-RandomSecret {
    $bytes = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes)).Replace("-", "").ToLowerInvariant()
}

$databasePassword = New-RandomSecret
$redisPassword = New-RandomSecret
$content = "POSTGRES_PASSWORD=$databasePassword`nREDIS_PASSWORD=$redisPassword`nPIPELINE_VERSION=envy-pe-v4`n"
$encoding = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($destination, $content, $encoding)
Write-Output "Created .env. Keep this file private; do not commit it to Git."
