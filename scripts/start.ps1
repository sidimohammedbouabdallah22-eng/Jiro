param(
    [switch]$ResetAdminToken,
    [string]$EventExportUrl = '',
    [ValidateRange(1, 100000)][int]$EventExportRows = 10000,
    [string]$EventWriteTimeout = '5s'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $running = @(Get-CimInstance Win32_Process -Filter "Name='openwaf.exe'" | Where-Object { $_.ExecutablePath -eq (Join-Path $projectRoot 'bin/openwaf.exe') })
    if ($running.Count) { throw 'OpenWAF is already running. Stop it with Ctrl+C in its server terminal before starting or resetting the token.' }
    go build -o bin/openwaf.exe ./cmd/waf-server
    if ($LASTEXITCODE -ne 0) { throw 'OpenWAF build failed' }
    $env:OPENWAF_ADMIN_TOKEN = & (Join-Path $PSScriptRoot 'admin-token.ps1') -Reset:$ResetAdminToken
    Write-Host 'Console: http://127.0.0.1:8081'
    Write-Host 'Use this administrator token to sign in:'
    Write-Host $env:OPENWAF_ADMIN_TOKEN
    $serverArguments = @('-config', 'config/policy.json', '-event-export-rows', "$EventExportRows", '-event-write-timeout', $EventWriteTimeout)
    if ($EventExportUrl) { $serverArguments += @('-event-export-url', $EventExportUrl) }
    & ./bin/openwaf.exe @serverArguments
} finally {
    Pop-Location
}
