$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $modules = @(go list -deps -f '{{if .Module}}{{.Module.Dir}}{{end}}' ./cmd/waf-server | Where-Object { $_ -and $_ -ne $projectRoot } | Sort-Object -Unique)
    if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate runtime dependencies' }
    $destination = Join-Path $projectRoot 'THIRD_PARTY_LICENSES'
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    foreach ($modulePath in $modules) {
        $name = ($modulePath -replace '^.*[\\/]pkg[\\/]mod[\\/]', '').Replace('\', '_').Replace('/', '_')
        $target = Join-Path $destination $name
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Get-ChildItem -LiteralPath $modulePath -File | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)' } | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $target $_.Name) -Force
        }
    }
    Write-Host "Collected license files for $($modules.Count) runtime modules."
} finally {
    Pop-Location
}
