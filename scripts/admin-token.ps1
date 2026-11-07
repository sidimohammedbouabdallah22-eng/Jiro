param([switch]$Reset)
$ErrorActionPreference = 'Stop'
$tokenPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'config/admin-token.txt'
if (-not $Reset -and $env:OPENWAF_ADMIN_TOKEN) {
    return $env:OPENWAF_ADMIN_TOKEN.Trim()
}
if (-not $Reset -and (Test-Path -LiteralPath $tokenPath)) {
    $saved = [System.IO.File]::ReadAllText($tokenPath).Trim()
    if ($saved.Length -lt 32) { throw 'Saved administrator token is invalid. Use -ResetAdminToken to replace it.' }
    return $saved
}
$secret = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($secret) } finally { $rng.Dispose() }
$token = [BitConverter]::ToString($secret).Replace('-', '').ToLowerInvariant()
$directory = Split-Path -Parent $tokenPath
New-Item -ItemType Directory -Path $directory -Force | Out-Null
if (-not (Test-Path -LiteralPath $tokenPath)) { New-Item -ItemType File -Path $tokenPath | Out-Null }
# Restrict access before writing the credential. Compatible with Windows PowerShell 5.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $tokenPath
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
$acl.AddAccessRule($rule)
if ($PSVersionTable.PSEdition -eq 'Core') {
    [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]$tokenPath, $acl)
} else {
    (Get-Item -LiteralPath $tokenPath).SetAccessControl($acl)
}
[System.IO.File]::WriteAllText($tokenPath, $token)
return $token
