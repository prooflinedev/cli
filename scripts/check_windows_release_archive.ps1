#requires -Version 5.1
# Validate the exact Windows release archive using the same parser and limits
# as install.ps1. Invoked under BOTH Windows PowerShell 5.1 and PowerShell 7.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ArchivePath,
    [Parameter(Mandatory = $true)][string]$ExecutablePath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1')
$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
$executable = (Resolve-Path -LiteralPath $ExecutablePath).Path
$archiveLength = ([IO.FileInfo]::new($archive)).Length
if ($archiveLength -le 0 -or $archiveLength -gt $script:MaxArchiveBytes) {
    throw "Packaged Windows archive violates installer compressed-size limit: $archiveLength bytes."
}
$payload = Get-ProoflineTarExecutable ([IO.File]::ReadAllBytes($archive))
if ($payload.Length -le 0) {
    throw 'Packaged Windows archive has no installable executable.'
}
$sha = [Security.Cryptography.SHA256]::Create()
try { $payloadHash = [BitConverter]::ToString($sha.ComputeHash($payload)).Replace('-', '') }
finally { $sha.Dispose() }
$expectedHash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
if ($payloadHash -cne $expectedHash) {
    throw 'Windows installer-extracted payload differs from the version-tested build.'
}
Write-Host "Windows archive compatible with PowerShell $($PSVersionTable.PSVersion): $payloadHash"
