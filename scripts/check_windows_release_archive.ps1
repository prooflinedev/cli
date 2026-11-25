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
# Open the archive just once and deny replacement, ensuring the size bound
# applies to precisely the stream whose bytes the parser will consume.
$stream = [IO.File]::Open($archive, [IO.FileMode]::Open,
    [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    $length = $stream.Length
    if ($length -le 0 -or $length -gt $script:MaxArchiveBytes) {
        throw "Packaged Windows archive violates installer compressed-size limit: $length bytes."
    }
    $compressed = [byte[]]::new([int]$length)
    $offset = 0
    while ($offset -lt $compressed.Length) {
        $count = $stream.Read($compressed, $offset, $compressed.Length - $offset)
        if ($count -le 0) { throw 'Packaged Windows archive truncated during read.' }
        $offset += $count
    }
}
finally { $stream.Dispose() }
$payload = Get-ProoflineTarExecutable $compressed
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
