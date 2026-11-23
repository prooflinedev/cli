#requires -Version 5.1
<#
.SYNOPSIS
  Tests an actual Windows upgrade using two pinned official Proofline releases.
.DESCRIPTION
  Uses a fresh GUID-named TEMP directory only. No user PATH modifications,
  authentication, existing Proofline installation or admin access.
  Executes install.ps1 under the same PowerShell edition that launched the
  test. Deletes the test directory on success unless -KeepFiles is provided.
  Preserves it on failure for debugging. Requires network access.
#>
[CmdletBinding()]
param([switch]$KeepFiles)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this integration test on Windows.'
}

$installer = Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1'
if (-not [IO.File]::Exists($installer)) { throw 'Cannot find install.ps1.' }
$root = Join-Path ([IO.Path]::GetTempPath()) ('proofline-real-upgrade-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$bin = Join-Path $root 'bin'
$oldUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$script:TestEngine = (Get-Process -Id $PID).Path  # Test whichever PowerShell edition invoked this script.
$passed = $false

function Install-Release([string]$Version) {
    Write-Host "Installing official Proofline $Version..."
    & $script:TestEngine -NoProfile -NonInteractive -File $installer -Version $Version -InstallDir $bin -NoModifyPath
    if ($LASTEXITCODE -ne 0) {
        throw "Installer $Version exited with code $LASTEXITCODE."
    }
}
function Check-Release([string]$Version) {
    $exe = Join-Path $bin 'proofline.exe'
    $receipt = Join-Path $bin '.proofline-install.receipt.json'
    $pending = Join-Path $bin '.proofline-install.pending.json'
    if (-not [IO.File]::Exists($exe) -or -not [IO.File]::Exists($receipt)) {
        throw "Managed installation missing executable or receipt for $Version."
    }
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    $receiptHash = (Get-FileHash -LiteralPath $receipt -Algorithm SHA256).Hash
    $record = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receipt))
    if ($record.schema -ne 1 -or $record.version -cne $Version -or $record.sha256 -cne $hash) {
        throw "Receipt verification failed for $Version."
    }
    if ([IO.File]::Exists($pending)) {
        throw "Pending journal remains after successful installation of $Version."
    }
    $debris = @(Get-ChildItem -LiteralPath $bin -Force | Where-Object {
        $_.Name -match '\A\.proofline-(staged|recovery|api-backup|restore|damaged)-'
    })
    if ($debris.Count -ne 0) {
        throw "Unexpected staged or recovery artifacts remain after $Version."
    }
    $output = @(& $exe '--version')
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -or ($output -join [Environment]::NewLine).Trim() -cne "proofline $Version") {
        throw "Executable version check failed for $Version (exit $exitCode)."
    }
    return [pscustomobject]@{
        BinarySha256 = $hash
        ReceiptSha256 = $receiptHash
    }
}

try {
    Install-Release '0.5.1'
    $before = Check-Release '0.5.1'
    Write-Host "PASS fresh v0.5.1 install; hash $($before.BinarySha256)"

    Install-Release '0.5.2'
    $after = Check-Release '0.5.2'
    if ($before.BinarySha256 -ceq $after.BinarySha256) {
        throw 'Old and new executable hashes unexpectedly match.'
    }
    Write-Host "PASS upgrade to v0.5.2; hash $($after.BinarySha256)"

    Install-Release '0.5.2'
    $repeat = Check-Release '0.5.2'
    if ($repeat.BinarySha256 -cne $after.BinarySha256 -or
        $repeat.ReceiptSha256 -cne $after.ReceiptSha256) {
        throw 'Repeated installation modified executable or receipt.'
    }
    Write-Host 'PASS v0.5.2 reinstallation is a no-op'

    if ([Environment]::GetEnvironmentVariable('Path', 'User') -cne $oldUserPath) {
        throw 'User PATH changed despite -NoModifyPath.'
    }
    Write-Host 'PASS user PATH unchanged'
    $passed = $true
}
catch {
    Write-Warning "FAIL real-release integration: $($_.Exception.ToString())"
}
finally {
    if ($passed -and -not $KeepFiles) {
        try {
            Remove-Item -LiteralPath $root -Force -Recurse -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not clean disposable test directory: $($_.Exception.Message)"
            $passed = $false
        }
    }
}
if ($passed) {
    Write-Host 'Real Windows release upgrade test: PASS'
    if ($KeepFiles) { Write-Host "Retained test installation: $bin" }
    else { Write-Host 'Cleaned temporary test directory.' }
}
else {
    Write-Warning "Test evidence retained at: $root"
    exit 1
}
