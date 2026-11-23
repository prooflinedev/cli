#requires -Version 5.1
<#
.SYNOPSIS
  Tests cross-process Windows installer locking with disposable local fixtures.
.DESCRIPTION
  No network, admin rights, PATH changes, or real executable execution.
  The main test invokes a separate PowerShell holder process, then checks that
  a competing upgrade refuses to modify its verified previous installation.
  The holder mode is internal to this test and requires a fresh test marker.
#>
[CmdletBinding()]
param(
    [ValidateSet('Test', 'Hold')][string]$Mode = 'Test',
    [string]$CaseDir,
    [string]$Python = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this test on Windows.'
}

if ($Mode -eq 'Hold') {
    if ([string]::IsNullOrWhiteSpace($CaseDir)) { throw 'Holder needs CaseDir.' }
    $folder = [IO.Path]::GetFullPath($CaseDir)
    $marker = Join-Path $folder '.proofline-test-only'
    if (-not [IO.File]::Exists($marker) -or
        [IO.File]::ReadAllText($marker) -cne 'DISPOSABLE_LOCK_TEST') {
        throw 'Refusing to hold lock without disposable test marker.'
    }
    $lock = Join-Path $folder '.proofline-install.lock'
    $ready = Join-Path $folder '.holder-ready'
    $release = Join-Path $folder '.holder-release'
    $stream = [IO.File]::Open($lock, [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        [IO.File]::WriteAllText($ready, 'LOCK_HELD')
        $expires = [DateTime]::UtcNow.AddSeconds(25)
        while ([DateTime]::UtcNow -lt $expires -and -not [IO.File]::Exists($release)) {
            Start-Sleep -Milliseconds 100
        }
        if (-not [IO.File]::Exists($release)) {
            throw 'Holder timed out waiting for parent release signal.'
        }
    }
    finally { $stream.Dispose() }
    exit 0
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('proofline-concurrent-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$bin = Join-Path $root 'bin'
[IO.Directory]::CreateDirectory($bin) | Out-Null
[IO.File]::WriteAllText((Join-Path $bin '.proofline-test-only'), 'DISPOSABLE_LOCK_TEST')
$holder = $null
$passed = $false
$holderReady = Join-Path $bin '.holder-ready'
$holderRelease = Join-Path $bin '.holder-release'

function Assert-Condition([bool]$Value, [string]$Message) {
    if (-not $Value) { throw $Message }
}
function Digest-Bytes([byte[]]$Data) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Data)).Replace('-', '') }
    finally { $sha.Dispose() }
}

try {
    & $Python (Join-Path $PSScriptRoot 'generate_windows_installer_fixtures.py') $root | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Offline fixture generator failed.' }
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1')
    $oldArchive = [IO.File]::ReadAllBytes((Join-Path $root 'valid.tar.gz'))
    $oldManifest = [IO.File]::ReadAllBytes((Join-Path $root 'SHA256SUMS'))
    $newArchive = [IO.File]::ReadAllBytes((Join-Path $root 'upgrade.tar.gz'))
    $newManifest = [IO.File]::ReadAllBytes((Join-Path $root 'SHA256SUMS-upgrade'))
    $script:oldHash = Digest-Bytes (Get-ProoflineTarExecutable $oldArchive)
    $script:newHash = Digest-Bytes (Get-ProoflineTarExecutable $newArchive)

    # This is test-only: artificial PE fixtures must never be executed.
    function Assert-ProoflineExeVersion([string]$Path, [string]$Version) {
        $expected = switch ($Version) {
            '0.5.1' { $script:oldHash; break }
            '0.5.2' { $script:newHash; break }
            default { throw "Unexpected fixture version $Version" }
        }
        if ((Get-ProoflineSha256 $Path) -cne $expected) {
            throw "Invalid fixture contents for $Version"
        }
    }

    $active = Install-ProoflineArchive $oldArchive $oldManifest '0.5.1' $bin
    Assert-Condition ((Get-ProoflineSha256 $active) -ceq $script:oldHash) 'Old fixture did not install.'
    $receipt = Join-Path $bin '.proofline-install.receipt.json'
    Assert-ProoflineRecord $receipt '0.5.1' $script:oldHash

    $powershell = (Get-Process -Id $PID).Path
    $args = '-NoProfile -NonInteractive -File "' + $PSCommandPath +
        '" -Mode Hold -CaseDir "' + $bin + '"'
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $powershell
    $start.Arguments = $args
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $holder = [Diagnostics.Process]::Start($start)
    if ($null -eq $holder) { throw 'Could not start lock holder process.' }

    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    while (-not [IO.File]::Exists($holderReady) -and [DateTime]::UtcNow -lt $deadline) {
        if ($holder.HasExited) { throw 'Lock holder exited before readiness.' }
        Start-Sleep -Milliseconds 100
    }
    Assert-Condition ([IO.File]::Exists($holderReady)) 'Lock holder did not signal readiness.'
    Assert-Condition (-not $holder.HasExited) 'Lock holder exited before contested upgrade.'
    Write-Host 'Separate PowerShell process holds installer lock.'

    $refused = $false
    try {
        [void](Install-ProoflineArchive $newArchive $newManifest '0.5.2' $bin)
    }
    catch {
        if ($_.Exception.Message -match 'Another installer may be running|lock file is unavailable') {
            $refused = $true
        }
        else { throw }
    }
    Assert-Condition $refused 'Competing installer was not rejected due to exclusive lock.'
    Assert-Condition ((Get-ProoflineSha256 $active) -ceq $script:oldHash) 'Concurrent attempt changed active executable.'
    Assert-ProoflineRecord $receipt '0.5.1' $script:oldHash
    Assert-Condition (-not [IO.File]::Exists((Join-Path $bin '.proofline-install.pending.json'))) 'Concurrent attempt left a journal.'
    Write-Host 'PASS competing installer refused; old executable, receipt and journal unchanged.'

    [IO.File]::WriteAllText($holderRelease, 'RELEASE')
    if (-not $holder.WaitForExit(10000)) { throw 'Holder did not exit after release.' }
    Assert-Condition ($holder.ExitCode -eq 0) "Lock holder exited $($holder.ExitCode)."
    Write-Host 'PASS second process released lock cleanly.'

    $upgraded = Install-ProoflineArchive $newArchive $newManifest '0.5.2' $bin
    Assert-Condition ((Get-ProoflineSha256 $upgraded) -ceq $script:newHash) 'Upgrade after lock release failed.'
    Assert-ProoflineRecord $receipt '0.5.2' $script:newHash
    Assert-Condition (-not [IO.File]::Exists((Join-Path $bin '.proofline-install.pending.json'))) 'Upgrade left a journal.'
    Write-Host 'PASS upgrade succeeds after competing process releases lock.'
    $passed = $true
}
catch {
    Write-Warning "FAIL cross-process lock test: $($_.Exception.ToString())"
}
finally {
    if ($null -ne $holder) {
        try {
            if (-not $holder.HasExited) {
                # This child was created solely for the disposable test.
                $holder.Kill()
                $holder.WaitForExit(5000) | Out-Null
            }
        }
        catch {
            Write-Warning "Could not stop test lock holder process: $($_.Exception.Message)"
            $passed = $false
        }
        $holder.Dispose()
    }
    if ($passed) {
        try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        catch {
            $passed = $false
            Write-Warning "Could not clean test sandbox: $($_.Exception.Message)"
        }
    }
}
if ($passed) {
    Write-Host 'Cross-process Windows lock integration: PASS; temporary files cleaned.'
}
else {
    Write-Warning "Failure evidence retained at: $root"
    exit 1
}
