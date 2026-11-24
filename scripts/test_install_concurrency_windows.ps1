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
    [string]$HoldToken,
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
    $driver = Split-Path -Parent $folder
    if ([IO.Path]::GetDirectoryName($driver) -ine [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char]'\') -or
        [IO.Path]::GetFileName($driver) -cnotmatch '\Aproofline-concurrent-[0-9a-f]{32}\z' -or
        [IO.Path]::GetFileName($folder) -cne 'bin') {
        throw 'Holder refused a directory outside the disposable test sandbox.'
    }
    foreach ($path in @($driver, $folder)) {
        if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Holder refused a reparse-point test directory.'
        }
    }
    $marker = Join-Path $folder '.proofline-test-only'
    if ($HoldToken -cnotmatch '\A[0-9a-f]{32}\z') {
        throw 'Refusing to hold lock without a valid test token.'
    }
    # The rename is an atomic, exclusive claim: only one competing holder
    # can move this single-use marker. Validate after claiming it.
    $claimed = Join-Path $folder ('.proofline-test-claimed-' + $HoldToken)
    if ([IO.File]::Exists($claimed)) { throw 'Test marker was already claimed.' }
    try { [IO.File]::Move($marker, $claimed) }
    catch { throw 'Refusing to hold lock: fresh disposable test marker is unavailable or already claimed.' }
    $validatedClaim = $false
    try {
        if ([IO.File]::ReadAllText($claimed) -cne "DISPOSABLE_LOCK_TEST:$HoldToken") {
            # Preserve an unrecognized claim if restoration fails or a
            # replacement marker appeared. Never delete another test's token.
            if (-not [IO.File]::Exists($marker)) { [IO.File]::Move($claimed, $marker) }
            throw 'Refusing to hold lock: claimed marker has unexpected contents.'
        }
        $validatedClaim = $true
    }
    finally {
        if ($validatedClaim -and [IO.File]::Exists($claimed)) { [IO.File]::Delete($claimed) }
    }
    # Hold the *production* installer lock, not a separately manufactured
    # FileShare.None handle. Otherwise the test passes even if the installer
    # accidentally weakens its own lock sharing policy.
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1')
    $script:holderOriginalReceipt = (Get-Item Function:\Read-ProoflineReceipt).ScriptBlock
    $script:holderReady = Join-Path $folder '.holder-ready'
    $script:holderRelease = Join-Path $folder '.holder-release'
    function Read-ProoflineReceipt([string]$Path) {
        # Install-ProoflineArchive reaches this function only after opening
        # the production lock, so parent contention exercises that lock.
        [IO.File]::WriteAllText($script:holderReady, 'LOCK_HELD')
        $expires = [DateTime]::UtcNow.AddSeconds(25)
        while ([DateTime]::UtcNow -lt $expires -and -not [IO.File]::Exists($script:holderRelease)) {
            Start-Sleep -Milliseconds 100
        }
        if (-not [IO.File]::Exists($script:holderRelease)) {
            throw 'Holder timed out waiting for parent release signal.'
        }
        return (& $script:holderOriginalReceipt $Path)
    }
    $archive = [IO.File]::ReadAllBytes((Join-Path $driver 'valid.tar.gz'))
    $sums = [IO.File]::ReadAllBytes((Join-Path $driver 'SHA256SUMS'))
    [void](Install-ProoflineArchive $archive $sums '0.5.1' $folder)
    exit 0
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('proofline-concurrent-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$bin = Join-Path $root 'bin'
[IO.Directory]::CreateDirectory($bin) | Out-Null
$holdToken = [guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText((Join-Path $bin '.proofline-test-only'), "DISPOSABLE_LOCK_TEST:$holdToken")
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
    function Assert-ProoflineExeVersion([string]$Path, [string]$Version, [string]$ExpectedSha256) {
        $expected = switch ($Version) {
            '0.5.1' { $script:oldHash; break }
            '0.5.2' { $script:newHash; break }
            default { throw "Unexpected fixture version $Version" }
        }
        if ($ExpectedSha256 -cne $expected) {
            throw "Version check for $Version omitted or supplied an incorrect digest."
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
        '" -Mode Hold -CaseDir "' + $bin + '" -HoldToken "' + $holdToken + '"'
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

    $stagesBefore = @(Get-ChildItem -LiteralPath $bin -Force -Filter '.proofline-staged-*.exe' | ForEach-Object FullName)
    Assert-Condition ($stagesBefore.Count -eq 0) 'Test fixture unexpectedly contains staged executables before refusal.'
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
    $stagesAfter = @(Get-ChildItem -LiteralPath $bin -Force -Filter '.proofline-staged-*.exe' | ForEach-Object FullName)
    Assert-Condition ($stagesAfter.Count -eq $stagesBefore.Count) 'Competing installer staged executable bytes before acquiring lock.'
    Write-Host 'PASS competing installer refused; old executable, receipt, stage and journal unchanged.'

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
