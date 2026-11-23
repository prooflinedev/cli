#requires -Version 5.1
<#
.SYNOPSIS
  Offline installer-managed Windows upgrade/recovery tests.
.DESCRIPTION
  Uses fake PE fixtures that are NEVER executed. Replaces executable version
  smoke-check function with a strict digest assertion inside this test scope.
  No download, user PATH modification, or real Proofline installation.
#>
[CmdletBinding()]
param([string]$Python = 'python')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run these tests on Windows.'
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('proofline-upgrade-tests-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$passed = 0
$failed = 0

function Check([string]$Name, [scriptblock]$Case) {
    try {
        & $Case
        $script:passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:failed++
        Write-Warning "FAIL $Name : $($_.Exception.ToString())"
    }
}
function Require([bool]$Condition, [string]$Explanation) {
    if (-not $Condition) { throw $Explanation }
}
function Must-Throw([scriptblock]$Case) {
    $didThrow = $false
    try { & $Case | Out-Null } catch { $didThrow = $true }
    if (-not $didThrow) { throw 'Expected an error, but operation succeeded.' }
}
function Fixture([string]$Name) {
    return ,([IO.File]::ReadAllBytes((Join-Path $root $Name)))
}
function Active([string]$Name) {
    return (Join-Path (Join-Path $root $Name) 'proofline.exe')
}
function Receipt([string]$Name) {
    return (Join-Path (Join-Path $root $Name) '.proofline-install.receipt.json')
}
function Pending([string]$Name) {
    return (Join-Path (Join-Path $root $Name) '.proofline-install.pending.json')
}
function Get-ProoflineSha256FileBytes([byte[]]$Value) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($Value)).Replace('-', '') }
    finally { $hash.Dispose() }
}
function PrepareOld([string]$Name) {
    $directory = Join-Path $root $Name
    $installed = Install-ProoflineArchive $script:oldArchive $script:oldSums '0.5.1' $directory
    Require ((Get-ProoflineSha256 $installed) -ceq $script:oldHash) 'Old fixture did not install.'
    return $directory
}
function MakePending([string]$Directory) {
    $id = [guid]::NewGuid().ToString('N')
    $paths = Get-ProoflineTransactionPaths $Directory $id
    $active = Join-Path $Directory 'proofline.exe'
    [IO.File]::Copy($active, $paths.old, $false)
    $pendingPath = Join-Path $Directory '.proofline-install.pending.json'
    $json = ConvertTo-Json -Compress -InputObject ([ordered]@{
        schema = 2
        id = $id
        oldVersion = '0.5.1'
        oldSha256 = $script:oldHash
        newVersion = '0.5.2'
        newSha256 = $script:newHash
    })
    Write-ProoflineAtomicRecord $pendingPath $json
    return $paths
}

try {
    $scriptDir = $PSScriptRoot
    & $Python (Join-Path $scriptDir 'generate_windows_installer_fixtures.py') $root | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed.' }
    . (Join-Path (Split-Path -Parent $scriptDir) 'install.ps1')
    $script:oldArchive = Fixture 'valid.tar.gz'
    $script:oldSums = Fixture 'SHA256SUMS'
    $script:newArchive = Fixture 'upgrade.tar.gz'
    $script:newSums = Fixture 'SHA256SUMS-upgrade'
    $script:oldHash = Get-ProoflineSha256FileBytes (Get-ProoflineTarExecutable $script:oldArchive)
    $script:newHash = Get-ProoflineSha256FileBytes (Get-ProoflineTarExecutable $script:newArchive)

    # Test-only shadow function: fake PE fixtures are not runnable and must
    # NEVER be started. Production installer calls the original version checker.
    function Assert-ProoflineExeVersion([string]$Path, [string]$Version) {
        $digest = Get-ProoflineSha256 $Path
        $expected = switch ($Version) {
            '0.5.1' { $script:oldHash; break }
            '0.5.2' { $script:newHash; break }
            default { throw "Unexpected test-only version $Version" }
        }
        if ($digest -cne $expected) {
            throw "Test fixture for $Version has unexpected digest."
        }
    }

    Check 'interrupted fresh install cleans only verified matching stage' {
        $dir = Join-Path $root 'fresh-stage'
        [IO.Directory]::CreateDirectory($dir) | Out-Null
        $id = [guid]::NewGuid().ToString('N')
        $stage = Join-Path $dir ('.proofline-staged-' + $id + '.exe')
        $other = Join-Path $dir ('.proofline-staged-' + [guid]::NewGuid().ToString('N') + '.exe')
        [IO.File]::WriteAllBytes($stage, (Get-ProoflineTarExecutable $script:oldArchive))
        [IO.File]::WriteAllText($other, 'UNRELATED_STAGING_EVIDENCE')
        Write-ProoflineAtomicRecord (Join-Path $dir '.proofline-install.pending.json') (ConvertTo-Json -Compress -InputObject ([ordered]@{
            schema = 3; id = $id; version = '0.5.1'; sha256 = $script:oldHash
        }))
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists($stage)) 'Transaction-owned verified stage survived cleanup.'
        Require ([IO.File]::Exists($other)) 'Unrelated staged file was removed.'
        Require (-not [IO.File]::Exists((Join-Path $dir '.proofline-install.pending.json'))) 'Fresh pending record remains.'
        Require (-not [IO.File]::Exists((Join-Path $dir 'proofline.exe'))) 'Interrupted install unexpectedly published an executable.'
    }
    Check 'interrupted fresh install refuses an unverified stage' {
        $dir = Join-Path $root 'fresh-tampered'
        [IO.Directory]::CreateDirectory($dir) | Out-Null
        $id = [guid]::NewGuid().ToString('N')
        $stage = Join-Path $dir ('.proofline-staged-' + $id + '.exe')
        [IO.File]::WriteAllText($stage, 'INCOMPLETE_DOWNLOAD')
        $journal = Join-Path $dir '.proofline-install.pending.json'
        Write-ProoflineAtomicRecord $journal (ConvertTo-Json -Compress -InputObject ([ordered]@{
            schema = 3; id = $id; version = '0.5.1'; sha256 = $script:oldHash
        }))
        Must-Throw { Invoke-ProoflinePendingRepair $dir }
        Require ([IO.File]::Exists($journal)) 'Journal vanished despite unrecognized stage.'
        Require ([IO.File]::Exists($stage)) 'Unverified stage was silently discarded.'
    }
    Check 'interrupted fresh install finalizes verified published executable' {
        $dir = Join-Path $root 'fresh-published'
        [IO.Directory]::CreateDirectory($dir) | Out-Null
        $id = [guid]::NewGuid().ToString('N')
        [IO.File]::WriteAllBytes((Join-Path $dir 'proofline.exe'), (Get-ProoflineTarExecutable $script:oldArchive))
        $journal = Join-Path $dir '.proofline-install.pending.json'
        Write-ProoflineAtomicRecord $journal (ConvertTo-Json -Compress -InputObject ([ordered]@{
            schema = 3; id = $id; version = '0.5.1'; sha256 = $script:oldHash
        }))
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists($journal)) 'Journal not cleared after successful receipt recovery.'
        Assert-ProoflineRecord (Join-Path $dir '.proofline-install.receipt.json') '0.5.1' $script:oldHash
        Require ((Get-ProoflineSha256 (Join-Path $dir 'proofline.exe')) -ceq $script:oldHash) 'First-install recovery modified verified bytes.'
    }
    Check 'clean upgrade from previous verified install' {
        $dir = PrepareOld 'normal'
        $destination = Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir
        Require ((Get-ProoflineSha256 $destination) -ceq $script:newHash) 'New executable digest incorrect.'
        Assert-ProoflineRecord (Receipt 'normal') '0.5.2' $script:newHash
        Require (-not [IO.File]::Exists((Pending 'normal'))) 'Upgrade journal remains after success.'
        Require (@(Get-ChildItem -LiteralPath $dir -Force -Filter '.proofline-recovery*').Count -eq 0) 'Old backup not cleaned.'
    }
    Check 'receipt replacement preserves and cleans up its backup' {
        $dir = PrepareOld 'receipt-backup'
        $receiptPath = Receipt 'receipt-backup'
        Write-ProoflineReceipt $receiptPath '0.5.2' $script:newHash
        Assert-ProoflineRecord $receiptPath '0.5.2' $script:newHash
        $leftovers = @(Get-ChildItem -LiteralPath $dir -Force |
            Where-Object { $_.Name -like '.proofline-install.receipt.json.*' })
        Require ($leftovers.Count -eq 0) 'Receipt replacement left temporary or backup files.'
    }
    Check 'only sharing/lock HRESULTs are retryable' {
        $sharing = [IO.IOException]::new('temporarily held', -2147024864)
        $lock = [IO.IOException]::new('range locked', -2147024863)
        $denied = [UnauthorizedAccessException]::new('denied')
        $other = [IO.IOException]::new('not a sharing violation')
        Require (Test-ProoflineTransientReplaceFailure $sharing) 'Sharing violation not recognized.'
        Require (Test-ProoflineTransientReplaceFailure $lock) 'Lock violation not recognized.'
        Require (-not (Test-ProoflineTransientReplaceFailure $denied)) 'Access denial must not be retried.'
        Require (-not (Test-ProoflineTransientReplaceFailure $other)) 'Unrelated IO failure must not be retried.'
    }
    Check 'repeat upgrade is idempotent' {
        $dir = PrepareOld 'repeat'
        [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir)
        [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir)
        Require ((Get-ProoflineSha256 (Active 'repeat')) -ceq $script:newHash) 'Repeat changed active bytes.'
        Assert-ProoflineRecord (Receipt 'repeat') '0.5.2' $script:newHash
    }
    Check 'interrupted pre-switch stage cleaned by matching transaction ID' {
        $dir = PrepareOld 'pre-switch-stage'
        $paths = MakePending $dir
        [IO.File]::WriteAllBytes($paths.stage, (Get-ProoflineTarExecutable $script:newArchive))
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists($paths.stage)) 'Verified staged executable survived completed recovery.'
        Require (-not [IO.File]::Exists((Pending 'pre-switch-stage'))) 'Recovered transaction journal remains.'
        Require ((Get-ProoflineSha256 (Active 'pre-switch-stage')) -ceq $script:oldHash) 'Old executable changed.'
        Assert-ProoflineRecord (Receipt 'pre-switch-stage') '0.5.1' $script:oldHash
    }
    Check 'untrusted pre-switch stage is preserved with the journal' {
        $dir = PrepareOld 'tampered-stage'
        $paths = MakePending $dir
        [IO.File]::WriteAllText($paths.stage, 'NOT_THE_VERIFIED_CANDIDATE', [Text.Encoding]::ASCII)
        Must-Throw { Invoke-ProoflinePendingRepair $dir }
        Require ([IO.File]::Exists((Pending 'tampered-stage'))) 'Unknown staged data lost its pending record.'
        Require ([IO.File]::Exists($paths.stage)) 'Unknown staged data was deleted.'
        Require ((Get-ProoflineSha256 (Active 'tampered-stage')) -ceq $script:oldHash) 'Old executable was changed.'
    }
    Check 'new active detected and finalized after restart' {
        $dir = PrepareOld 'finalize'
        $paths = MakePending $dir
        [IO.File]::WriteAllBytes((Active 'finalize'), (Get-ProoflineTarExecutable $script:newArchive))
        Invoke-ProoflinePendingRepair $dir
        Require ((Get-ProoflineSha256 (Active 'finalize')) -ceq $script:newHash) 'New active hash was lost.'
        Assert-ProoflineRecord (Receipt 'finalize') '0.5.2' $script:newHash
        Require (-not [IO.File]::Exists((Pending 'finalize'))) 'Pending journal not cleared.'
    }
    Check 'corrupt active restored from verified previous copy' {
        $dir = PrepareOld 'rollback'
        $paths = MakePending $dir
        [IO.File]::WriteAllText((Active 'rollback'), 'BROKEN', [Text.Encoding]::ASCII)
        Invoke-ProoflinePendingRepair $dir
        Require ((Get-ProoflineSha256 (Active 'rollback')) -ceq $script:oldHash) 'Old binary not restored.'
        Assert-ProoflineRecord (Receipt 'rollback') '0.5.1' $script:oldHash
        Require (-not [IO.File]::Exists((Pending 'rollback'))) 'Pending record remains after successful recovery.'
    }
    Check 'ambiguous state refuses and preserves evidence' {
        $dir = PrepareOld 'ambiguous'
        $paths = MakePending $dir
        [IO.File]::WriteAllText((Active 'ambiguous'), 'BROKEN', [Text.Encoding]::ASCII)
        [IO.File]::WriteAllText($paths.old, 'BAD', [Text.Encoding]::ASCII)
        Must-Throw { Invoke-ProoflinePendingRepair $dir }
        Require ([IO.File]::Exists((Pending 'ambiguous'))) 'Pending journal was removed in ambiguous state.'
        Require ((Get-ProoflineSha256 (Active 'ambiguous')) -cne $script:oldHash) 'Unverified bytes overwritten.'
    }
    Check 'exclusive lock refuses second installer without mutation' {
        $dir = PrepareOld 'locked'
        $lock = Join-Path $dir '.proofline-install.lock'
        $stream = [IO.File]::Open($lock, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            Must-Throw {
                [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir)
            }
        }
        finally { $stream.Dispose() }
        Require ((Get-ProoflineSha256 (Active 'locked')) -ceq $script:oldHash) 'Locked installer changed active executable.'
    }
}
finally {
    if ($failed -eq 0) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Offline Windows upgrade tests: $passed passed, $failed failed."
if ($failed -ne 0) {
    Write-Warning "Failed fixtures retained at $root"
    exit 1
}
