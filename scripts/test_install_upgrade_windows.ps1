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
    $script:smokeCount = 0
    $script:failInstalledPostcheckPath = $null
    $script:failInstalledPostcheckVersion = '0.5.2'
    function Assert-ProoflineExeVersion([string]$Path, [string]$Version) {
        $script:smokeCount++
        if ($null -ne $script:failInstalledPostcheckPath -and
            $Path -ieq $script:failInstalledPostcheckPath -and
            $Version -ceq $script:failInstalledPostcheckVersion) {
            # Only the installed copy fails, never the staged verified image.
            throw 'Simulated installed executable postcheck failure.'
        }
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
    Check 'interrupted first-install stage is quarantined and retry can proceed' {
        $dir = Join-Path $root 'fresh-tampered'
        [IO.Directory]::CreateDirectory($dir) | Out-Null
        $id = [guid]::NewGuid().ToString('N')
        $stage = Join-Path $dir ('.proofline-staged-' + $id + '.exe')
        [IO.File]::WriteAllText($stage, 'INCOMPLETE_DOWNLOAD')
        $journal = Join-Path $dir '.proofline-install.pending.json'
        Write-ProoflineAtomicRecord $journal (ConvertTo-Json -Compress -InputObject ([ordered]@{
            schema = 3; id = $id; version = '0.5.1'; sha256 = $script:oldHash
        }))
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists($journal)) 'Incomplete first install blocked further attempts.'
        Require (-not [IO.File]::Exists($stage)) 'Incomplete bytes remained at executable stage path.'
        Require ([IO.File]::ReadAllText($stage + '.incomplete') -ceq 'INCOMPLETE_DOWNLOAD') 'Untrusted bytes not retained for diagnosis.'
        Require (-not [IO.File]::Exists((Join-Path $dir 'proofline.exe'))) 'Untrusted stage was installed.'
        [void](Install-ProoflineArchive $script:oldArchive $script:oldSums '0.5.1' $dir)
        Assert-ProoflineRecord (Join-Path $dir '.proofline-install.receipt.json') '0.5.1' $script:oldHash
    }
    Check 'first install with no passed postcheck quarantines instead of finalizing' {
        $dir = Join-Path $root 'fresh-published'
        [IO.Directory]::CreateDirectory($dir) | Out-Null
        $id = [guid]::NewGuid().ToString('N')
        [IO.File]::WriteAllBytes((Join-Path $dir 'proofline.exe'), (Get-ProoflineTarExecutable $script:oldArchive))
        $journal = Join-Path $dir '.proofline-install.pending.json'
        Write-ProoflineAtomicRecord $journal (ConvertTo-Json -Compress -InputObject ([ordered]@{
            schema = 3; id = $id; version = '0.5.1'; sha256 = $script:oldHash; postcheck = 'checking'
        }))
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists($journal)) 'Quarantine did not clear the first-install journal.'
        Require (-not [IO.File]::Exists((Join-Path $dir 'proofline.exe'))) 'Unverified first-install image became active.'
        Require (-not [IO.File]::Exists((Join-Path $dir '.proofline-install.receipt.json'))) 'Unverified first install received a receipt.'
        $evidence = Join-Path $dir ".proofline-unverified-first-$id.exe"
        Require ((Get-ProoflineSha256 $evidence) -ceq $script:oldHash) 'First-install quarantine lost the rejected candidate.'
        [void](Install-ProoflineArchive $script:oldArchive $script:oldSums '0.5.1' $dir)
        Assert-ProoflineRecord (Join-Path $dir '.proofline-install.receipt.json') '0.5.1' $script:oldHash
    }
    Check 'passed first-install postcheck allows finalization after crash' {
        $dir = Join-Path $root 'fresh-passed'
        [IO.Directory]::CreateDirectory($dir) | Out-Null
        $id = [guid]::NewGuid().ToString('N')
        [IO.File]::WriteAllBytes((Join-Path $dir 'proofline.exe'), (Get-ProoflineTarExecutable $script:oldArchive))
        $journal = Join-Path $dir '.proofline-install.pending.json'
        Write-ProoflineAtomicRecord $journal (ConvertTo-Json -Compress -InputObject ([ordered]@{
            schema = 3; id = $id; version = '0.5.1'; sha256 = $script:oldHash; postcheck = 'checking'
        }))
        Set-ProoflinePendingPostcheck $journal 'passed'
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists($journal)) 'Passed first-install journal remains.'
        Assert-ProoflineRecord (Join-Path $dir '.proofline-install.receipt.json') '0.5.1' $script:oldHash
        Require ((Get-ProoflineSha256 (Join-Path $dir 'proofline.exe')) -ceq $script:oldHash) 'Verified first-install image was lost.'
    }
    Check 'clean upgrade from previous verified install' {
        $dir = PrepareOld 'normal'
        $destination = Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir
        Require ((Get-ProoflineSha256 $destination) -ceq $script:newHash) 'New executable digest incorrect.'
        Assert-ProoflineRecord (Receipt 'normal') '0.5.2' $script:newHash
        Require (-not [IO.File]::Exists((Pending 'normal'))) 'Upgrade journal remains after success.'
        Require (@(Get-ChildItem -LiteralPath $dir -Force -Filter '.proofline-recovery*').Count -eq 0) 'Old backup not cleaned.'
    }
    Check 'failed installed-executable postcheck restores verified old release' {
        $dir = PrepareOld 'failed-postcheck'
        $script:failInstalledPostcheckPath = Active 'failed-postcheck'
        try {
            Must-Throw { [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir) }
        }
        finally { $script:failInstalledPostcheckPath = $null }
        Require ((Get-ProoflineSha256 (Active 'failed-postcheck')) -ceq $script:oldHash) 'Failed postcheck left the rejected new image active.'
        Assert-ProoflineRecord (Receipt 'failed-postcheck') '0.5.1' $script:oldHash
        Require (-not [IO.File]::Exists((Pending 'failed-postcheck'))) 'Successful rollback did not clear its journal.'
        $damaged = @(Get-ChildItem -LiteralPath $dir -Force |
            Where-Object { $_.Name -match '\A\.proofline-damaged-[0-9a-f]{32}\.exe\z' })
        Require ($damaged.Count -eq 1) 'Failed replacement was not quarantined.'
        Require ((Get-ProoflineSha256 $damaged[0].FullName) -ceq $script:newHash) 'Quarantined bytes do not match rejected release.'
        $debris = @(Get-ChildItem -LiteralPath $dir -Force |
            Where-Object { $_.Name -match '\A\.proofline-(recovery|api-backup|staged)-' })
        Require ($debris.Count -eq 0) 'Successful rollback left executable transaction files.'
        [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir)
        Assert-ProoflineRecord (Receipt 'failed-postcheck') '0.5.2' $script:newHash
    }
    Check 'interrupted in-progress postcheck restores old release' {
        $dir = PrepareOld 'checking-interrupted'
        [void](MakePending $dir)
        Set-ProoflinePendingPostcheck (Pending 'checking-interrupted') 'checking'
        [IO.File]::WriteAllBytes((Active 'checking-interrupted'), (Get-ProoflineTarExecutable $script:newArchive))
        Invoke-ProoflinePendingRepair $dir
        Require ((Get-ProoflineSha256 (Active 'checking-interrupted')) -ceq $script:oldHash) 'Interrupted postcheck was incorrectly treated as verified.'
        Assert-ProoflineRecord (Receipt 'checking-interrupted') '0.5.1' $script:oldHash
        Require (-not [IO.File]::Exists((Pending 'checking-interrupted'))) 'Interrupted postcheck rollback left its journal.'
    }
    Check 'missing rollback backup never silently adopts rejected executable' {
        $dir = PrepareOld 'failed-postcheck-no-backup'
        $paths = MakePending $dir
        Set-ProoflinePendingPostcheck (Pending 'failed-postcheck-no-backup') 'checking'
        [IO.File]::WriteAllBytes((Active 'failed-postcheck-no-backup'), (Get-ProoflineTarExecutable $script:newArchive))
        [IO.File]::Delete($paths.old)
        Must-Throw { Invoke-ProoflinePendingRepair $dir }
        Must-Throw { Invoke-ProoflinePendingRepair $dir }
        Require ([IO.File]::Exists((Pending 'failed-postcheck-no-backup'))) 'Missing-backup failure lost its pending journal.'
        $record = Read-ProoflinePending (Pending 'failed-postcheck-no-backup')
        Require ($record.postcheck -ceq 'checking') 'A failed postcheck lost its durable rejection marker.'
        Assert-ProoflineRecord (Receipt 'failed-postcheck-no-backup') '0.5.1' $script:oldHash
        Require ((Get-ProoflineSha256 (Active 'failed-postcheck-no-backup')) -ceq $script:newHash) 'Recovery modified a file without a verified rollback source.'
    }
    Check 'completed postcheck permits interrupted receipt finalization' {
        $dir = PrepareOld 'passed-before-receipt'
        [void](MakePending $dir)
        Set-ProoflinePendingPostcheck (Pending 'passed-before-receipt') 'checking'
        [IO.File]::WriteAllBytes((Active 'passed-before-receipt'), (Get-ProoflineTarExecutable $script:newArchive))
        Set-ProoflinePendingPostcheck (Pending 'passed-before-receipt') 'passed'
        Invoke-ProoflinePendingRepair $dir
        Require ((Get-ProoflineSha256 (Active 'passed-before-receipt')) -ceq $script:newHash) 'Recovery rolled back an explicitly passed postcheck.'
        Assert-ProoflineRecord (Receipt 'passed-before-receipt') '0.5.2' $script:newHash
        Require (-not [IO.File]::Exists((Pending 'passed-before-receipt'))) 'Passed-postcheck recovery left its journal.'
    }
    Check 'failed first-install postcheck quarantines on next recovery' {
        $dir = Join-Path $root 'fresh-failed-installed-check'
        $script:failInstalledPostcheckPath = Join-Path $dir 'proofline.exe'
        $script:failInstalledPostcheckVersion = '0.5.1'
        try {
            Must-Throw { [void](Install-ProoflineArchive $script:oldArchive $script:oldSums '0.5.1' $dir) }
        }
        finally {
            $script:failInstalledPostcheckPath = $null
            $script:failInstalledPostcheckVersion = '0.5.2'
        }
        Require ([IO.File]::Exists((Pending 'fresh-failed-installed-check'))) 'Failed first install did not retain journal.'
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists((Active 'fresh-failed-installed-check'))) 'Rejected first-install executable remained active.'
        $evidence = @(Get-ChildItem -LiteralPath $dir -Filter '.proofline-unverified-first-*.exe')
        Require ($evidence.Count -eq 1) 'Rejected first-install image was not quarantined.'
        Require ((Get-ProoflineSha256 $evidence[0].FullName) -ceq $script:oldHash) 'Quarantined first-install bytes changed.'
        [void](Install-ProoflineArchive $script:oldArchive $script:oldSums '0.5.1' $dir)
        Assert-ProoflineRecord (Receipt 'fresh-failed-installed-check') '0.5.1' $script:oldHash
    }
    Check 'upgrade without postcheck marker rolls back matching new image' {
        $dir = PrepareOld 'legacy-unchecked-upgrade'
        [void](MakePending $dir)
        [IO.File]::WriteAllBytes((Active 'legacy-unchecked-upgrade'), (Get-ProoflineTarExecutable $script:newArchive))
        Invoke-ProoflinePendingRepair $dir
        Require ((Get-ProoflineSha256 (Active 'legacy-unchecked-upgrade')) -ceq $script:oldHash) 'Markerless upgrade was finalized by hash alone.'
        Assert-ProoflineRecord (Receipt 'legacy-unchecked-upgrade') '0.5.1' $script:oldHash
        Require (-not [IO.File]::Exists((Pending 'legacy-unchecked-upgrade'))) 'Rollback journal remains.'
    }
    Check 'unreadable primary backup falls back to verified secondary copy' {
        $dir = PrepareOld 'backup-fallback'
        $paths = MakePending $dir
        [IO.File]::Copy($paths.old, $paths.api, $false)
        [IO.File]::WriteAllBytes((Active 'backup-fallback'), (Get-ProoflineTarExecutable $script:newArchive))
        Set-ProoflinePendingPostcheck (Pending 'backup-fallback') 'checking'
        $originalDigest = (Get-Item Function:\Get-ProoflineSha256).ScriptBlock
        $script:blockedBackup = $paths.old
        $script:realDigest = $originalDigest
        try {
            Set-Item Function:\Get-ProoflineSha256 -Value {
                param([string]$Path)
                if ($Path -ieq $script:blockedBackup) { throw [IO.IOException]::new('Simulated unreadable primary backup.') }
                & $script:realDigest $Path
            }
            Invoke-ProoflinePendingRepair $dir
        }
        finally {
            Set-Item Function:\Get-ProoflineSha256 -Value $originalDigest
            $script:blockedBackup = $null
            $script:realDigest = $null
        }
        Require ((Get-ProoflineSha256 (Active 'backup-fallback')) -ceq $script:oldHash) 'Verified secondary backup did not restore old release.'
        Assert-ProoflineRecord (Receipt 'backup-fallback') '0.5.1' $script:oldHash
        Require (-not [IO.File]::Exists((Pending 'backup-fallback'))) 'Fallback recovery left pending journal.'
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
        $before = $script:smokeCount
        [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir)
        Require ($script:smokeCount -eq $before) 'No-op installation executed the pre-existing local executable.'
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
    Check 'interrupted upgrade stage is quarantined without blocking retry' {
        $dir = PrepareOld 'tampered-stage'
        $paths = MakePending $dir
        [IO.File]::WriteAllText($paths.stage, 'NOT_THE_VERIFIED_CANDIDATE', [Text.Encoding]::ASCII)
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists((Pending 'tampered-stage'))) 'Pre-switch retry is still blocked.'
        Require (-not [IO.File]::Exists($paths.stage)) 'Unverified stage remained available for execution.'
        Require ([IO.File]::ReadAllText($paths.stage + '.incomplete') -ceq 'NOT_THE_VERIFIED_CANDIDATE') 'Quarantined evidence is missing.'
        Require ((Get-ProoflineSha256 (Active 'tampered-stage')) -ceq $script:oldHash) 'Old executable was changed.'
        [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir)
        Assert-ProoflineRecord (Receipt 'tampered-stage') '0.5.2' $script:newHash
    }
    Check 'new active detected and finalized after restart' {
        $dir = PrepareOld 'finalize'
        $paths = MakePending $dir
        Set-ProoflinePendingPostcheck (Pending 'finalize') 'checking'
        [IO.File]::WriteAllBytes((Active 'finalize'), (Get-ProoflineTarExecutable $script:newArchive))
        Set-ProoflinePendingPostcheck (Pending 'finalize') 'passed'
        $before = $script:smokeCount
        Invoke-ProoflinePendingRepair $dir
        Require ($script:smokeCount -eq $before) 'Recovery executed pre-existing executable verified only by local journal.'
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
    Check 'crash before upgrade stage creation has a recoverable journal' {
        $dir = PrepareOld 'preparation'
        $paths = MakePending $dir
        [IO.File]::Delete($paths.old)
        # The upgrade can now be killed after journaling but before creating
        # a stage or a verified old backup.
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists((Pending 'preparation'))) 'Upgrade preparation record blocked retry.'
        Require ((Get-ProoflineSha256 (Active 'preparation')) -ceq $script:oldHash) 'Previous executable changed.'
        [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir)
        Require ((Get-ProoflineSha256 (Active 'preparation')) -ceq $script:newHash) 'Upgrade could not retry.'
    }
    Check 'verified normal upgrade is never undone by cleanup failure' {
        $dir = PrepareOld 'cleanup-normal'
        $originalCleanup = (Get-Item Function:\Clear-ProoflineUpgradeFiles).ScriptBlock
        try {
            Set-Item Function:\Clear-ProoflineUpgradeFiles -Value {
                throw 'Simulated cleanup deletion failure after verified upgrade.'
            }
            [void](Install-ProoflineArchive $script:newArchive $script:newSums '0.5.2' $dir)
        }
        finally { Set-Item Function:\Clear-ProoflineUpgradeFiles -Value $originalCleanup }
        Require ((Get-ProoflineSha256 (Active 'cleanup-normal')) -ceq $script:newHash) 'Cleanup failure rolled back a verified upgrade.'
        Assert-ProoflineRecord (Receipt 'cleanup-normal') '0.5.2' $script:newHash
        Require ([IO.File]::Exists((Pending 'cleanup-normal'))) 'Cleanup failure lost retry journal.'
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists((Pending 'cleanup-normal'))) 'Retried cleanup did not clear the journal.'
        Require ((Get-ProoflineSha256 (Active 'cleanup-normal')) -ceq $script:newHash) 'Retried cleanup changed the verified executable.'
    }
    Check 'verified recovered upgrade is never undone by cleanup failure' {
        $dir = PrepareOld 'cleanup-recovery'
        [void](MakePending $dir)
        Set-ProoflinePendingPostcheck (Pending 'cleanup-recovery') 'checking'
        [IO.File]::WriteAllBytes((Active 'cleanup-recovery'), (Get-ProoflineTarExecutable $script:newArchive))
        Set-ProoflinePendingPostcheck (Pending 'cleanup-recovery') 'passed'
        $originalCleanup = (Get-Item Function:\Clear-ProoflineUpgradeFiles).ScriptBlock
        try {
            Set-Item Function:\Clear-ProoflineUpgradeFiles -Value {
                throw 'Simulated cleanup deletion failure during recovery.'
            }
            Invoke-ProoflinePendingRepair $dir
        }
        finally { Set-Item Function:\Clear-ProoflineUpgradeFiles -Value $originalCleanup }
        Assert-ProoflineRecord (Receipt 'cleanup-recovery') '0.5.2' $script:newHash
        Require ((Get-ProoflineSha256 (Active 'cleanup-recovery')) -ceq $script:newHash) 'Cleanup failure restored old executable.'
        Require ([IO.File]::Exists((Pending 'cleanup-recovery'))) 'Recovery cleanup failure lost its journal.'
        Invoke-ProoflinePendingRepair $dir
        Require (-not [IO.File]::Exists((Pending 'cleanup-recovery'))) 'Recovery cleanup did not finish on retry.'
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
