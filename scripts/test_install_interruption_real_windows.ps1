#requires -Version 5.1
<#
.SYNOPSIS
  End-to-end tests for forcibly interrupted Windows executable installs and upgrades.
.DESCRIPTION
  Downloads two pinned official Proofline releases once, installs into
  disposable GUID-named TEMP directories, and generates INSTRUMENTED COPIES
  of install.ps1 in the test sandbox. A child PowerShell process runs actual
  Install-ProoflineArchive and terminates itself at a chosen checkpoint.
  Another fresh process calls the unmodified installer's recovery function.
  NEVER changes PATH or an existing Proofline installation.
  Does not simulate an OS crash, disk loss, or power failure.
#>
[CmdletBinding()]
param(
    [ValidateSet('Driver', 'Worker', 'Recover')]
    [string]$Mode = 'Driver',
    [string]$CaseDir,
    [string]$InstallerCopy,
    [string]$FixtureDir,
    [string]$DriverRoot,
    [string]$TestToken,
    [switch]$LatestOutage,
    [switch]$KeepFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Windows is required for the interruption integration test.'
}
$originalInstaller = Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1'

function Require([bool]$Ok, [string]$Message) {
    if (-not $Ok) { throw $Message }
}
function Get-TestBytes([string]$Directory, [string]$Name) {
    return ,([IO.File]::ReadAllBytes((Join-Path $Directory $Name)))
}
function Assert-Sandbox([string]$Directory, [string]$RunRoot, [string]$Token) {
    if ([string]::IsNullOrWhiteSpace($Directory) -or
        [string]::IsNullOrWhiteSpace($RunRoot) -or
        $Token -cnotmatch '\A[0-9a-f]{32}\z') {
        throw 'Missing validated interruption-test sandbox identity.'
    }
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char]'\')
    $root = [IO.Path]::GetFullPath($RunRoot).TrimEnd([char]'\')
    $case = [IO.Path]::GetFullPath($Directory).TrimEnd([char]'\')
    if ([IO.Path]::GetDirectoryName($root) -ine $temp -or
        [IO.Path]::GetFileName($root) -cnotmatch '\Aproofline-real-interruption-[0-9a-f]{32}\z' -or
        [IO.Path]::GetDirectoryName($case) -ine $root -or
        [IO.Path]::GetFileName($case) -notin @(
            'after-journal', 'upgrade-partial-stage', 'after-switch', 'corrupt-after-switch',
            'after-upgrade-passed', 'after-receipt', 'fresh-after-journal',
            'fresh-partial-stage', 'fresh-after-stage', 'fresh-after-move',
            'fresh-after-passed', 'fresh-after-receipt'
        )) {
        throw 'Interruption test child refused a directory outside the driver-created TEMP sandbox.'
    }
    foreach ($path in @($root, $case)) {
        if (-not [IO.Directory]::Exists($path) -or
            (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Interruption test sandbox directory does not exist or is a reparse point.'
        }
    }
    $runMarker = Join-Path $root '.proofline-run-token'
    $caseMarker = Join-Path $case '.proofline-test-only'
    if (-not [IO.File]::Exists($runMarker) -or
        [IO.File]::ReadAllText($runMarker) -cne $Token -or
        -not [IO.File]::Exists($caseMarker) -or
        [IO.File]::ReadAllText($caseMarker) -cne "DISPOSABLE_REAL_UPGRADE_TEST:$Token") {
        throw 'Interruption test driver identity does not match the disposable sandbox.'
    }
}
function Assert-TestExecutableVersion([string]$Exe, [string]$Version) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Exe
    $start.Arguments = '--version'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    try {
        if (-not $child.Start()) { throw "Could not start recovered version $Version." }
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        $clock = [Diagnostics.Stopwatch]::StartNew()
        if (-not $child.WaitForExit(15000)) {
            try { $child.Kill() } catch { }
            [void]$child.WaitForExit(5000)
            throw "Version check timed out for recovered $Version."
        }
        $remaining = [int][Math]::Max(0, 15000 - $clock.ElapsedMilliseconds)
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), $remaining)) {
            throw "Recovered $Version version probe exited but output pipes remained open after deadline."
        }
        Require ($child.ExitCode -eq 0 -and $stdout.GetAwaiter().GetResult().Trim() -ceq "proofline $Version" -and
            $stderr.GetAwaiter().GetResult().Trim() -eq '') "Executable version check failed for $Version."
    }
    finally { $child.Dispose() }
}
function Assert-Installed(
    [string]$Directory,
    [string]$Version,
    [ValidateSet('none', 'corrupt', 'unchecked')][string]$DamagedEvidence = 'none',
    [bool]$ExpectIncompleteStageEvidence = $false
) {
    $exe = Join-Path $Directory 'proofline.exe'
    $receipt = Join-Path $Directory '.proofline-install.receipt.json'
    $pending = Join-Path $Directory '.proofline-install.pending.json'
    Require ([IO.File]::Exists($exe)) 'Active executable missing.'
    Require ([IO.File]::Exists($receipt)) 'Installer receipt missing.'
    Require (-not [IO.File]::Exists($pending)) 'A recovery journal remains after recovery.'
    $data = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receipt))
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    Require ($data.schema -eq 1 -and $data.version -ceq $Version -and
        $data.sha256 -ceq $hash) 'Receipt does not match installed executable.'
    Require ($hash -ceq $script:pinnedExeHashes[$Version]) 'Recovered executable does not match pinned official fixture bytes.'
    Assert-TestExecutableVersion $exe $Version
    # A partial, untrusted stage is deliberately retained as .exe.incomplete
    # evidence. This is not an executable eligible for install or recovery.
    $incompletePattern = '\A\.proofline-staged-[0-9a-f]{32}\.exe\.incomplete\z'
    $files = @(Get-ChildItem -LiteralPath $Directory -Force)
    $debris = @($files | Where-Object {
        $_.Name -match '\A\.proofline-(recovery|api-backup|staged|restore)-' -and
        $_.Name -notmatch $incompletePattern
    })
    Require ($debris.Count -eq 0) 'A recovery or staging executable remains after successful repair.'
    $incomplete = @($files | Where-Object { $_.Name -match $incompletePattern })
    if ($ExpectIncompleteStageEvidence) {
        Require ($incomplete.Count -eq 1) 'Exactly one incomplete staged-file evidence copy was expected.'
        Require ($incomplete[0].Length -eq 32) 'Incomplete stage does not contain the expected injected prefix.'
    }
    else {
        Require ($incomplete.Count -eq 0) 'Unexpected incomplete staged-file evidence remains.'
    }
    # A corrupted active executable is intentionally kept in a quarantine
    # path following successful rollback. Don't conceal that evidence merely
    # to make this test green; verify exactly what was preserved.
    $damaged = @(Get-ChildItem -LiteralPath $Directory -Force |
        Where-Object { $_.Name -match '\A\.proofline-damaged-[0-9a-f]{32}\.exe\z' })
    if ($DamagedEvidence -cne 'none') {
        Require ($damaged.Count -eq 1) 'Expected one quarantined failed or unverified executable.'
        if ($DamagedEvidence -ceq 'corrupt') {
            Require ([IO.File]::ReadAllText($damaged[0].FullName) -ceq 'INTENTIONALLY_CORRUPTED') 'Quarantined contents differ from injected corruption.'
        }
        else {
            Require ((Get-FileHash -LiteralPath $damaged[0].FullName -Algorithm SHA256).Hash -ceq $script:pinnedExeHashes['0.5.2']) 'Quarantine does not match the pinned rejected new release.'
        }
    }
    else {
        Require ($damaged.Count -eq 0) 'Unexpected damaged executable remains.'
    }
    return $hash
}

if ($Mode -eq 'Worker' -or $Mode -eq 'Recover') {
    Assert-Sandbox $CaseDir $DriverRoot $TestToken
    if ($Mode -eq 'Worker') {
        if ([IO.Path]::GetFullPath($FixtureDir) -ine ([IO.Path]::Combine([IO.Path]::GetFullPath($DriverRoot), 'cache'))) {
            throw 'Worker fixture directory is not inside its driver sandbox.'
        }
        $expectedCopy = [IO.Path]::Combine([IO.Path]::GetFullPath($DriverRoot),
            ('instrumented-' + [IO.Path]::GetFileName([IO.Path]::GetFullPath($CaseDir)) + '.ps1'))
        if ([IO.Path]::GetFullPath($InstallerCopy) -ine $expectedCopy) {
            throw 'Worker installer copy does not match driver-owned instrumented file.'
        }
    }
    elseif ([IO.Path]::GetFullPath($InstallerCopy) -ine [IO.Path]::GetFullPath($originalInstaller)) {
        throw 'Recovery worker must use the unmodified repository installer.'
    }
    if ([string]::IsNullOrWhiteSpace($InstallerCopy) -or
        -not [IO.File]::Exists($InstallerCopy)) {
        throw 'Child requires its installer file.'
    }
    $validatedCopy = [IO.Path]::GetFullPath($InstallerCopy)
    if (([IO.File]::GetAttributes($validatedCopy) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Refusing to dot-source an installer copy that is a reparse point.'
    }
    . $validatedCopy
    if ($Mode -eq 'Recover') {
        if ($LatestOutage) {
            # Invoke the real entrypoint so moving repair after /cli/latest
            # fails the test even if standalone repair remains correct.
            function Get-ProoflineLatestVersion {
                throw 'INTENTIONAL_LATEST_LOOKUP_UNAVAILABLE'
            }
            try { Invoke-ProoflineInstaller $null $CaseDir $false }
            catch {
                if ($_.Exception.Message -cne 'INTENTIONAL_LATEST_LOOKUP_UNAVAILABLE') { throw }
                Write-Output 'LATEST_LOOKUP_FAILED_AFTER_RECOVERY'
                exit 17
            }
            throw 'Latest lookup outage unexpectedly completed.'
        }
        Invoke-ProoflinePendingRepair $CaseDir
        Write-Output 'RECOVERY_COMPLETED'
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($FixtureDir)) { throw 'Missing fixture directory.' }
    $fresh = [IO.File]::Exists((Join-Path $CaseDir '.first-install-case'))
    $name = if ($fresh) { 'old' } else { 'new' }
    $version = if ($fresh) { '0.5.1' } else { '0.5.2' }
    $archive = Get-TestBytes $FixtureDir "$name.tar.gz"
    $manifest = Get-TestBytes $FixtureDir "$name-SHA256SUMS"
    # An instrumented installer will kill ONLY THIS worker at the checkpoint.
    [void](Install-ProoflineArchive $archive $manifest $version $CaseDir)
    throw 'Worker unexpectedly returned: checkpoint injection did not terminate it.'
}

function Invoke-HiddenPowerShell([string]$Arguments, [string]$Purpose) {
    # A fresh console-subsystem powershell.exe normally opens another console
    # when launched with Start-Process. Suppress its window while preserving
    # stdout, stderr, exit status, and a finite timeout for diagnosis.
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $engine
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    try {
        if (-not $child.Start()) { throw "Could not start $Purpose." }
        # Drain both pipes concurrently; waiting before reading may deadlock
        # when a child writes enough data to fill a redirected pipe.
        $outTask = $child.StandardOutput.ReadToEndAsync()
        $errTask = $child.StandardError.ReadToEndAsync()
        $clock = [Diagnostics.Stopwatch]::StartNew()
        if (-not $child.WaitForExit(90000)) {
            try { $child.Kill() } catch { }
            [void]$child.WaitForExit(5000)
            throw "$Purpose did not exit within 90 seconds."
        }
        $remaining = [int][Math]::Max(0, 90000 - $clock.ElapsedMilliseconds)
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($outTask, $errTask), $remaining)) {
            throw "$Purpose exited but output pipes remained open after the 90-second deadline."
        }
        return [pscustomobject]@{
            ExitCode = $child.ExitCode
            Output = $outTask.GetAwaiter().GetResult()
            ErrorOutput = $errTask.GetAwaiter().GetResult()
        }
    }
    finally { $child.Dispose() }
}

function Make-InstrumentedInstaller([string]$Source, [string]$Destination, [string]$Checkpoint) {
    # Normalize line endings, then require the exact current production
    # statements. A changed installer should fail this test's setup rather
    # than silently disable fault injection.
    $text = [IO.File]::ReadAllText($Source).Replace("`r`n", "`n")
    # The marker proves this child reached the intentional termination point.
    $mark = '[IO.File]::WriteAllText(([IO.Path]::Combine($directory, ''.injected-stop'')), ''' +
        $Checkpoint + ''', [Text.Encoding]::ASCII)'
    $abort = $mark + "`n" + '                Stop-Process -Id $PID -Force -ErrorAction Stop'
    if ($Checkpoint -eq 'after-journal') {
        $target = '        Write-ProoflineAtomicRecord $pending $record' +
            "`n" + '        try {'
        $replacement = '        Write-ProoflineAtomicRecord $pending $record' +
            "`n" + '        ' + $abort + "`n" + '        try {'
    }
    elseif ($Checkpoint -eq 'fresh-partial-stage' -or $Checkpoint -eq 'upgrade-partial-stage') {
        $target = '                $stream.Write($binary, 0, $binary.Length)' +
            "`n" + '                $stream.Flush($true)'
        $replacement = '                $stream.Write($binary, 0, [Math]::Min(32, $binary.Length))' +
            "`n" + '                $stream.Flush($true)' +
            "`n" + '                ' + $abort
    }
    elseif ($Checkpoint -eq 'after-switch' -or $Checkpoint -eq 'corrupt-after-switch') {
        $target = '                Invoke-ProoflineReplaceWithRetry $stage $destination $paths.api $hash $oldReceipt.sha256' +
            "`n" + '                if ('
        $damage = if ($Checkpoint -eq 'corrupt-after-switch') {
            '                [IO.File]::WriteAllText($destination, "INTENTIONALLY_CORRUPTED", [Text.Encoding]::ASCII)' + "`n"
        }
        else { '' }
        $replacement = '                Invoke-ProoflineReplaceWithRetry $stage $destination $paths.api $hash $oldReceipt.sha256' +
            "`n" + $damage + '                ' + $abort + "`n" + '                if ('
    }
    elseif ($Checkpoint -eq 'after-upgrade-passed') {
        $target = "                Set-ProoflinePendingPostcheck "+'$pending '+ "'passed'" +
            "`n" + '                Write-ProoflineReceipt $receipt $ReleaseVersion $hash'
        $replacement = "                Set-ProoflinePendingPostcheck "+'$pending '+ "'passed'" +
            "`n" + '                ' + $abort +
            "`n" + '                Write-ProoflineReceipt $receipt $ReleaseVersion $hash'
    }
    elseif ($Checkpoint -eq 'fresh-after-passed') {
        $target = "                    Set-ProoflinePendingPostcheck "+'$pending '+ "'passed'" +
            "`n" + '                    Write-ProoflineReceipt $receipt $ReleaseVersion $hash'
        $replacement = "                    Set-ProoflinePendingPostcheck "+'$pending '+ "'passed'" +
            "`n" + '                    ' + $abort +
            "`n" + '                    Write-ProoflineReceipt $receipt $ReleaseVersion $hash'
    }
    elseif ($Checkpoint -eq 'after-receipt') {
        $target = '                Write-ProoflineReceipt $receipt $ReleaseVersion $hash' +
            "`n" + '                try { Clear-ProoflineUpgradeFiles $paths $pending $hash }'
        $replacement = '                Write-ProoflineReceipt $receipt $ReleaseVersion $hash' +
            "`n" + '                ' + $abort +
            "`n" + '                try { Clear-ProoflineUpgradeFiles $paths $pending $hash }'
    }
    elseif ($Checkpoint -eq 'fresh-after-journal') {
        $target = '        Write-ProoflineAtomicRecord $pending $record' +
            "`n" + '        try {'
        $replacement = '        Write-ProoflineAtomicRecord $pending $record' +
            "`n" + '        ' + $abort + "`n" + '        try {'
    }
    elseif ($Checkpoint -eq 'fresh-after-stage') {
        $target = '            Assert-ProoflineExeVersion $stage $ReleaseVersion $hash' +
            "`n`n" + '            if ($null -eq $oldReceipt) {'
        $replacement = '            Assert-ProoflineExeVersion $stage $ReleaseVersion $hash' +
            "`n" + '            ' + $abort + "`n`n" + '            if ($null -eq $oldReceipt) {'
    }
    elseif ($Checkpoint -eq 'fresh-after-move') {
        $target = '                [IO.File]::Move($stage, $destination)' +
            "`n" + '                if ('
        $replacement = '                [IO.File]::Move($stage, $destination)' +
            "`n" + '                ' + $abort + "`n" + '                if ('
    }
    elseif ($Checkpoint -eq 'fresh-after-receipt') {
        $target = '                    Write-ProoflineReceipt $receipt $ReleaseVersion $hash' +
            "`n" + '                    Clear-ProoflineJournalBackup $pending'
        $replacement = '                    Write-ProoflineReceipt $receipt $ReleaseVersion $hash' +
            "`n" + '                    ' + $abort + "`n" + '                    Clear-ProoflineJournalBackup $pending'
    }
    else { throw "Unsupported injection checkpoint $Checkpoint." }
    Require ($text.Contains($target)) "Production installer checkpoint '$Checkpoint' changed."
    Require (($text.Split([string[]]@($target), [StringSplitOptions]::None).Count) -eq 2) "Checkpoint '$Checkpoint' is not unique."
    $instrumented = $text.Replace($target, $replacement)
    # Parse generated scripts before starting any worker. Source-only
    # validation cannot catch malformed injection templates.
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput(
        $instrumented, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        $details = @($parseErrors | ForEach-Object {
            "line $($_.Extent.StartLineNumber): $($_.Message)"
        }) -join '; '
        throw "Generated $Checkpoint installer failed syntax preflight: $details"
    }
    [IO.File]::WriteAllText($Destination, $instrumented, [Text.UTF8Encoding]::new($false))
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('proofline-real-interruption-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$cache = Join-Path $root 'cache'
[IO.Directory]::CreateDirectory($cache) | Out-Null
$scenarios = @(
    'after-journal', 'upgrade-partial-stage', 'after-switch', 'corrupt-after-switch',
    'after-upgrade-passed', 'after-receipt',
    'fresh-after-journal', 'fresh-partial-stage', 'fresh-after-stage', 'fresh-after-move',
    'fresh-after-passed', 'fresh-after-receipt'
)
$expected = @{
    'after-journal' = '0.5.1'
    'upgrade-partial-stage' = '0.5.1'
    'after-switch' = '0.5.1'
    'corrupt-after-switch' = '0.5.1'
    'after-upgrade-passed' = '0.5.2'
    'after-receipt' = '0.5.2'
    'fresh-after-journal' = 'absent'
    'fresh-partial-stage' = 'absent'
    'fresh-after-stage' = 'absent'
    'fresh-after-move' = 'absent'
    'fresh-after-passed' = '0.5.1'
    'fresh-after-receipt' = '0.5.1'
}
$engine = (Get-Process -Id $PID).Path
$testToken = [guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText((Join-Path $root '.proofline-run-token'), $testToken)
$pathBefore = [Environment]::GetEnvironmentVariable('Path', 'User')
$results = @()
$passed = $false
$cleanup = $false

try {
    . $originalInstaller
    $script:pinnedExeHashes = @{}
    foreach ($pair in @(@('0.5.1', 'old'), @('0.5.2', 'new'))) {
        $v = $pair[0]
        $kind = $pair[1]
        $prefix = "/cli/download/$v"
        Write-Host "Downloading pinned official v$v fixture..."
        $archive = Get-ProoflineOfficialBytes "$prefix/$script:ProoflineArchiveName" $script:MaxArchiveBytes
        $manifest = Get-ProoflineOfficialBytes "$prefix/SHA256SUMS" 8192
        Assert-ProoflineChecksum $archive $manifest
        $verifiedBinary = Get-ProoflineTarExecutable $archive
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $script:pinnedExeHashes[$v] = [BitConverter]::ToString($sha.ComputeHash($verifiedBinary)).Replace('-', '') }
        finally { $sha.Dispose() }
        [IO.File]::WriteAllBytes((Join-Path $cache "$kind.tar.gz"), $archive)
        [IO.File]::WriteAllBytes((Join-Path $cache "$kind-SHA256SUMS"), $manifest)
    }
    $oldArchive = Get-TestBytes $cache 'old.tar.gz'
    $oldManifest = Get-TestBytes $cache 'old-SHA256SUMS'

    foreach ($checkpoint in $scenarios) {
        $directory = Join-Path $root $checkpoint
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        [IO.File]::WriteAllText((Join-Path $directory '.proofline-test-only'), "DISPOSABLE_REAL_UPGRADE_TEST:$testToken")
        $isFresh = $checkpoint -like 'fresh-*'
        $oldDigest = $null
        if ($isFresh) {
            [IO.File]::WriteAllText((Join-Path $directory '.first-install-case'), 'DISPOSABLE')
            Write-Host "Vacant first-install sandbox prepared for $checkpoint."
        }
        else {
            [void](Install-ProoflineArchive $oldArchive $oldManifest '0.5.1' $directory)
            $oldDigest = Assert-Installed $directory '0.5.1'
            Write-Host "Initial v0.5.1 installation validated for $checkpoint."
        }

        $copy = Join-Path $root ("instrumented-$checkpoint.ps1")
        Make-InstrumentedInstaller $originalInstaller $copy $checkpoint
        $stdout = Join-Path $root ("worker-$checkpoint.stdout.txt")
        $stderr = Join-Path $root ("worker-$checkpoint.stderr.txt")
        $arguments = '-NoProfile -NonInteractive -File "' + $PSCommandPath +
            '" -Mode Worker -CaseDir "' + $directory +
            '" -FixtureDir "' + $cache + '" -InstallerCopy "' + $copy +
            '" -DriverRoot "' + $root + '" -TestToken ' + $testToken
        $worker = Invoke-HiddenPowerShell $arguments "upgrade worker ($checkpoint)"
        $workerExit = $worker.ExitCode
        [IO.File]::WriteAllText($stdout, $worker.Output)
        [IO.File]::WriteAllText($stderr, $worker.ErrorOutput)
        $workerOutput = $worker.Output + $worker.ErrorOutput
        $marker = Join-Path $directory '.injected-stop'
        Require ([IO.File]::Exists($marker)) "Worker failed before reaching $checkpoint; exit $workerExit; output: $workerOutput"
        Require ([IO.File]::ReadAllText($marker) -ceq $checkpoint) "Wrong checkpoint marker for $checkpoint."
        Require ($workerExit -eq -1) "Worker did not terminate as expected at $checkpoint; exit $workerExit; output: $workerOutput"
        $journal = Join-Path $directory '.proofline-install.pending.json'
        Require ([IO.File]::Exists($journal)) "No pending journal existed after forced termination at $checkpoint."
        $onDiskJournal = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($journal))
        if ($checkpoint -in @('after-switch', 'corrupt-after-switch', 'fresh-after-move')) {
            Require ($onDiskJournal.postcheck -ceq 'checking') 'Switch happened without durable checking state.'
        }
        if ($checkpoint -in @('after-upgrade-passed', 'fresh-after-passed')) {
            Require ($onDiskJournal.postcheck -ceq 'passed') 'Passed checkpoint did not persist postcheck before receipt.'
            $receiptBefore = Join-Path $directory '.proofline-install.receipt.json'
            if ($checkpoint -eq 'fresh-after-passed') {
                Require (-not [IO.File]::Exists($receiptBefore)) 'First-install receipt was prematurely published before persisted passed checkpoint.'
            }
            else {
                $oldReceipt = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receiptBefore))
                Require ($oldReceipt.version -ceq '0.5.1') 'Upgrade receipt was prematurely published before persisted passed checkpoint.'
            }
        }
        $activeFile = Join-Path $directory 'proofline.exe'
        $activeDigest = $null
        if ([IO.File]::Exists($activeFile)) {
            $activeDigest = (Get-FileHash -LiteralPath $activeFile -Algorithm SHA256).Hash
        }
        if ($checkpoint -in @('fresh-after-journal', 'fresh-partial-stage', 'fresh-after-stage')) {
            Require ($null -eq $activeDigest) 'Fresh install published executable before intended checkpoint.'
        }
        elseif ($checkpoint -in @('fresh-after-move', 'fresh-after-passed', 'fresh-after-receipt')) {
            Require ($activeDigest -ceq $script:pinnedExeHashes['0.5.1']) 'Fresh install did not publish the pinned executable before checkpoint.'
        }
        elseif ($checkpoint -in @('after-journal', 'upgrade-partial-stage')) {
            Require ($activeDigest -ceq $oldDigest) 'Journal checkpoint unexpectedly changed old executable.'
        }
        elseif ($checkpoint -eq 'corrupt-after-switch') {
            Require ([IO.File]::ReadAllText($activeFile) -ceq 'INTENTIONALLY_CORRUPTED') 'Corruption checkpoint did not install injected corruption.'
        }
        else {
            Require ($activeDigest -ceq $script:pinnedExeHashes['0.5.2']) 'Replacement checkpoint did not publish pinned new executable.'
        }

        $recoverStdout = Join-Path $root ("recovery-$checkpoint.stdout.txt")
        $recoverStderr = Join-Path $root ("recovery-$checkpoint.stderr.txt")
        $recoverArgs = '-NoProfile -NonInteractive -File "' + $PSCommandPath +
            '" -Mode Recover -CaseDir "' + $directory +
            '" -InstallerCopy "' + $originalInstaller +
            '" -DriverRoot "' + $root + '" -TestToken ' + $testToken
        if ($checkpoint -eq 'after-switch') { $recoverArgs += ' -LatestOutage' }
        $recovery = Invoke-HiddenPowerShell $recoverArgs "recovery worker ($checkpoint)"
        $recoverExit = $recovery.ExitCode
        [IO.File]::WriteAllText($recoverStdout, $recovery.Output)
        [IO.File]::WriteAllText($recoverStderr, $recovery.ErrorOutput)
        $recoverOutput = $recovery.Output + $recovery.ErrorOutput
        if ($checkpoint -eq 'after-switch') {
            Require ($recoverExit -eq 17 -and
                $recoverOutput.Contains('LATEST_LOOKUP_FAILED_AFTER_RECOVERY')) "Unpinned latest-outage recovery failed at $checkpoint; exit $recoverExit; output: $recoverOutput"
        }
        else {
            Require ($recoverExit -eq 0) "Fresh recovery process failed for $checkpoint; output: $recoverOutput"
        }
        $digest = $null
        if ($expected[$checkpoint] -eq 'absent') {
            Require (-not [IO.File]::Exists($activeFile)) 'Interrupted fresh install unexpectedly published an executable.'
            Require (-not [IO.File]::Exists((Join-Path $directory '.proofline-install.receipt.json'))) 'Interrupted fresh install incorrectly wrote a receipt.'
            Require (-not [IO.File]::Exists($journal)) 'Interrupted fresh install left a pending journal.'
            $unclaimed = @(Get-ChildItem -LiteralPath $directory -Force |
                Where-Object { $_.Name -match '^\.proofline-staged-[a-f0-9]{32}\.exe$' })
            Require ($unclaimed.Count -eq 0) 'Fresh-install recovery left a staged executable.'
            if ($checkpoint -eq 'fresh-partial-stage') {
                $evidence = @(Get-ChildItem -LiteralPath $directory -Force |
                    Where-Object { $_.Name -match '^\.proofline-staged-[a-f0-9]{32}\.exe\.incomplete$' })
                Require ($evidence.Count -eq 1) 'Incomplete first-install bytes were not preserved.'
            }
            $unverified = @(Get-ChildItem -LiteralPath $directory -Force |
                Where-Object { $_.Name -match '^\.proofline-unverified-first-[a-f0-9]{32}\.exe$' })
            if ($checkpoint -eq 'fresh-after-move') {
                Require ($unverified.Count -eq 1) 'Unverified published first-install executable was not quarantined.'
                Require ((Get-FileHash -LiteralPath $unverified[0].FullName -Algorithm SHA256).Hash -ceq $script:pinnedExeHashes['0.5.1']) 'First-install quarantine does not match pinned executable.'
            }
            else { Require ($unverified.Count -eq 0) 'Unexpected first-install quarantine remains.' }
            Write-Host "PASS $checkpoint; fresh process recovered without accepting an unverified executable."
        }
        else {
            $damagedMode = 'none'
            if ($checkpoint -eq 'corrupt-after-switch') { $damagedMode = 'corrupt' }
            elseif ($checkpoint -eq 'after-switch') { $damagedMode = 'unchecked' }
            $digest = Assert-Installed $directory $expected[$checkpoint] `
                $damagedMode `
                ($checkpoint -eq 'upgrade-partial-stage')
            if ($isFresh) {
                Require ($null -ne $digest) 'First-install recovery failed to finalize new executable.'
            }
            elseif ($expected[$checkpoint] -eq '0.5.1') {
                Require ($digest -ceq $oldDigest) 'Rollback did not preserve original executable bytes.'

            }
            else {
                Require ($digest -cne $oldDigest) 'Recovery did not install the different new executable.'
            }
            Write-Host "PASS $checkpoint; fresh process recovered to v$($expected[$checkpoint])."
        }
        $results += [pscustomobject]@{
            checkpoint = $checkpoint
            workerExitCode = $workerExit
            recoveryExitCode = $recoverExit
            recoveredVersion = $expected[$checkpoint]
            recoveredSha256 = $digest
        }
    }

    Require ([Environment]::GetEnvironmentVariable('Path', 'User') -ceq $pathBefore) 'User PATH was modified.'
    $passed = $true
}
catch {
    Write-Warning "FAIL real installer interruption test: $($_.Exception.ToString())"
}
finally {
    if ($passed -and -not $KeepFiles) {
        try {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
            $cleanup = $true
        }
        catch {
            Write-Warning "Could not delete disposable test directory: $($_.Exception.Message)"
            $passed = $false
        }
    }
}
Write-Host "Completed $($results.Count) of $($scenarios.Count) interruption scenarios."
if ($passed) {
    Write-Host 'Real Windows installer interruption integration: PASS'
    if ($KeepFiles) { Write-Host "Retained test evidence at $root" }
    else { Write-Host "Cleaned isolated test directory: $cleanup" }
}
else {
    Write-Warning "Failure evidence preserved at: $root"
    exit 1
}
