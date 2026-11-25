#requires -Version 5.1
# Offline validator tests: no network, PATH changes, installation or execution.
[CmdletBinding()]
param([string]$Python = 'python')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run these PowerShell tests on Windows.'
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('proofline-validation-tests-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$installer = Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1'
$generator = Join-Path $PSScriptRoot 'generate_windows_installer_fixtures.py'
$passed = 0
$failed = 0

function Test-Case([string]$Name, [scriptblock]$Check) {
    try {
        & $Check
        $script:passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:failed++
        Write-Warning "FAIL $Name : $($_.Exception.Message)"
    }
}
function Must-Throw([scriptblock]$Action) {
    $didThrow = $false
    try { & $Action | Out-Null } catch { $didThrow = $true }
    if (-not $didThrow) { throw 'Expected rejection, but operation succeeded.' }
}
function Bytes([string]$Filename) {
    return ,([IO.File]::ReadAllBytes((Join-Path $root $Filename)))
}

try {
    & $Python $generator $root | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Python fixture generation failed.' }
    . $installer
    $valid = Bytes 'valid.tar.gz'
    $sums = Bytes 'SHA256SUMS'

    Test-Case 'valid official-style tar and multi-target digest manifest' {
        Assert-ProoflineChecksum $valid $sums
        $exe = Get-ProoflineTarExecutable $valid
        # Verify every payload byte, not just the archive layout and length.
        $expected = [byte[]]::new(1024)
        $expected[0] = 77
        $expected[1] = 90
        $expected[0x3c] = 0x80
        $expected[0x80] = 80
        $expected[0x81] = 69
        $expected[0x84] = 0x64
        $expected[0x85] = 0x86
        if ($exe.Length -ne $expected.Length) { throw 'Unexpected fixture executable length.' }
        for ($i = 0; $i -lt $expected.Length; $i++) {
            if ($exe[$i] -ne $expected[$i]) {
                throw "Extracted executable payload differs from independent fixture at byte $i."
            }
        }
    }
    foreach ($name in @('SHA256SUMS-mismatch', 'SHA256SUMS-duplicate',
            'SHA256SUMS-missing', 'SHA256SUMS-malformed')) {
        $manifest = Bytes $name
        Test-Case "manifest rejects $name" {
            Must-Throw { Assert-ProoflineChecksum $valid $manifest }
        }
    }
    foreach ($name in @('traversal.tar.gz', 'unexpected-member.tar.gz',
            'symlink.tar.gz', 'not-pe.tar.gz')) {
        $archive = Bytes $name
        Test-Case "archive rejects $name" {
            if ($name -eq 'symlink.tar.gz') {
                $rejectedForType = $false
                try { [void](Get-ProoflineTarExecutable $archive) }
                catch {
                    if ($_.Exception.Message -notlike '*exactly one regular proofline.exe*') {
                        throw "Symlink rejected for the wrong reason: $($_.Exception.Message)"
                    }
                    $rejectedForType = $true
                }
                if (-not $rejectedForType) { throw 'Symlink tar member was accepted.' }
            }
            else { Must-Throw { Get-ProoflineTarExecutable $archive } }
        }
    }
    Test-Case 'invalid PE signature is rejected at a valid offset' {
        $badSignature = Bytes 'bad-pe-signature.tar.gz'
        $specificRejection = $false
        try { [void](Get-ProoflineTarExecutable $badSignature) }
        catch {
            if ($_.Exception.Message -notlike '*no valid PE signature*') {
                throw "Invalid PE signature rejected for wrong reason: $($_.Exception.Message)"
            }
            $specificRejection = $true
        }
        if (-not $specificRejection) { throw 'Corrupt PE signature was accepted.' }
    }
    Test-Case 'valid PE with x86 COFF Machine is rejected as non-AMD64' {
        $x86 = Bytes 'x86-machine.tar.gz'
        $rejectedArchitecture = $false
        try { [void](Get-ProoflineTarExecutable $x86) }
        catch {
            if ($_.Exception.Message -notlike '*AMD64 (x64) COFF machine type*') {
                throw "x86 fixture rejected for wrong reason: $($_.Exception.Message)"
            }
            $rejectedArchitecture = $true
        }
        if (-not $rejectedArchitecture) { throw 'Mislabeled x86 release was accepted.' }
    }
    Test-Case 'checksum rejects modified archive bytes' {
        $modified = Bytes 'bad-digest.tar.gz'
        Must-Throw { Assert-ProoflineChecksum $modified $sums }
    }
    Test-Case 'strict semantic versions' {
        if ((Assert-ProoflineVersion '1.2.3') -cne '1.2.3') { throw 'Valid version rejected.' }
        Must-Throw { Assert-ProoflineVersion '../1.2.3' }
        Must-Throw { Assert-ProoflineVersion '01.2.3' }
        Must-Throw { Assert-ProoflineVersion '1.2.3-rc1' }
    }
    Test-Case 'literal REG_SZ PATH tokens are not expanded during duplicate detection' {
        $variable = 'PROOFLINE_DUPLICATE_KIND_TEST'
        $previous = [Environment]::GetEnvironmentVariable($variable, 'Process')
        $directory = 'C:\ProoflineTest\bin'
        [Environment]::SetEnvironmentVariable($variable, 'C:\ProoflineTest', 'Process')
        try {
            $token = '%' + $variable + '%\bin'
            $literal = Get-ProoflineUpdatedUserPath $token $directory ([Microsoft.Win32.RegistryValueKind]::String)
            if ($literal -cne ($token + ';' + $directory)) { throw 'REG_SZ token incorrectly treated as expanded directory.' }
            # An expandable entry can move when the variable changes.
            # Preserve the literal installed directory even when the token
            # happens to expand to it at this moment.
            $expanded = Get-ProoflineUpdatedUserPath $token $directory ([Microsoft.Win32.RegistryValueKind]::ExpandString)
            if ($expanded -cne ($token + ';' + $directory)) {
                throw 'Variable-dependent PATH entry incorrectly suppressed stable installed directory.'
            }
        }
        finally { [Environment]::SetEnvironmentVariable($variable, $previous, 'Process') }
    }
    Test-Case 'REG_EXPAND_SZ refuses an installation path whose percent tokens would expand' {
        # Stubs make this non-mutating even if the installer regresses: the
        # helper throws before any registry write can be attempted.
        $realReader = (Get-Item Function:\Get-ProoflineUserPathRecord).ScriptBlock
        $realCalculator = (Get-Item Function:\Get-ProoflineUpdatedUserPath).ScriptBlock
        try {
            Set-Item Function:\Get-ProoflineUserPathRecord -Value {
                return @{ value = 'C:\safe'; kind = [Microsoft.Win32.RegistryValueKind]::ExpandString; exists = $true }
            }
            Set-Item Function:\Get-ProoflineUpdatedUserPath -Value {
                throw 'PATH calculator reached after invalid expandable install directory.'
            }
            $rejected = $false
            try { Add-ProoflineUserPath 'C:\literal\%PROOFLINE_UNSAFE_EXPANSION%\bin' }
            catch {
                if ($_.Exception.Message -notlike '*contains %VARIABLE% syntax*') { throw }
                $rejected = $true
            }
            if (-not $rejected) { throw 'Unsafe expandable installation path was accepted.' }
        }
        finally {
            Set-Item Function:\Get-ProoflineUpdatedUserPath -Value $realCalculator
            Set-Item Function:\Get-ProoflineUserPathRecord -Value $realReader
        }
    }
    Test-Case 'pinned installation directory and ancestor resist rename' {
        # A plain directory is renameable; pinning must make it unavailable
        # for rename until the entire installer transaction completes.
        $probe = Join-Path $root 'unpinned-control'
        [IO.Directory]::CreateDirectory($probe) | Out-Null
        [IO.Directory]::Move($probe, $probe + '-moved')
        [IO.Directory]::Move($probe + '-moved', $probe)

        $parent = Join-Path $root 'pin-parent'
        $child = Join-Path $parent 'bin'
        $guards = Protect-ProoflineDirectoryTree $child $true
        try {
            if ($guards.Count -lt 2) { throw 'Directory pinning returned too few handles.' }
            foreach ($guard in $guards) {
                if ($guard.IsClosed -or $guard.IsInvalid) {
                    throw 'Directory guard handle was closed before the transaction.'
                }
            }
            foreach ($testPath in @($child, $parent)) {
                $blocked = $false
                try { [IO.Directory]::Move($testPath, $testPath + '-moved') }
                catch [IO.IOException] { $blocked = $true }
                if (-not $blocked) {
                    throw "Pinned directory was renamed while its guard was held: $testPath"
                }
                if (-not [IO.Directory]::Exists($testPath)) {
                    throw "Pinned directory disappeared: $testPath"
                }
            }
        }
        finally { foreach ($guard in $guards) { $guard.Dispose() } }
    }
    Test-Case 'PATH change is idempotent' {
        $directory = 'C:\Users\tester\AppData\Local\Programs\Proofline\bin'
        if ($null -ne (Get-ProoflineUpdatedUserPath $directory $directory)) {
            throw 'Duplicate PATH entry would be appended.'
        }
        if ((Get-ProoflineUpdatedUserPath 'C:\Other' $directory) -cne ('C:\Other;' + $directory)) {
            throw 'Expected PATH entry missing.'
        }
    }
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "Offline PowerShell validator tests: $passed passed, $failed failed."
if ($failed -ne 0) { exit 1 }
