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
