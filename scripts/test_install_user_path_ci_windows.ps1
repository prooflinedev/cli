#requires -Version 5.1
<#
.SYNOPSIS
  Verify raw current-user PATH persistence and expandable registry types.
.DESCRIPTION
  CI-only test: insert a unique expandable PATH entry, append Proofline path,
  assert idempotence and fresh-process visibility, restore exact raw registry
  value and value kind. Refuses execution outside GitHub Actions Windows.
#>
[CmdletBinding()]
param([ValidateSet('Check', 'ReadUserPath')][string]$Mode = 'Check')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Windows CI runner required.'
}
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'Refusing PATH mutation outside a disposable GitHub-hosted Windows runner profile.'
}

function Get-RawUserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    if ($null -eq $key) { return @{ exists = $false; value = ''; kind = 'ExpandString' } }
    try {
        if ('Path' -notin @($key.GetValueNames())) {
            return @{ exists = $false; value = ''; kind = 'ExpandString' }
        }
        $kind = $key.GetValueKind('Path')
        $raw = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($raw -isnot [string]) { throw 'User PATH has an unexpected registry type.' }
        return @{ exists = $true; value = $raw; kind = $kind.ToString() }
    }
    finally { $key.Dispose() }
}

if ($Mode -eq 'ReadUserPath') {
    $fresh = Get-RawUserPath
    $data = ConvertTo-Json -Compress -InputObject $fresh
    [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($data)))
    exit 0
}

. (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1')
$original = Get-RawUserPath
$directory = Join-Path $env:RUNNER_TEMP ('proofline-path-ci-' + [guid]::NewGuid().ToString('N'))
$token = '%PROOFLINE_CI_TEST_ROOT%\bin'
$originalToken = [Environment]::GetEnvironmentVariable('PROOFLINE_CI_TEST_ROOT', 'Process')
[Environment]::SetEnvironmentVariable('PROOFLINE_CI_TEST_ROOT', (Join-Path $env:RUNNER_TEMP 'proofline-expanded-token'), 'Process')
$seed = if ([string]::IsNullOrEmpty($original.value)) { $token }
else { $original.value.TrimEnd(';') + ';' + $token }
# Independent oracle: do not use the same helper under test to construct
# expected output, or truncation before $token could go undetected.
$expected = $seed.TrimEnd(';') + ';' + $directory
if ($seed -match [regex]::Escape($directory)) { throw 'Fresh randomized CI directory was already in User PATH.' }
[IO.Directory]::CreateDirectory($directory) | Out-Null

$seeded = $false
$ok = $false
$restored = $false
try {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $key.SetValue('Path', $seed, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        $seeded = $true
    }
    finally { $key.Dispose() }

    # Exercise the default installer entrypoint without -NoModifyPath, not
    # merely its PATH helper. The disposable runner owns this user profile.
    $installer = Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1'
    $engine = (Get-Process -Id $PID).Path
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $engine
    $start.Arguments = '-NoProfile -NonInteractive -File "' + $installer + '" -Version 0.5.1 -InstallDir "' + $directory + '"'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    try {
        if (-not $child.Start()) { throw 'Could not start full installer for User PATH test.' }
        if (-not $child.WaitForExit(120000)) {
            try { $child.Kill() } catch { }
            [void]$child.WaitForExit(5000)
            throw 'Full installer exceeded the 120-second PATH integration deadline.'
        }
        if ($child.ExitCode -ne 0) { throw "Default installer exited $($child.ExitCode)." }
    }
    finally { $child.Dispose() }
    $after = Get-RawUserPath
    if ($after.value -cne $expected -or $after.kind -cne 'ExpandString') {
        throw 'Installer did not preserve expandable PATH entry and its type.'
    }
    if (-not $after.value.Contains($token)) {
        throw 'Installer expanded or removed the existing %VARIABLE% token.'
    }
    if ($null -ne (Get-ProoflineUpdatedUserPath $after.value $directory)) {
        throw 'PATH duplicate-detection unexpectedly added a second entry.'
    }

    Add-ProoflineUserPath $directory
    $repeat = Get-RawUserPath
    if ($repeat.value -cne $expected -or $repeat.kind -cne 'ExpandString') {
        throw 'Second PATH update mutated the raw registry value or its type.'
    }

    $engine = (Get-Process -Id $PID).Path
    $encoded = @(& $engine -NoProfile -NonInteractive -File $PSCommandPath -Mode ReadUserPath)
    if ($LASTEXITCODE -ne 0) {
        throw "Fresh PowerShell process failed to read User PATH: $LASTEXITCODE"
    }
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($encoded -join '').Trim()))
    $fresh = ConvertFrom-Json -InputObject $json
    if ($fresh.value -cne $expected -or $fresh.kind -cne 'ExpandString') {
        throw 'Fresh process did not see the correct raw User PATH and registry kind.'
    }

    Write-Host 'PASS raw expandable PATH text and REG_EXPAND_SZ preserved.'
    Write-Host 'PASS repeated PATH update did not create duplicates.'
    Write-Host 'PASS fresh PowerShell process observed persisted User PATH.'
    $ok = $true
}
finally {
    if ($seeded) {
        $current = Get-RawUserPath
        # Restore only the exact test values; do not overwrite other edits.
        if ($current.kind -in @('ExpandString', 'String') -and
            $current.value -cin @($seed, $expected)) {
            # Even if a registry-kind regression occurred, restore the exact
            # seeded text instead of leaving the disposable PATH entries behind.
            $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
            try {
                if ($original.exists) {
                    $originalKind = [Enum]::Parse([Microsoft.Win32.RegistryValueKind], $original.kind)
                    $key.SetValue('Path', $original.value, $originalKind)
                }
                else { $key.DeleteValue('Path', $false) }
            }
            finally { $key.Dispose() }
            Send-ProoflineEnvironmentChange
            $check = Get-RawUserPath
            $restored = ($check.exists -eq $original.exists -and
                $check.value -ceq $original.value -and $check.kind -ceq $original.kind)
        }
        else { Write-Warning 'User PATH changed concurrently; refusing to overwrite it.' }
    }
    [Environment]::SetEnvironmentVariable('PROOFLINE_CI_TEST_ROOT', $originalToken, 'Process')
    Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
}
if (-not $ok -or -not $restored) {
    throw 'CI User PATH persistence failed or original raw PATH was not restored.'
}
Write-Host 'CI User PATH persistence, expandability and restore: PASS'
