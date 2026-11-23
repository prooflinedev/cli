#requires -Version 5.1
<#
.SYNOPSIS
  Verify current-user PATH registry updates only in a disposable CI runner.
.DESCRIPTION
  Writes a unique temporary Proofline-style PATH entry to the CI runner's
  User PATH, checks a fresh PowerShell process can read it, checks idempotence,
  and restores the original value in finally. Refuses non-CI execution.
  Never run this test on a personal Windows profile.
#>
[CmdletBinding()]
param([ValidateSet('Check','ReadUserPath')][string]$Mode = 'Check')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Windows CI runner required.'
}
if ($env:GITHUB_ACTIONS -cne 'true' -or [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'Refusing PATH registry test outside GitHub Actions Windows runner.'
}

if ($Mode -eq 'ReadUserPath') {
    $freshPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $freshPath) { $freshPath = '' }
    [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($freshPath)))
    exit 0
}

. (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1')
$original = [Environment]::GetEnvironmentVariable('Path', 'User')
$directory = Join-Path $env:RUNNER_TEMP ('proofline-path-ci-' + [guid]::NewGuid().ToString('N'))
$expected = Get-ProoflineUpdatedUserPath $original $directory
if ($null -eq $expected) {
    throw 'Fresh randomized CI directory was already in User PATH.'
}
[IO.Directory]::CreateDirectory($directory) | Out-Null
$ok = $false
$restoreOk = $false
try {
    Add-ProoflineUserPath $directory
    $after = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($after -cne $expected) {
        throw 'User PATH did not persist expected entry.'
    }
    if ($null -ne (Get-ProoflineUpdatedUserPath $after $directory)) {
        throw 'User PATH idempotence function returned a duplicate entry.'
    }
    Add-ProoflineUserPath $directory
    if ([Environment]::GetEnvironmentVariable('Path', 'User') -cne $expected) {
        throw 'Second PATH update mutated the registry value.'
    }

    $engine = (Get-Process -Id $PID).Path
    $encoded = @(& $engine -NoProfile -NonInteractive -File $PSCommandPath -Mode ReadUserPath)
    if ($LASTEXITCODE -ne 0) {
        throw "Fresh PowerShell process failed to read User PATH: $LASTEXITCODE"
    }
    $fresh = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($encoded -join '').Trim()))
    if ($fresh -cne $expected) {
        throw 'Fresh PowerShell process observed a different User PATH.'
    }
    Write-Host 'PASS new PowerShell process sees persistent User PATH entry.'
    Write-Host 'PASS repeated PATH update does not duplicate entry.'
    $ok = $true
}
finally {
    # Restore only if the test's exact value is still present. In case of an
    # unexpected concurrent edit, do not overwrite it with an older snapshot.
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($current -ceq $expected) {
        [Environment]::SetEnvironmentVariable('Path', $original, 'User')
        $restored = [Environment]::GetEnvironmentVariable('Path', 'User')
        $normalizedOriginal = if ($null -eq $original) { '' } else { $original }
        $normalizedRestored = if ($null -eq $restored) { '' } else { $restored }
        $restoreOk = ($normalizedRestored -ceq $normalizedOriginal)
        if (-not $restoreOk) {
            Write-Warning 'Could not verify original CI User PATH value was restored.'
        }
    }
    else {
        Write-Warning 'User PATH changed unexpectedly during CI; refusing to overwrite concurrent edits.'
    }
    Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
}
if (-not $ok -or -not $restoreOk) {
    throw 'CI User PATH persistence check failed or did not restore original value.'
}
Write-Host 'CI User PATH persistence and restore: PASS'
