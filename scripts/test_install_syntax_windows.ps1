#requires -Version 5.1
# Parse installer scripts and tests without executing network/process tests.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$paths = @((Join-Path $root 'install.ps1'),
           (Join-Path $PSScriptRoot 'check_windows_release_archive.ps1'))
$paths += @(Get-ChildItem -LiteralPath $PSScriptRoot -File -Filter 'test_install*windows.ps1' |
    ForEach-Object { $_.FullName })
foreach ($path in $paths) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        foreach ($parseError in $parseErrors) {
            Write-Host ("{0}:{1}:{2}: {3}" -f $path,
                $parseError.Extent.StartLineNumber,
                $parseError.Extent.StartColumnNumber,
                $parseError.Message)
        }
        throw "PowerShell syntax validation failed for $path."
    }
}
Write-Host "PowerShell syntax validation: PASS ($($paths.Count) scripts parsed)."
