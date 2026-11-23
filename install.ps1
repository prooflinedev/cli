# Install the official Proofline Windows x64 CLI release for the current user.
# Installer-managed upgrades use a verified previous image, a pending journal,
# and postcheck/rollback. Tested on Windows PowerShell 5.1 and PowerShell 7.
# .\install.ps1 [-Version 0.5.2] [-InstallDir C:\path\to\bin] [-NoModifyPath]
[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDir,
    [switch]$NoModifyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ProoflineArchiveName = 'proofline-x86_64-pc-windows-msvc.tar.gz'
$script:ProoflineOrigin = 'https://proofline.sh'
$script:MaxArchiveBytes = 64 * 1024 * 1024
$script:MaxExecutableBytes = 128 * 1024 * 1024

function Assert-ProoflinePlatform {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'The Windows installer can run only on Windows.'
    }
    $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    if ($architecture -ne 'X64') {
        throw "No official Windows release is available for architecture '$architecture' (expected X64)."
    }
}

function Assert-ProoflineVersion([string]$Value) {
    if ($Value.Length -gt 32 -or $Value -cnotmatch '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z') {
        throw 'Expected a release version of the form X.Y.Z, containing only digits and dots.'
    }
    return $Value
}

function Get-ProoflineOfficialBytes([string]$RelativePath, [int]$MaximumLength) {
    # The relative path is assembled exclusively from constant strings and a
    # validated version. Do not expose arbitrary URLs to installer arguments.
    if ($RelativePath -notmatch '\A/cli/(latest|download/[0-9]+\.[0-9]+\.[0-9]+/(SHA256SUMS|proofline-x86_64-pc-windows-msvc\.tar\.gz))\z') {
        throw 'Invalid official release request.'
    }
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    # PowerShell 5.1 uses .NET Framework, where HttpClientHandler.SslProtocols
    # may not be implemented. Scope TLS 1.2 to this download and restore the
    # process policy afterward. PowerShell 7 retains the system TLS defaults.
    $originalProtocol = $null
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        $originalProtocol = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(120)
    $cancellation = [Threading.CancellationTokenSource]::new()
    $cancellation.CancelAfter(120000)
    try {
        # Bound the complete response, including any stalled body reads.
        $downloadClock = [Diagnostics.Stopwatch]::StartNew()
        $uri = [Uri]($script:ProoflineOrigin + $RelativePath)
        for ($redirect = 0; $redirect -le 3; $redirect++) {
            $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token).GetAwaiter().GetResult()
            try {
                $status = [int]$response.StatusCode
                if ($status -in @(301, 302, 303, 307, 308)) {
                    if ($redirect -eq 3 -or $null -eq $response.Headers.Location) {
                        throw 'Too many redirects or a redirect without a Location header.'
                    }
                    $nextUri = [Uri]::new($uri, $response.Headers.Location)
                    if ($nextUri.Scheme -cne 'https' -or $nextUri.Host -cne 'proofline.sh' -or
                        -not $nextUri.IsDefaultPort -or $nextUri.UserInfo -ne '' -or
                        $nextUri.AbsolutePath -cne $uri.AbsolutePath -or $nextUri.Query -ne '') {
                        throw "The release endpoint redirected outside its approved HTTPS path: $nextUri"
                    }
                    $uri = $nextUri
                    continue
                }
                if ($status -ne 200) { throw "Official release download failed (HTTP $status): $uri" }
                if ($response.Content.Headers.ContentLength -gt $MaximumLength) {
                    throw 'Release download exceeds the permitted size.'
                }
                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $outputStream = [IO.MemoryStream]::new()
                try {
                    $buffer = [byte[]]::new(65536)
                    while ($true) {
                        $remaining = [int][Math]::Max(0, 120000 - $downloadClock.ElapsedMilliseconds)
                        if ($remaining -eq 0) {
                            $response.Dispose()
                            throw 'Release download exceeded its 120-second deadline.'
                        }
                        $read = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token)
                        # HttpClient.Timeout stops after headers with ResponseHeadersRead.
                        # On .NET Framework, stream cancellation may be ignored; bound
                        # the actual wait and close the response on timeout.
                        if (-not $read.Wait($remaining)) {
                            $response.Dispose()
                            throw 'Release download exceeded its 120-second deadline.'
                        }
                        $count = $read.GetAwaiter().GetResult()
                        if ($count -eq 0) { break }
                        if ($outputStream.Length + $count -gt $MaximumLength) {
                            throw 'Release download exceeds the permitted size.'
                        }
                        $outputStream.Write($buffer, 0, $count)
                    }
                    return ,($outputStream.ToArray())
                }
                finally {
                    $inputStream.Dispose()
                    $outputStream.Dispose()
                }
            }
            finally { $response.Dispose() }
        }
        throw 'Release download exhausted the redirect limit.'
    }
    finally {
        $cancellation.Dispose()
        $client.Dispose()
        $handler.Dispose()
        if ($null -ne $originalProtocol) {
            [Net.ServicePointManager]::SecurityProtocol = $originalProtocol
        }
    }
}

function Get-ProoflineLatestVersion {
    $bytes = Get-ProoflineOfficialBytes '/cli/latest' 128
    $value = ([Text.UTF8Encoding]::new($false, $true)).GetString($bytes)
    if ($value -notmatch '\A([0-9]+\.[0-9]+\.[0-9]+)\r?\n?\z') {
        throw 'The official latest-version pointer is malformed.'
    }
    return (Assert-ProoflineVersion $Matches[1])
}

function Assert-ProoflineChecksum([byte[]]$ArchiveBytes, [byte[]]$ManifestBytes) {
    if ($ArchiveBytes.Length -eq 0 -or $ArchiveBytes.Length -gt $script:MaxArchiveBytes) {
        throw 'Release archive is empty or too large.'
    }
    if ($ManifestBytes.Length -eq 0 -or $ManifestBytes.Length -gt 8192) {
        throw 'Release checksum manifest is empty or too large.'
    }
    $manifest = ([Text.UTF8Encoding]::new($false, $true)).GetString($ManifestBytes)
    $expected = $null
    $seen = @{}
    foreach ($line in ($manifest -split "`n")) {
        $line = $line.TrimEnd("`r")
        if ($line.Length -eq 0) { continue }
        if ($line -cnotmatch '\A([0-9a-fA-F]{64}) [ *](proofline-[a-zA-Z0-9_.-]+\.tar\.gz)\z') {
            throw 'The checksum manifest contains a malformed line.'
        }
        $digest = $Matches[1]
        $name = $Matches[2]
        if ($seen.ContainsKey($name)) { throw "Duplicate checksum entry: $name" }
        $seen[$name] = $true
        if ($name -ceq $script:ProoflineArchiveName) { $expected = $digest }
    }
    if ($null -eq $expected) { throw "SHA256SUMS does not list $script:ProoflineArchiveName" }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = [BitConverter]::ToString($hash.ComputeHash($ArchiveBytes)).Replace('-', '') }
    finally { $hash.Dispose() }
    if ($actual -cne $expected.ToUpperInvariant()) {
        throw 'Release checksum mismatch; no executable has been installed.'
    }
}

function Get-ProoflineTarOctal([byte[]]$Bytes, [int]$Offset, [int]$Width) {
    $field = ([Text.Encoding]::ASCII).GetString($Bytes, $Offset, $Width)
    if ($field -cnotmatch '\A[ \x00]*([0-7]+)[ \x00]*\z') {
        throw 'Invalid tar numeric field.'
    }
    return [Convert]::ToInt64($Matches[1], 8)
}

function Get-ProoflineTarName([byte[]]$Bytes, [int]$Offset, [int]$Width) {
    $stop = $Offset
    while ($stop -lt ($Offset + $Width) -and $Bytes[$stop] -ne 0) {
        if ($Bytes[$stop] -lt 32 -or $Bytes[$stop] -gt 126) {
            throw 'Tar path contains non-printable or non-ASCII bytes.'
        }
        $stop++
    }
    for ($i = $stop; $i -lt ($Offset + $Width); $i++) {
        if ($Bytes[$i] -ne 0) { throw 'Tar string field has data after its terminator.' }
    }
    return [Text.Encoding]::ASCII.GetString($Bytes, $Offset, $stop - $Offset)
}

function Get-ProoflineTarExecutable([byte[]]$ArchiveBytes) {
    # Decode into bounded memory, then independently parse a minimal, strict
    # one-member ustar archive; never ask tar.exe to unpack arbitrary paths.
    $source = [IO.MemoryStream]::new($ArchiveBytes, $false)
    $gzip = [IO.Compression.GZipStream]::new($source, [IO.Compression.CompressionMode]::Decompress)
    $output = [IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(65536)
        $limit = $script:MaxExecutableBytes + 10240
        while (($count = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($output.Length + $count -gt $limit) { throw 'Decompressed archive exceeds the permitted size.' }
            $output.Write($buffer, 0, $count)
        }
        $tar = $output.ToArray()
    }
    finally {
        $gzip.Dispose()
        $source.Dispose()
        $output.Dispose()
    }
    if ($tar.Length -lt 1536 -or $tar.Length % 512 -ne 0) {
        throw 'Release tar archive has invalid alignment or is truncated.'
    }
    $sum = 0L
    for ($i = 0; $i -lt 512; $i++) {
        if ($i -ge 148 -and $i -lt 156) { $sum += 32 }
        else { $sum += $tar[$i] }
    }
    if ((Get-ProoflineTarOctal $tar 148 8) -ne $sum) { throw 'Tar header checksum is invalid.' }
    if ((Get-ProoflineTarName $tar 0 100) -cne 'proofline.exe' -or
        (Get-ProoflineTarName $tar 345 155) -ne '' -or
        (Get-ProoflineTarName $tar 157 100) -ne '' -or
        $tar[156] -notin @(0, 48)) {
        throw 'Release archive must contain exactly one regular proofline.exe.'
    }
    $size = Get-ProoflineTarOctal $tar 124 12
    if ($size -lt 2 -or $size -gt $script:MaxExecutableBytes) {
        throw 'Release executable is empty or too large.'
    }
    $afterFile = [long]512 + $size
    $afterPadding = [long]([Math]::Ceiling($afterFile / 512.0) * 512)
    if ($afterPadding + 1024 -gt $tar.Length) { throw 'Release archive is truncated.' }
    for ($i = $afterFile; $i -lt $tar.Length; $i++) {
        if ($tar[$i] -ne 0) { throw 'Release archive has nonzero padding or an unexpected extra member.' }
    }
    $binary = [byte[]]::new([int]$size)
    [Array]::Copy($tar, 512, $binary, 0, [int]$size)
    if ($binary.Length -lt 256 -or $binary[0] -ne 77 -or $binary[1] -ne 90) {
        throw 'Release executable has no valid MZ header.'
    }
    $peOffset = [BitConverter]::ToInt32($binary, 0x3c)
    if ($peOffset -lt 64 -or $peOffset -gt ($binary.Length - 4) -or
        $binary[$peOffset] -ne 80 -or $binary[$peOffset + 1] -ne 69 -or
        $binary[$peOffset + 2] -ne 0 -or $binary[$peOffset + 3] -ne 0) {
        throw 'Release executable has no valid PE signature.'
    }
    return ,$binary
}

function Resolve-ProoflineInstallDir([string]$Requested) {
    if ([string]::IsNullOrWhiteSpace($Requested)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA is missing.' }
        $Requested = [IO.Path]::Combine($env:LOCALAPPDATA, 'Programs', 'Proofline', 'bin')
    }
    # Reject UNC/device paths and relative paths. An explicit path must be an
    # ordinary absolute drive path with no PATH delimiter.
    if ($Requested -notmatch '^[A-Za-z]:[\\/]' -or $Requested.Contains(';')) {
        throw 'InstallDir must be a local absolute drive path without semicolons.'
    }
    return [IO.Path]::GetFullPath($Requested)
}

function Assert-ProoflineNoReparse([string]$Path) {
    if ([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)) {
        if (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing an install path that is a symbolic link or reparse point: $Path"
        }
    }
}

function Get-ProoflineUpdatedUserPath([string]$Current, [string]$Directory) {
    if ($null -eq $Current) { $Current = '' }
    $normalized = $Directory.TrimEnd([char[]]@('\', '/'))
    foreach ($entry in ($Current -split ';')) {
        $expanded = [Environment]::ExpandEnvironmentVariables($entry.Trim())
        if ($expanded.TrimEnd([char[]]@('\', '/')) -ieq $normalized) {
            return $null # already present; no registry write needed
        }
    }
    $result = if ($Current.TrimEnd(';') -eq '') { $Directory } else { $Current.TrimEnd(';') + ';' + $Directory }
    if ($result.Length -gt 30000) { throw 'User PATH is too long; add the directory manually.' }
    return $result
}

function Get-ProoflineUserPathRecord {
    # Environment.GetEnvironmentVariable('Path', 'User') expands REG_EXPAND_SZ.
    # Read raw text and the registry kind to avoid flattening %VARIABLE% entries.
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    if ($null -eq $key) {
        return @{ value = ''; kind = [Microsoft.Win32.RegistryValueKind]::ExpandString; exists = $false }
    }
    try {
        if ('Path' -notin @($key.GetValueNames())) {
            return @{ value = ''; kind = [Microsoft.Win32.RegistryValueKind]::ExpandString; exists = $false }
        }
        $kind = $key.GetValueKind('Path')
        if ($kind -notin @([Microsoft.Win32.RegistryValueKind]::String,
                          [Microsoft.Win32.RegistryValueKind]::ExpandString)) {
            throw 'User PATH registry value has an unsupported type; change it manually.'
        }
        $value = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($value -isnot [string]) { throw 'User PATH registry value is not text.' }
        return @{ value = $value; kind = $kind; exists = $true }
    }
    finally { $key.Dispose() }
}

function Send-ProoflineEnvironmentChange {
    # RegistryKey.SetValue retains REG_EXPAND_SZ but does not notify other
    # processes. Notify the shell as Environment.SetEnvironmentVariable does.
    if (-not ('ProoflineEnvironmentNotifier' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ProoflineEnvironmentNotifier {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr hwnd, uint msg,
        IntPtr wParam, string lParam, uint flags, uint timeout, out IntPtr result);
}
'@
    }
    $result = [IntPtr]::Zero
    $sent = [ProoflineEnvironmentNotifier]::SendMessageTimeout(
        [IntPtr]65535, 0x1a, [IntPtr]::Zero, 'Environment', 0x2, 5000, [ref]$result)
    if ($sent -eq [IntPtr]::Zero) {
        Write-Warning 'User PATH was saved, but the environment-change notification was not acknowledged. Open a new terminal.'
    }
}

function Add-ProoflineUserPath([string]$Directory) {
    $previous = Get-ProoflineUserPathRecord
    $result = Get-ProoflineUpdatedUserPath $previous.value $Directory
    if ($null -eq $result) {
        Write-Host 'User PATH already contains the Proofline directory.'
        return
    }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        # Avoid an obvious lost update if another process changed PATH since
        # our read. This is not a cross-process atomic registry compare/swap.
        $fresh = Get-ProoflineUserPathRecord
        if ($fresh.value -cne $previous.value -or
            $fresh.kind -ne $previous.kind -or $fresh.exists -ne $previous.exists) {
            throw 'User PATH changed concurrently; retry the installer or add the directory manually.'
        }
        $key.SetValue('Path', $result, $previous.kind)
    }
    finally { $key.Dispose() }
    Send-ProoflineEnvironmentChange
    Write-Host 'Added Proofline to your user PATH. Open a new terminal to use it.'
}


function Assert-ProoflinePathTree([string]$Directory) {
    # A pre-existing reparse-point ancestor can redirect writes outside the
    # requested directory. Check all existing ancestors and refuse such paths.
    $cursor = [IO.DirectoryInfo]::new($Directory)
    while ($null -ne $cursor) {
        if ($cursor.Exists -and
            ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing a directory that contains a reparse point: $($cursor.FullName)"
        }
        $cursor = $cursor.Parent
    }
}

function Get-ProoflineSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Assert-ProoflineExeVersion([string]$Path, [string]$Version) {
    # Run only a checksum-verified release, never a raw unverified download.
    # Process isolation and timeout avoid hanging this installer indefinitely.
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Path
    $startInfo.Arguments = '--version'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'Candidate executable did not start.' }
        if (-not $process.WaitForExit(15000)) {
            try { $process.Kill() } catch { }
            throw 'Candidate executable did not exit within 15 seconds.'
        }
        $actual = $process.StandardOutput.ReadToEnd().Trim()
        $stderr = $process.StandardError.ReadToEnd().Trim()
        if ($process.ExitCode -ne 0 -or $actual -cne "proofline $Version" -or $stderr -ne '') {
            throw "Executable version check failed (expected 'proofline $Version', exit $($process.ExitCode), got '$actual' '$stderr')."
        }
    }
    finally { $process.Dispose() }
}

function Write-ProoflineAtomicRecord([string]$Path, [string]$Content) {
    # Only used for first install. Do not overwrite existing transaction files.
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $file = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Content)
        $file.Write($bytes, 0, $bytes.Length)
        $file.Flush($true)
    }
    finally { $file.Dispose() }
    try { [IO.File]::Move($temporary, $Path) }
    finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Assert-ProoflineRecord([string]$Path, [string]$ExpectedVersion, [string]$ExpectedHash) {
    $record = Read-ProoflineReceipt $Path
    if ($record.version -cne $ExpectedVersion -or $record.sha256 -cne $ExpectedHash) {
        throw "An existing Proofline installation record does not match this release: $Path"
    }
}

function Read-ProoflineReceipt([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { throw 'No installer-managed receipt exists.' }
    if (([IO.FileInfo]$Path).Length -gt 4096) { throw 'Installation receipt is too large.' }
    $record = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Path))
    if ($null -eq $record -or $record.schema -ne 1 -or
        $record.sha256 -cnotmatch '\A[A-F0-9]{64}\z') {
        throw 'Installation receipt is invalid; refusing to modify existing executable.'
    }
    [void](Assert-ProoflineVersion $record.version)
    return $record
}

function Write-ProoflineReceipt([string]$Path, [string]$Version, [string]$Hash) {
    $record = ConvertTo-Json -Compress -InputObject ([ordered]@{
        schema = 1
        version = $Version
        sha256 = $Hash
    })
    if (-not [IO.File]::Exists($Path)) {
        Write-ProoflineAtomicRecord $Path $record
    }
    else {
        $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
        $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($record)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        # PowerShell 5.1/.NET Framework rejected a null backup path on
        # receipt replacement. Give File.Replace a real, unique same-volume
        # backup path. Preserve that backup if replacement/validation fails.
        $backup = $Path + '.' + [guid]::NewGuid().ToString('N') + '.bak'
        $verified = $false
        try {
            [IO.File]::Replace($temp, $Path, $backup)
            Assert-ProoflineRecord $Path $Version $Hash
            $verified = $true
        }
        finally {
            if ([IO.File]::Exists($temp)) {
                try { [IO.File]::Delete($temp) }
                catch { Write-Warning "Receipt staging file remains at $temp" }
            }
            # Journaled installer recovery handles errors before this point.
            # Never discard a previous receipt until the new one is verified.
            if ($verified -and [IO.File]::Exists($backup)) {
                try { [IO.File]::Delete($backup) }
                catch { Write-Warning "Previous receipt backup remains at $backup" }
            }
        }
    }
    Assert-ProoflineRecord $Path $Version $Hash
}

function Read-ProoflinePending([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { return $null }
    if (([IO.FileInfo]$Path).Length -gt 4096) { throw 'Pending transaction is too large.' }
    $record = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Path))
    if ($null -eq $record) { throw 'Pending transaction is empty.' }
    if ($record.schema -in @(1, 3)) {
        if ($record.sha256 -cnotmatch '\A[A-F0-9]{64}\z') {
            throw 'Pending first-install digest is invalid.'
        }
        [void](Assert-ProoflineVersion $record.version)
        if ($record.schema -eq 3) {
            if ($record.id -cnotmatch '\A[0-9a-f]{32}\z') {
                throw 'Pending first-install stage ID is invalid.'
            }
            $firstPostcheck = $record.PSObject.Properties['postcheck']
            if ($null -ne $firstPostcheck -and $firstPostcheck.Value -cnotin @('checking', 'passed')) {
                throw 'Pending first-install postcheck state is invalid.'
            }
        }
        return $record
    }
    if ($record.schema -ne 2 -or
        $record.id -cnotmatch '\A[0-9a-f]{32}\z' -or
        $record.oldSha256 -cnotmatch '\A[A-F0-9]{64}\z' -or
        $record.newSha256 -cnotmatch '\A[A-F0-9]{64}\z') {
        throw 'Pending upgrade record is invalid.'
    }
    [void](Assert-ProoflineVersion $record.oldVersion)
    [void](Assert-ProoflineVersion $record.newVersion)
    if ($record.oldSha256 -ceq $record.newSha256) {
        throw 'Pending upgrade has identical old and new digests.'
    }
    $postcheck = $record.PSObject.Properties['postcheck']
    if ($null -ne $postcheck -and $postcheck.Value -cnotin @('checking', 'passed')) {
        throw 'Pending upgrade postcheck state is invalid.'
    }
    return $record
}

function Set-ProoflinePendingPostcheck([string]$Pending, [ValidateSet('checking', 'passed')][string]$State) {
    # Record validation progress durably before publishing an installed image.
    # A failed or interrupted postcheck must never be finalized by hash alone.
    $record = Read-ProoflinePending $Pending
    if ($null -eq $record -or $record.schema -notin @(2, 3)) {
        throw 'Cannot update postcheck state without a valid installation journal.'
    }
    $currentProperty = $record.PSObject.Properties['postcheck']
    $current = if ($null -eq $currentProperty) { $null } else { $currentProperty.Value }
    if (($State -ceq 'checking' -and ($record.schema -ne 2 -or $null -ne $current)) -or
        ($State -ceq 'passed' -and $current -cne 'checking')) {
        throw 'Invalid installation postcheck state transition.'
    }
    $record | Add-Member -NotePropertyName postcheck -NotePropertyValue $State -Force
    $temporary = $Pending + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $backup = $Pending + '.' + [guid]::NewGuid().ToString('N') + '.bak'
    foreach ($path in @($Pending, $temporary, $backup)) { Assert-ProoflineNoReparse $path }
    $verified = $false
    try {
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $json = ConvertTo-Json -Compress -InputObject $record
            $bytes = [Text.Encoding]::UTF8.GetBytes($json)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
        [IO.File]::Replace($temporary, $Pending, $backup)
        $updated = Read-ProoflinePending $Pending
        if ($updated.id -cne $record.id -or $updated.postcheck -cne $State) {
            throw 'Could not verify the persisted upgrade postcheck state.'
        }
        $verified = $true
    }
    finally {
        if ([IO.File]::Exists($temporary)) {
            try { [IO.File]::Delete($temporary) }
            catch { Write-Warning "Postcheck journal staging file remains at $temporary" }
        }
        if ($verified -and [IO.File]::Exists($backup)) {
            try { [IO.File]::Delete($backup) }
            catch { Write-Warning "Previous postcheck journal copy remains at $backup" }
        }
    }
}

function Get-ProoflineTransactionPaths([string]$Directory, [string]$Id) {
    # NEVER use a path supplied directly by transaction JSON.
    if ($Id -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Invalid transaction ID.' }
    return @{
        old = [IO.Path]::Combine($Directory, ".proofline-recovery-$Id.exe")
        api = [IO.Path]::Combine($Directory, ".proofline-api-backup-$Id.exe")
        damaged = [IO.Path]::Combine($Directory, ".proofline-damaged-$Id.exe")
        stage = [IO.Path]::Combine($Directory, ".proofline-staged-$Id.exe")
    }
}

function Clear-ProoflineUpgradeFiles(
    [hashtable]$Paths, [string]$Pending, [string]$NewHash,
    [switch]$PreserveIncompleteStage
) {
    # Only delete transaction-owned artifacts derived from a validated ID.
    foreach ($key in @('old', 'api', 'stage')) {
        Assert-ProoflineNoReparse $Paths[$key]
    }
    if ([IO.File]::Exists($Paths.stage) -and
        (Get-ProoflineSha256 $Paths.stage) -cne $NewHash) {
        if (-not $PreserveIncompleteStage) {
            throw 'Pending upgrade stage has unexpected contents; preserving transaction evidence.'
        }
        # Before switching, the installed old executable is still intact.
        # Quarantine an incomplete stage instead of permanently blocking retry.
        $evidence = $Paths.stage + '.incomplete'
        Assert-ProoflineNoReparse $evidence
        if ([IO.File]::Exists($evidence)) {
            throw 'Incomplete-stage evidence path already exists; preserving the journal.'
        }
        [IO.File]::Move($Paths.stage, $evidence)
        Write-Warning "Unverified interrupted upgrade stage preserved at $evidence"
    }
    foreach ($key in @('old', 'api', 'stage')) {
        if ([IO.File]::Exists($Paths[$key])) { [IO.File]::Delete($Paths[$key]) }
    }
    [IO.File]::Delete($Pending) # delete journal LAST
}

function Recover-ProoflinePending([string]$Directory) {
    # Caller MUST hold the stable installer lock during this operation.
    $destination = [IO.Path]::Combine($Directory, 'proofline.exe')
    $receipt = [IO.Path]::Combine($Directory, '.proofline-install.receipt.json')
    $pending = [IO.Path]::Combine($Directory, '.proofline-install.pending.json')
    $record = Read-ProoflinePending $pending
    if ($null -eq $record) { return }
    foreach ($path in @($destination, $receipt, $pending)) {
        Assert-ProoflineNoReparse $path
    }

    if ($record.schema -in @(1, 3)) {
        # Schema 3 records the exact stage ID BEFORE any staged file is
        # created. This makes a killed first install recoverable even when
        # termination occurs before the executable move. Legacy schema 1
        # journal recovery remains supported without guessing stage paths.
        $stage = $null
        if ($record.schema -eq 3) {
            $stage = [IO.Path]::Combine($Directory, ('.proofline-staged-' + $record.id + '.exe'))
            Assert-ProoflineNoReparse $stage
        }
        if (-not [IO.File]::Exists($destination)) {
            if ([IO.File]::Exists($receipt)) {
                throw 'Interrupted first installation has a receipt but no executable.'
            }
            if ($null -ne $stage -and [IO.File]::Exists($stage)) {
                if ((Get-ProoflineSha256 $stage) -cne $record.sha256) {
                    # No executable was published. Keep incomplete bytes for
                    # diagnosis, but remove the transaction's blocking journal.
                    $evidence = $stage + '.incomplete'
                    Assert-ProoflineNoReparse $evidence
                    if ([IO.File]::Exists($evidence)) {
                        throw 'Incomplete-stage evidence path already exists; preserving journal.'
                    }
                    [IO.File]::Move($stage, $evidence)
                    Write-Warning "Unverified first-install stage preserved at $evidence"
                }
                else { [IO.File]::Delete($stage) }
            }
            [IO.File]::Delete($pending)
            return
        }
        if ($null -ne $stage -and [IO.File]::Exists($stage) -and
            (Get-ProoflineSha256 $stage) -cne $record.sha256) {
            throw 'Published first-install executable has an unverified stage; preserving journal.'
        }
        if ((Get-ProoflineSha256 $destination) -cne $record.sha256) {
            throw 'Interrupted first install has an unrecognized executable; preserving journal.'
        }
        # A matching digest is not proof that the installed executable can
        # start. Never execute a pre-existing image verified only against local
        # mutable journal metadata. Require a persisted successful postcheck.
        $firstStatus = $record.PSObject.Properties['postcheck']
        $passedFirst = ($null -ne $firstStatus -and $firstStatus.Value -ceq 'passed')
        if (-not $passedFirst -and $record.schema -eq 1 -and [IO.File]::Exists($receipt)) {
            # Legacy first-install journals had no postcheck state. A valid
            # matching receipt is evidence the old installer completed its
            # installed-path check before writing that receipt.
            Assert-ProoflineRecord $receipt $record.version $record.sha256
            $passedFirst = $true
        }
        if (-not $passedFirst) {
            if ([IO.File]::Exists($receipt)) {
                throw 'An unverified first install has a receipt; preserving transaction evidence.'
            }
            $evidenceId = if ($record.schema -eq 3) { $record.id } else { [guid]::NewGuid().ToString('N') }
            $evidence = [IO.Path]::Combine($Directory, ".proofline-unverified-first-$evidenceId.exe")
            Assert-ProoflineNoReparse $evidence
            if ([IO.File]::Exists($evidence)) { throw 'First-install quarantine path exists; preserving recovery journal.' }
            [IO.File]::Move($destination, $evidence)
            if ($null -ne $stage -and [IO.File]::Exists($stage)) { [IO.File]::Delete($stage) }
            [IO.File]::Delete($pending)
            Write-Warning "Unverified first-install executable quarantined at $evidence; retry installation."
            return
        }
        if ([IO.File]::Exists($receipt)) {
            Assert-ProoflineRecord $receipt $record.version $record.sha256
        }
        else { Write-ProoflineReceipt $receipt $record.version $record.sha256 }
        if ($null -ne $stage -and [IO.File]::Exists($stage)) {
            [IO.File]::Delete($stage)
        }
        [IO.File]::Delete($pending)
        Write-Host 'Recovered verified first installation.'
        return
    }

    $paths = Get-ProoflineTransactionPaths $Directory $record.id
    foreach ($path in $paths.Values) { Assert-ProoflineNoReparse $path }
    $activeHash = $null
    if ([IO.File]::Exists($destination)) { $activeHash = Get-ProoflineSha256 $destination }

    # If post-replacement validation was in progress at interruption, or
    # explicitly failed, keep the previous verified version. A matching SHA
    # does not establish that the new executable can start successfully.
    $postcheck = $record.PSObject.Properties['postcheck']
    $postcheckVerified = ($null -ne $postcheck -and $postcheck.Value -ceq 'passed')
    if ($activeHash -ceq $record.newSha256 -and $postcheckVerified) {
        $finalized = $false
        try {
            # A local journal hash is not sufficient authority to execute
            # an existing image. Validate bytes and write the matching receipt.
            Write-ProoflineReceipt $receipt $record.newVersion $record.newSha256
            $finalized = $true
        }
        catch {
            Write-Warning "New executable is present but cannot be finalized: $($_.Exception.Message)"
        }
        if ($finalized) {
            # Cleaning old files is not part of the successful version switch.
            # Preserve the new executable and journal if cleanup must be retried.
            try { Clear-ProoflineUpgradeFiles $paths $pending $record.newSha256 }
            catch { Write-Warning "Upgrade finalized; cleanup will be retried: $($_.Exception.Message)" }
            Write-Host "Finalized interrupted Proofline $($record.newVersion) upgrade."
            return
        }
    }

    if ($activeHash -ceq $record.oldSha256) {
        Write-ProoflineReceipt $receipt $record.oldVersion $record.oldSha256
        try { Clear-ProoflineUpgradeFiles $paths $pending $record.newSha256 -PreserveIncompleteStage }
        catch { Write-Warning "Verified previous installation retained; cleanup will be retried: $($_.Exception.Message)" }
        Write-Host "Previous Proofline $($record.oldVersion) installation remains usable."
        return
    }

    $source = $null
    foreach ($candidate in @($paths.old, $paths.api)) {
        if (-not [IO.File]::Exists($candidate)) { continue }
        try {
            if ((Get-ProoflineSha256 $candidate) -ceq $record.oldSha256) {
                $source = $candidate
                break
            }
        }
        catch {
            # An unreadable primary copy must not mask a valid secondary.
            Write-Warning "Cannot read recovery candidate $candidate; checking the next verified copy: $($_.Exception.Message)"
        }
    }
    if ($null -eq $source) {
        throw 'Neither executable is verified and no valid previous-version copy remains. Files and recovery journal preserved.'
    }

    $restore = [IO.Path]::Combine($Directory, ('.proofline-restore-' + [guid]::NewGuid().ToString('N') + '.exe'))
    [IO.File]::Copy($source, $restore, $false)
    try {
        if ((Get-ProoflineSha256 $restore) -cne $record.oldSha256) {
            throw 'Verified recovery copy changed while preparing rollback.'
        }
        if ([IO.File]::Exists($destination)) {
            if ([IO.File]::Exists($paths.damaged)) {
                throw 'Damaged-file evidence path already exists; manual recovery required.'
            }
            [IO.File]::Replace($restore, $destination, $paths.damaged)
        } else {
            [IO.File]::Move($restore, $destination)
        }
        if ((Get-ProoflineSha256 $destination) -cne $record.oldSha256) {
            throw 'Restored executable digest differs from previous release.'
        }
        # Recovery copy was checked against the recorded hash; do not execute
        # a pre-existing local image during repair.
        Write-ProoflineReceipt $receipt $record.oldVersion $record.oldSha256
        Clear-ProoflineUpgradeFiles $paths $pending $record.newSha256
        Write-Host "Restored verified Proofline $($record.oldVersion) after interrupted upgrade."
    }
    finally {
        if ([IO.File]::Exists($restore)) {
            try { [IO.File]::Delete($restore) }
            catch { Write-Warning "Recovery staging file remains: $restore" }
        }
    }
}

function Invoke-ProoflinePendingRepair([string]$Directory) {
    # Recover BEFORE network activity, so an outage cannot block local repair.
    $directory = Resolve-ProoflineInstallDir $Directory
    Assert-ProoflinePathTree $directory
    if (-not [IO.Directory]::Exists($directory)) { return }
    $pending = [IO.Path]::Combine($directory, '.proofline-install.pending.json')
    if (-not [IO.File]::Exists($pending)) { return }
    $lock = [IO.Path]::Combine($directory, '.proofline-install.lock')
    Assert-ProoflineNoReparse $lock
    $handle = [IO.File]::Open($lock, [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { Recover-ProoflinePending $directory }
    finally { $handle.Dispose() }
}

function Test-ProoflineTransientReplaceFailure([Exception]$Error) {
    # Retry only Win32 sharing (32) and lock (33) violations, not
    # arbitrary permission errors or partial filesystem failures.
    $current = $Error
    while ($null -ne $current) {
        if ($current -is [IO.IOException] -and
            $current.HResult -in @(-2147024864, -2147024863)) {
            return $true
        }
        $current = $current.InnerException
    }
    return $false
}

function Invoke-ProoflineReplaceWithRetry(
    [string]$Candidate,
    [string]$Destination,
    [string]$Backup,
    [string]$NewHash,
    [string]$OldHash
) {
    # A recently executed binary or filesystem scanner can hold a transient
    # handle. Retry only after confirming BOTH files retain pre-switch bytes
    # and backup path has NOT appeared. Never retry a partial replacement.
    $delays = @(0, 150, 300, 600, 1200, 2400)
    for ($index = 0; $index -lt $delays.Count; $index++) {
        if ($index -gt 0) {
            Start-Sleep -Milliseconds $delays[$index]
            foreach ($path in @($Candidate, $Destination, $Backup)) {
                Assert-ProoflineNoReparse $path
            }
            if (-not [IO.File]::Exists($Candidate) -or
                -not [IO.File]::Exists($Destination) -or
                [IO.File]::Exists($Backup) -or
                (Get-ProoflineSha256 $Candidate) -cne $NewHash -or
                (Get-ProoflineSha256 $Destination) -cne $OldHash) {
                throw 'Replacement files changed after sharing failure; unsafe to retry.'
            }
        }
        try {
            [IO.File]::Replace($Candidate, $Destination, $Backup)
            return
        }
        catch {
            if (-not (Test-ProoflineTransientReplaceFailure $_.Exception) -or
                $index -eq ($delays.Count - 1)) {
                throw
            }
            Write-Warning "Executable replacement is temporarily locked; retrying verified state ($($index + 1)/$($delays.Count))."
        }
    }
}

function Install-ProoflineArchive(
    [byte[]]$ArchiveBytes,
    [byte[]]$ChecksumBytes,
    [string]$ReleaseVersion,
    [string]$Directory
) {
    $ReleaseVersion = Assert-ProoflineVersion $ReleaseVersion
    Assert-ProoflineChecksum $ArchiveBytes $ChecksumBytes
    $binary = Get-ProoflineTarExecutable $ArchiveBytes
    $digest = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($digest.ComputeHash($binary)).Replace('-', '') }
    finally { $digest.Dispose() }

    $directory = Resolve-ProoflineInstallDir $Directory
    Assert-ProoflinePathTree $directory
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $destination = [IO.Path]::Combine($directory, 'proofline.exe')
    $receipt = [IO.Path]::Combine($directory, '.proofline-install.receipt.json')
    $pending = [IO.Path]::Combine($directory, '.proofline-install.pending.json')
    $lock = [IO.Path]::Combine($directory, '.proofline-install.lock')
    foreach ($path in @($destination, $receipt, $pending, $lock)) {
        Assert-ProoflineNoReparse $path
    }
    try {
        $lockHandle = [IO.File]::Open($lock, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch { throw "Another installer may be running, or the lock file is unavailable: $($_.Exception.Message)" }
    try {
        # Handle a concurrent previous installer that stopped during download.
        if ([IO.File]::Exists($pending)) {
            Recover-ProoflinePending $directory
        }
        $hasDestination = [IO.File]::Exists($destination)
        $hasReceipt = [IO.File]::Exists($receipt)
        if ($hasDestination -ne $hasReceipt) {
            throw 'Incomplete or unmanaged existing installation; refusing to overwrite it.'
        }
        $oldReceipt = $null
        if ($hasDestination) {
            $oldReceipt = Read-ProoflineReceipt $receipt
            if ((Get-ProoflineSha256 $destination) -cne $oldReceipt.sha256) {
                throw 'Existing Proofline executable does not match its installer-managed receipt.'
            }
            # Existing binaries are not executed merely because a local
            # receipt contains a matching hash. Only verified downloads run.
            if ($oldReceipt.version -ceq $ReleaseVersion -and
                $oldReceipt.sha256 -ceq $hash) {
                Write-Host "Proofline $ReleaseVersion is already installed; nothing was changed."
                return $destination
            }
        }
        # Tie the stage path to the same validated transaction ID that the
        # pending journal records. Recovery can now clean ONLY its own stage.
        $id = [guid]::NewGuid().ToString('N')
        $stage = [IO.Path]::Combine($directory, ('.proofline-staged-' + $id + '.exe'))
        Assert-ProoflineNoReparse $stage
        if ($null -eq $oldReceipt) {
            $record = ConvertTo-Json -Compress -InputObject ([ordered]@{
                schema = 3
                id = $id
                version = $ReleaseVersion
                sha256 = $hash
                postcheck = 'checking'
            })
        }
        else {
            # Journal BEFORE creating the staged image or previous-version
            # copy. A killed preparation then has an exact transaction ID
            # with which to clean up owned artifacts.
            $record = ConvertTo-Json -Compress -InputObject ([ordered]@{
                schema = 2
                id = $id
                oldVersion = $oldReceipt.version
                oldSha256 = $oldReceipt.sha256
                newVersion = $ReleaseVersion
                newSha256 = $hash
            })
        }
        Write-ProoflineAtomicRecord $pending $record
        try {
            $stream = [IO.File]::Open($stage, [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $stream.Write($binary, 0, $binary.Length)
                $stream.Flush($true)
            }
            finally { $stream.Dispose() }
            Assert-ProoflineExeVersion $stage $ReleaseVersion

            if ($null -eq $oldReceipt) {
                [IO.File]::Move($stage, $destination)
                if ((Get-ProoflineSha256 $destination) -cne $hash) {
                    throw 'Installed executable digest differs after relocation.'
                }
                Assert-ProoflineExeVersion $destination $ReleaseVersion
                Set-ProoflinePendingPostcheck $pending 'passed'
                Write-ProoflineReceipt $receipt $ReleaseVersion $hash
                [IO.File]::Delete($pending)
                return $destination
            }

            # Upgrade: independently preserve the previous verified executable.
            $paths = Get-ProoflineTransactionPaths $directory $id
            foreach ($path in $paths.Values) { Assert-ProoflineNoReparse $path }
            [IO.File]::Copy($destination, $paths.old, $false)
            if ((Get-ProoflineSha256 $paths.old) -cne $oldReceipt.sha256) {
                throw 'Could not preserve a verified previous executable; upgrade aborted.'
            }
            try {
                # Mark validation in-progress BEFORE switching the image.
                # A crash after switch but before postcheck will conservatively
                # restore the previous executable instead of adopting untested bytes.
                Set-ProoflinePendingPostcheck $pending 'checking'
                Invoke-ProoflineReplaceWithRetry $stage $destination $paths.api $hash $oldReceipt.sha256
                if ((Get-ProoflineSha256 $destination) -cne $hash) {
                    throw 'Upgraded executable digest differs from verified candidate.'
                }
                Assert-ProoflineExeVersion $destination $ReleaseVersion
                Set-ProoflinePendingPostcheck $pending 'passed'
                Write-ProoflineReceipt $receipt $ReleaseVersion $hash
                try { Clear-ProoflineUpgradeFiles $paths $pending $hash }
                catch { Write-Warning "Verified upgrade retained; cleanup will be retried: $($_.Exception.Message)" }
                Write-Host "Upgraded Proofline $($oldReceipt.version) to $ReleaseVersion."
                return $destination
            }
            catch {
                $originalError = $_.Exception.Message
                try { Recover-ProoflinePending $directory }
                catch {
                    throw "Upgrade failed ($originalError). Automatic recovery also failed: $($_.Exception.Message). Transaction evidence was preserved."
                }
                throw "Upgrade encountered an error ($originalError); recovery was attempted. Verify the reported installed version."
            }
        }
        finally {
            if ([IO.File]::Exists($stage)) {
                try { [IO.File]::Delete($stage) }
                catch { Write-Warning "Staged file remains at $stage" }
            }
        }
    }
    finally { $lockHandle.Dispose() }
}

function Invoke-ProoflineInstaller([string]$RequestedVersion, [string]$RequestedDirectory, [bool]$ModifyPath) {
    Assert-ProoflinePlatform
    Invoke-ProoflinePendingRepair $RequestedDirectory
    $release = if ([string]::IsNullOrWhiteSpace($RequestedVersion)) {
        Get-ProoflineLatestVersion
    } else { Assert-ProoflineVersion $RequestedVersion }
    $prefix = "/cli/download/$release"
    Write-Host "Downloading Proofline $release for Windows x64..."
    $archive = Get-ProoflineOfficialBytes "$prefix/$script:ProoflineArchiveName" $script:MaxArchiveBytes
    $sums = Get-ProoflineOfficialBytes "$prefix/SHA256SUMS" 8192
    $installed = Install-ProoflineArchive $archive $sums $release $RequestedDirectory
    Write-Host "Verified proofline $release at $installed"
    if ($ModifyPath) {
        try { Add-ProoflineUserPath ([IO.Path]::GetDirectoryName($installed)) }
        catch { Write-Warning "Proofline installed, but PATH update failed: $($_.Exception.Message)" }
    }
    else { Write-Host 'PATH unchanged (-NoModifyPath was selected).' }
    Write-Host 'Next: open a new terminal and run proofline login.'
}

# Dot-sourcing allows the non-mutating validator functions to be unit tested.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-ProoflineInstaller $Version $InstallDir (-not [bool]$NoModifyPath) }
    catch {
        [Console]::Error.WriteLine("proofline install: $($_.Exception.Message)")
        exit 1
    }
}
