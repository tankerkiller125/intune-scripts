<#
.SYNOPSIS
Intune remediation script for outdated OpenSSL DLLs.

.DESCRIPTION
Uses detection-produced inventory in ProgramData to locate OpenSSL DLLs,
downloads latest available ZIP packages by major version, extracts replacement
DLLs, and updates DLLs in place.

Exit codes:
  0 = remediation success or no-op
  1 = remediation failure
#>

[CmdletBinding()]
param(
    [switch]$VerboseMode,
    [switch]$DryRun,
    [switch]$WithBackup,
    [switch]$RestoreBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($VerboseMode) { $VerbosePreference = 'Continue' }

$Script:InventoryRoot = Join-Path $env:ProgramData 'IntuneOpenSSLRemediation'
$Script:InventoryPath = Join-Path $Script:InventoryRoot 'openssl-dll-inventory.json'
$Script:WorkRoot = Join-Path $Script:InventoryRoot 'work'

function Convert-LetterToNumber {
    param([string]$Letter)
    if ([string]::IsNullOrWhiteSpace($Letter)) { return 0 }
    return ([int][char]$Letter.ToLowerInvariant() - [int][char]'a') + 1
}

function Parse-OpenSslVersion {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text, '(?<maj>\d+)\.(?<min>\d+)\.(?<pat>\d+)(?<let>[a-z]?)', 'IgnoreCase')
    if (-not $m.Success) { return $null }

    $baseMajor = [int]$m.Groups['maj'].Value
    $baseMinor = [int]$m.Groups['min'].Value
    $basePatch = [int]$m.Groups['pat'].Value
    $letter = $m.Groups['let'].Value

    if ($baseMajor -eq 1) {
        return [pscustomobject]@{
            Major       = 1
            Minor       = $baseMinor
            Patch       = $basePatch
            Letter      = $letter
            LetterNum   = Convert-LetterToNumber -Letter $letter
            Raw         = $m.Value
            LegacyMajor = $baseMinor
            LegacyMinor = $basePatch
        }
    }

    [pscustomobject]@{
        Major     = $baseMajor
        Minor     = $baseMinor
        Patch     = $basePatch
        Letter    = $letter
        LetterNum = Convert-LetterToNumber -Letter $letter
        Raw       = $m.Value
    }
}

function Get-PortableExecutableArchitecture {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $reader = $null
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $reader = New-Object System.IO.BinaryReader($stream)

            $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
            $peOffset = $reader.ReadInt32()

            $stream.Seek($peOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
            $machine = $reader.ReadUInt16()

            switch ($machine) {
                0x014c { return 'x86' }
                0x8664 { return 'x64' }
                0xAA64 { return 'arm64' }
                default { return 'unknown' }
            }
        }
        finally {
            if ($null -ne $reader) {
                $reader.Close()
            }
        }
    }
    catch {
        return 'unknown'
    }
}

function Get-EntryArchitecture {
    param([Parameter(Mandatory = $true)]$Entry)

    $hasArchProperty = $Entry.PSObject.Properties.Match('Architecture').Count -gt 0
    if ($hasArchProperty -and -not [string]::IsNullOrWhiteSpace($Entry.Architecture)) {
        return [string]$Entry.Architecture
    }

    if (Test-Path -LiteralPath $Entry.Path) {
        return Get-PortableExecutableArchitecture -Path $Entry.Path
    }

    return 'unknown'
}

function Compare-OpenSslVersion {
    param(
        [Parameter(Mandatory = $true)]$Left,
        [Parameter(Mandatory = $true)]$Right
    )

    foreach ($p in @('Major', 'Minor', 'Patch', 'LetterNum')) {
        if ($Left.$p -gt $Right.$p) { return 1 }
        if ($Left.$p -lt $Right.$p) { return -1 }
    }
    return 0
}

function Get-WinOpenSslZipPackages {
    $sourceUrl = 'https://www.firedaemon.com/get-openssl'
    $resp = Invoke-WebRequest -Uri $sourceUrl -UseBasicParsing -TimeoutSec 60

    $rx = [regex]'https://download\.firedaemon\.com/FireDaemon-OpenSSL/openssl-(?<ver>\d+\.\d+\.\d+[a-z]?)\.zip'
    $packages = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($m in $rx.Matches($resp.Content)) {
        $url = $m.Value
        if (-not $seen.Add($url)) { continue }

        $ver = Parse-OpenSslVersion -Text $m.Groups['ver'].Value
        if ($null -eq $ver) { continue }

        $packages.Add([pscustomobject]@{
            Url     = $url
            Version = $ver
        })
    }

    $result = $packages.ToArray()
    Write-Verbose ("Discovered OpenSSL ZIP packages: {0}" -f $result.Count)
    return $result
}

function Get-LatestByMajor {
    param([Parameter(Mandatory = $true)][array]$Packages)

    $latest = @{}
    foreach ($pkg in $Packages) {
        $k = [string]$pkg.Version.Major
        if (-not $latest.ContainsKey($k)) {
            $latest[$k] = $pkg
            continue
        }
        if ((Compare-OpenSslVersion -Left $pkg.Version -Right $latest[$k].Version) -gt 0) {
            $latest[$k] = $pkg
        }
    }
    return $latest
}

function Expand-OpenSslZip {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    if (Test-Path -LiteralPath $DestinationPath) {
        Remove-Item -LiteralPath $DestinationPath -Recurse -Force
    }

    New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
    Write-Verbose ("Extracting ZIP: {0} -> {1}" -f $ZipPath, $DestinationPath)
    Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
}

function Test-ZipArchiveReadable {
    param([Parameter(Mandatory = $true)][string]$ZipPath)

    if (-not (Test-Path -LiteralPath $ZipPath)) {
        return $false
    }

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        try {
            $null = $zip.Entries.Count
        }
        finally {
            $zip.Dispose()
        }
        return $true
    }
    catch {
        return $false
    }
}

function Get-ValidLocalZip {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$LocalZip
    )

    if (Test-ZipArchiveReadable -ZipPath $LocalZip) {
        Write-Verbose ("Using cached package: {0}" -f $LocalZip)
        return $LocalZip
    }

    if (Test-Path -LiteralPath $LocalZip) {
        Write-Verbose ("Cached package is invalid/corrupt; removing: {0}" -f $LocalZip)
        Remove-Item -LiteralPath $LocalZip -Force -ErrorAction SilentlyContinue
    }

    $tempZip = "$LocalZip.download"
    if (Test-Path -LiteralPath $tempZip) {
        Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
    }

    Write-Verbose ("Downloading package: {0}" -f $Url)
    Invoke-WebRequest -Uri $Url -OutFile $tempZip -UseBasicParsing -TimeoutSec 180

    if (-not (Test-ZipArchiveReadable -ZipPath $tempZip)) {
        Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
        throw "Downloaded package is not a valid ZIP archive: $Url"
    }

    Move-Item -LiteralPath $tempZip -Destination $LocalZip -Force
    return $LocalZip
}

function Find-ReplacementDll {
    param(
        [Parameter(Mandatory = $true)][string]$ExtractedPath,
        [Parameter(Mandatory = $true)][string]$DllName,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $false)][string]$TargetArchitecture
    )

    $preferredArch = $null
    if (-not [string]::IsNullOrWhiteSpace($TargetArchitecture) -and $TargetArchitecture -ne 'unknown') {
        $preferredArch = $TargetArchitecture
    }
    elseif ($TargetPath -like 'C:\Program Files\*') {
        $preferredArch = 'x64'
    }
    elseif ($TargetPath -like 'C:\Program Files (x86)\*') {
        $preferredArch = 'x86'
    }

    $allMatches = @(Get-ChildItem -Path $ExtractedPath -Filter $DllName -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\(x64|x86|arm64)\\bin\\' })
    if ($allMatches.Count -eq 0) {
        return $null
    }

    if ($preferredArch -eq 'x64') {
        $x64Match = $allMatches | Where-Object { $_.FullName -match '\\x64\\bin\\' } | Select-Object -First 1
        if ($null -ne $x64Match) { return $x64Match.FullName }
        return $null
    }

    if ($preferredArch -eq 'x86') {
        $x86Match = $allMatches | Where-Object { $_.FullName -match '\\x86\\bin\\' } | Select-Object -First 1
        if ($null -ne $x86Match) { return $x86Match.FullName }
        return $null
    }

    if ($preferredArch -eq 'arm64') {
        $arm64Match = $allMatches | Where-Object { $_.FullName -match '\\arm64\\bin\\' } | Select-Object -First 1
        if ($null -ne $arm64Match) { return $arm64Match.FullName }
        return $null
    }

    return ($allMatches | Select-Object -First 1).FullName
}

function Read-Inventory {
    if (-not (Test-Path -LiteralPath $Script:InventoryPath)) {
        throw "Inventory file not found: $Script:InventoryPath. Detection must run first."
    }

    $raw = Get-Content -LiteralPath $Script:InventoryPath -Raw -ErrorAction Stop
    $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $parsed -or $null -eq $parsed.Entries) {
        throw "Inventory file is invalid: $Script:InventoryPath"
    }

    $entries = @($parsed.Entries)
    Write-Verbose ("Loaded inventory entries: {0}" -f $entries.Count)
    return $entries
}

function Test-FileLockState {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            return [pscustomobject]@{ IsLocked = $false; AccessDenied = $false; Message = '' }
        }
        finally {
            $stream.Dispose()
        }
    }
    catch [System.UnauthorizedAccessException] {
        return [pscustomobject]@{ IsLocked = $false; AccessDenied = $true; Message = $_.Exception.Message }
    }
    catch [System.IO.IOException] {
        return [pscustomobject]@{ IsLocked = $true; AccessDenied = $false; Message = $_.Exception.Message }
    }
    catch {
        return [pscustomobject]@{ IsLocked = $false; AccessDenied = $true; Message = $_.Exception.Message }
    }
}

function Update-DllInPlace {
    param(
        [Parameter(Mandatory = $true)]$Entry,
        [Parameter(Mandatory = $true)][string]$ReplacementPath,
        [Parameter(Mandatory = $false)][switch]$DoBackup
    )

    if (-not (Test-Path -LiteralPath $Entry.Path)) {
        throw "Target DLL not found: $($Entry.Path)"
    }

    $currentHash = (Get-FileHash -LiteralPath $Entry.Path -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($currentHash -ne $Entry.SHA256) {
        throw "Hash mismatch for $($Entry.Path). Expected $($Entry.SHA256), found $currentHash."
    }

    $backupPath = "$($Entry.Path).bak"
    if ($DoBackup) {
        Write-Verbose ("Backing up DLL: {0} -> {1}" -f $Entry.Path, $backupPath)
        Copy-Item -LiteralPath $Entry.Path -Destination $backupPath -Force
    }

    try {
        Write-Verbose ("Replacing DLL: {0} <- {1}" -f $Entry.Path, $ReplacementPath)
        Copy-Item -LiteralPath $ReplacementPath -Destination $Entry.Path -Force
    }
    catch {
        if ($DoBackup -and (Test-Path -LiteralPath $backupPath)) {
            Copy-Item -LiteralPath $backupPath -Destination $Entry.Path -Force
        }
        throw
    }
}

function Restore-DllFromBackup {
    param([Parameter(Mandatory = $true)]$Entry)

    if (-not (Test-Path -LiteralPath $Entry.Path)) {
        throw "Target DLL not found for restore: $($Entry.Path)"
    }

    $backupPath = "$($Entry.Path).bak"
    if (-not (Test-Path -LiteralPath $backupPath)) {
        return $false
    }

    Write-Verbose ("Restoring DLL backup: {0} <- {1}" -f $Entry.Path, $backupPath)
    Copy-Item -LiteralPath $backupPath -Destination $Entry.Path -Force
    return $true
}

try {
    Write-Verbose 'Starting OpenSSL remediation run.'
    if ($DryRun) {
        Write-Output 'DryRun mode enabled. No files will be downloaded, extracted, or modified.'
    }

    if ($WithBackup) {
        Write-Output 'WithBackup mode enabled. Backups will be written as <dll>.bak before replacement.'
    }

    if ($RestoreBackup) {
        Write-Output 'RestoreBackup mode enabled. Script will restore DLLs from existing .bak files.'
    }

    if ($WithBackup -and $RestoreBackup) {
        throw 'WithBackup and RestoreBackup cannot be used together in the same run.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $entries = @(Read-Inventory)
    if ($entries.Count -eq 0) {
        Write-Output 'Inventory has no entries. Nothing to remediate.'
        exit 0
    }

    if ($RestoreBackup) {
        $restored = 0
        $missingBackup = New-Object System.Collections.Generic.List[string]

        foreach ($entry in $entries) {
            $backupPath = "$($entry.Path).bak"
            if ($DryRun) {
                if (Test-Path -LiteralPath $backupPath) {
                    Write-Output "DryRun: Would restore $($entry.Path) from $backupPath"
                    $restored++
                }
                else {
                    $missingBackup.Add("Backup missing: $backupPath")
                }
                continue
            }

            if (Restore-DllFromBackup -Entry $entry) {
                Write-Output "Restored: $($entry.Path)"
                $restored++
            }
            else {
                $missingBackup.Add("Backup missing: $backupPath")
            }
        }

        if ($missingBackup.Count -gt 0) {
            Write-Output 'Restore skipped:'
            $missingBackup | ForEach-Object { Write-Output " - $_" }
        }

        if ($DryRun) {
            Write-Output "DryRun restore complete. Planned restores: $restored"
        }
        else {
            Write-Output "RestoreBackup complete. Restored DLL count: $restored"
        }
        exit 0
    }

    $packages = @(Get-WinOpenSslZipPackages)
    if ($packages.Count -eq 0) {
        throw 'No OpenSSL ZIP packages discovered from source feed.'
    }

    $latestByMajor = Get-LatestByMajor -Packages $packages
    Write-Verbose ("Available major branches in package feed: {0}" -f (($latestByMajor.Keys | Sort-Object) -join ', '))

    $downloadDir = Join-Path $Script:WorkRoot 'downloads'
    $extractDir = Join-Path $Script:WorkRoot 'extract'
    if (-not $DryRun) {
        New-Item -Path $downloadDir -ItemType Directory -Force | Out-Null
        New-Item -Path $extractDir -ItemType Directory -Force | Out-Null
    }

    $packageCache = @{}
    $updated = 0
    $planned = 0
    $skipped = New-Object System.Collections.Generic.List[string]

    foreach ($entry in $entries) {
        if (-not (Test-Path -LiteralPath $entry.Path)) {
            $skipped.Add("Missing file: $($entry.Path)")
            continue
        }

        $entryArchitecture = Get-EntryArchitecture -Entry $entry

        $installedVersion = Parse-OpenSslVersion -Text $entry.VersionRaw
        if ($null -eq $installedVersion) {
            $skipped.Add("Unparseable version: $($entry.Path) ($($entry.VersionRaw))")
            continue
        }

        if ($entryArchitecture -eq 'arm64' -and $installedVersion.Major -eq 1) {
            $skipped.Add("No ARM64 replacement exists for OpenSSL 1.x: $($entry.Path)")
            continue
        }

        $majorKey = [string]$installedVersion.Major
        if (-not $latestByMajor.ContainsKey($majorKey)) {
            $skipped.Add("No package source for major $($majorKey): $($entry.Path)")
            continue
        }

        $pkg = $latestByMajor[$majorKey]
        if ((Compare-OpenSslVersion -Left $installedVersion -Right $pkg.Version) -ge 0) {
            continue
        }

        if ($DryRun) {
            if (-not $packageCache.ContainsKey($majorKey)) {
                $fileName = [IO.Path]::GetFileName(([uri]$pkg.Url).AbsolutePath)
                $localZip = Join-Path $downloadDir $fileName
                $extractPath = Join-Path $extractDir ("{0}_{1}" -f $pkg.Version.Major, $pkg.Version.Raw)

                if (Test-Path -LiteralPath $localZip) {
                    Write-Output "DryRun: Would use cached package $localZip"
                }
                else {
                    Write-Output "DryRun: Would download package $($pkg.Url) to $localZip"
                }

                if (Test-Path -LiteralPath $extractPath) {
                    Write-Output "DryRun: Would use existing extracted content at $extractPath"
                }
                else {
                    Write-Output "DryRun: Would extract package to $extractPath"
                }

                $packageCache[$majorKey] = $true
            }

            Write-Output ("DryRun: Would update {0} ({1} -> {2})" -f $entry.Path, $installedVersion.Raw, $pkg.Version.Raw)
            $planned++
            continue
        }

        if (-not $packageCache.ContainsKey($majorKey)) {
            $fileName = [IO.Path]::GetFileName(([uri]$pkg.Url).AbsolutePath)
            $localZip = Join-Path $downloadDir $fileName
            $localZip = Get-ValidLocalZip -Url $pkg.Url -LocalZip $localZip

            $extractPath = Join-Path $extractDir ("{0}_{1}" -f $pkg.Version.Major, $pkg.Version.Raw)
            Expand-OpenSslZip -ZipPath $localZip -DestinationPath $extractPath

            $packageCache[$majorKey] = [pscustomobject]@{
                ExtractPath = $extractPath
                Version     = $pkg.Version
            }
        }

        $replacement = Find-ReplacementDll -ExtractedPath $packageCache[$majorKey].ExtractPath -DllName $entry.Name -TargetPath $entry.Path -TargetArchitecture $entryArchitecture
        if ([string]::IsNullOrWhiteSpace($replacement)) {
            $skipped.Add("Replacement DLL not found for $($entry.Path)")
            continue
        }

        $targetLock = Test-FileLockState -Path $entry.Path
        if ($targetLock.IsLocked) {
            $skipped.Add("Locked/in-use file (skipped): $($entry.Path)")
            continue
        }
        if ($targetLock.AccessDenied) {
            $skipped.Add("Access denied (skipped): $($entry.Path)")
            continue
        }

        if ($WithBackup) {
            $backupPath = "$($entry.Path).bak"
            if (Test-Path -LiteralPath $backupPath) {
                $backupLock = Test-FileLockState -Path $backupPath
                if ($backupLock.IsLocked) {
                    $skipped.Add("Backup file locked/in-use (skipped): $backupPath")
                    continue
                }
                if ($backupLock.AccessDenied) {
                    $skipped.Add("Backup file access denied (skipped): $backupPath")
                    continue
                }
            }
        }

        try {
            Update-DllInPlace -Entry $entry -ReplacementPath $replacement -DoBackup:$WithBackup
            $updated++
            Write-Output "Updated: $($entry.Path) -> $($packageCache[$majorKey].Version.Raw)"
        }
        catch [System.IO.IOException] {
            $skipped.Add("I/O error during update (likely in use): $($entry.Path) [$($_.Exception.Message)]")
            continue
        }
        catch [System.UnauthorizedAccessException] {
            $skipped.Add("Access denied during update: $($entry.Path) [$($_.Exception.Message)]")
            continue
        }
    }

    if ($skipped.Count -gt 0) {
        Write-Output 'Skipped:'
        $skipped | ForEach-Object { Write-Output " - $_" }
    }

    if ($DryRun) {
        Write-Output "DryRun complete. Planned DLL updates: $planned"
        exit 0
    }

    Write-Output "Remediation complete. Updated DLL count: $updated"
    exit 0
}
catch {
    Write-Output "Remediation error: $($_.Exception.Message)"
    exit 1
}