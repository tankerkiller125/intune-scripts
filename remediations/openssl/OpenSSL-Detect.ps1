<#
.SYNOPSIS
Intune detection script for outdated OpenSSL DLLs.

.DESCRIPTION
Scans selected writable C: paths for OpenSSL DLLs, creates an inventory file in
ProgramData with path/hash/version details, and determines compliance by
comparing discovered DLL versions with latest available ZIP-package versions in
the same major line.

Exit codes:
  0 = compliant
  1 = remediation required or detection failure
#>

[CmdletBinding()]
param(
    [switch]$VerboseMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($VerboseMode) { $VerbosePreference = 'Continue' }

$Script:InventoryRoot = Join-Path $env:ProgramData 'IntuneOpenSSLRemediation'
$Script:InventoryPath = Join-Path $Script:InventoryRoot 'openssl-dll-inventory.json'

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

function Get-OpenSslDllVersion {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $candidates = @(
            $item.VersionInfo.ProductVersion,
            $item.VersionInfo.FileVersion,
            $item.VersionInfo.FileDescription
        )

        foreach ($c in $candidates) {
            $parsed = Parse-OpenSslVersion -Text $c
            if ($null -ne $parsed) {
                return $parsed
            }
        }
    }
    catch {
        return $null
    }

    return $null
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

function Get-ScanRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    $candidates = @(
        #'C:\Users',
        'C:\Program Files',
        'C:\Program Files (x86)',
        'C:\ProgramData'
    )

    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) {
            $roots.Add($path)
        }
    }

    $result = $roots.ToArray()
    Write-Verbose ("Scan roots: {0}" -f ($result -join ', '))
    return $result
}

function Get-OpenSslDllInventory {
    $patterns = @('libcrypto*.dll', 'libssl*.dll', 'libeay32.dll', 'ssleay32.dll')
    $roots = Get-ScanRoots
    $found = New-Object System.Collections.Generic.List[object]

    foreach ($root in $roots) {
        Write-Verbose "Scanning root: $root"
        $dlls = Get-ChildItem -Path $root -Include $patterns -File -Recurse -ErrorAction SilentlyContinue
        Write-Verbose ("Candidate DLL files in {0}: {1}" -f $root, @($dlls).Count)
        foreach ($dll in $dlls) {
            $version = Get-OpenSslDllVersion -Path $dll.FullName
            if ($null -eq $version) { continue }

            $hash = $null
            try {
                $hash = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            }
            catch {
                continue
            }

            $found.Add([pscustomobject]@{
                Path         = $dll.FullName
                Name         = $dll.Name
                Architecture = Get-PortableExecutableArchitecture -Path $dll.FullName
                SHA256       = $hash
                VersionRaw   = $version.Raw
                VersionMajor = $version.Major
                VersionMinor = $version.Minor
                VersionPatch = $version.Patch
                VersionLetter= $version.Letter
                Version      = $version
            })

            Write-Verbose ("Detected OpenSSL DLL: {0} [{1}] [{2}]" -f $dll.FullName, $version.Raw, $found[$found.Count - 1].Architecture)
        }
    }

    $result = $found.ToArray()
    Write-Verbose ("Total detected OpenSSL DLLs: {0}" -f $result.Count)
    return $result
}

function Write-InventoryFile {
    param([Parameter(Mandatory = $true)][array]$Inventory)

    if (-not (Test-Path -LiteralPath $Script:InventoryRoot)) {
        New-Item -Path $Script:InventoryRoot -ItemType Directory -Force | Out-Null
    }

    $payload = [pscustomobject]@{
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
        ScanRoots    = Get-ScanRoots
        Entries      = @($Inventory | ForEach-Object {
            [pscustomobject]@{
                Path          = $_.Path
                Name          = $_.Name
                Architecture  = $_.Architecture
                SHA256        = $_.SHA256
                VersionRaw    = $_.VersionRaw
                VersionMajor  = $_.VersionMajor
                VersionMinor  = $_.VersionMinor
                VersionPatch  = $_.VersionPatch
                VersionLetter = $_.VersionLetter
            }
        })
    }

    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Script:InventoryPath -Encoding UTF8
    Write-Verbose "Inventory file written: $Script:InventoryPath"
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

try {
    Write-Verbose 'Starting OpenSSL detection run.'
    $inventory = @(Get-OpenSslDllInventory)
    Write-InventoryFile -Inventory $inventory

    if ($inventory.Count -eq 0) {
        Write-Output "No OpenSSL DLLs found in scoped paths. Compliant. Inventory: $Script:InventoryPath"
        exit 0
    }

    $packages = @(Get-WinOpenSslZipPackages)
    if ($packages.Count -eq 0) {
        Write-Output 'Detection error: no OpenSSL ZIP packages discovered from source feed.'
        exit 1
    }

    $latestByMajor = Get-LatestByMajor -Packages $packages
    Write-Verbose ("Available major branches in package feed: {0}" -f (($latestByMajor.Keys | Sort-Object) -join ', '))

    $nonCompliant = New-Object System.Collections.Generic.List[string]
    foreach ($dll in $inventory) {
        if ($dll.Architecture -eq 'arm64' -and $dll.VersionMajor -eq 1) {
            $nonCompliant.Add("$($dll.Path) (OpenSSL 1.x has no ARM64 build source)")
            continue
        }

        $majorKey = [string]$dll.VersionMajor
        if (-not $latestByMajor.ContainsKey($majorKey)) {
            $nonCompliant.Add("$($dll.Path) (major $majorKey has no package source)")
            continue
        }

        $target = $latestByMajor[$majorKey].Version
        if ((Compare-OpenSslVersion -Left $dll.Version -Right $target) -lt 0) {
            $nonCompliant.Add("$($dll.Path) ($($dll.Version.Raw) < $($target.Raw))")
        }
    }

    if ($nonCompliant.Count -gt 0) {
        Write-Verbose ("Non-compliant DLL count: {0}" -f $nonCompliant.Count)
        Write-Output "OpenSSL remediation required. Inventory: $Script:InventoryPath"
        $nonCompliant | ForEach-Object { Write-Output " - $_" }
        exit 1
    }

    Write-Verbose 'All detected DLLs compliant.'
    Write-Output "All discovered OpenSSL DLLs are at latest available minor/patch level. Inventory: $Script:InventoryPath"
    exit 0
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    if ($VerboseMode) {
        if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
            Write-Output $_.InvocationInfo.PositionMessage
        }
        if ($_.ScriptStackTrace) {
            Write-Output $_.ScriptStackTrace
        }
    }
    exit 1
}
