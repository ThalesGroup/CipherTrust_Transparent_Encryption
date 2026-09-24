param(
    [string]$LogFilePath = "C:\ProgramData\Vormetric\DataSecurityExpert\agent\log",
    [switch]$SingleFile,
    [Alias('r')]
    [switch]$SkipResourceSets
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-UniqueName {
    <#
    .SYNOPSIS
    Generates a unique process set name with format: RansomwareProcessSet_YYYYMMDD_HHMMSS_RANDOMID
    #>
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $randomId = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    return "RansomwareProcessSet_${timestamp}_${randomId}"
}

function Get-UniqueResourceSetName {
    <#
    .SYNOPSIS
    Generates a unique resource set name with format: ResourceSet_YYYYMMDD_HHMMSS_RANDOMID
    #>
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $randomId = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    return "ResourceSet_${timestamp}_${randomId}"
}

function Split-ProcessPath {
    <#
    .SYNOPSIS
    Splits a process path into directory and filename components.
    
    .PARAMETER Path
    The full process path to split.
    
    .OUTPUTS
    Hashtable with "directory" and "file" keys.
    #>
    param([string]$Path)
    
    # Normalize path: convert double backslashes to single
    $Path = $Path -replace '\\\\', '\'
    
    $lastBackslash = $Path.LastIndexOf('\')
    
    if ($lastBackslash -eq -1) {
        # No backslash found
        return @{
            "directory" = ""
            "file"      = $Path
        }
    }
    else {
        # Include the backslash in the directory
        $directory = $Path.Substring(0, $lastBackslash + 1)
        $file = $Path.Substring($lastBackslash + 1)
        return @{
            "directory" = $directory
            "file"      = $file
        }
    }
}

function Split-ResourcePath {
    <#
    .SYNOPSIS
    Splits a resource path into directory and filename components.
    
    .PARAMETER Path
    The full resource path to split.
    
    .OUTPUTS
    Hashtable with "directory" and "file" keys.
    #>
    param([string]$Path)
    
    # Normalize path: convert double backslashes to single
    $Path = $Path -replace '\\\\', '\'
    
    $lastBackslash = $Path.LastIndexOf('\')
    
    if ($lastBackslash -eq -1) {
        # No backslash found
        return @{
            "directory" = ""
            "file"      = $Path
        }
    }
    else {
        # Include the backslash in the directory
        $directory = $Path.Substring(0, $lastBackslash + 1)
        $file = $Path.Substring($lastBackslash + 1)
        return @{
            "directory" = $directory
            "file"      = $file
        }
    }
}

function Get-AlternateProcessPaths {
    <#
    .SYNOPSIS
    Generates alternate paths for C:\Windows ↔ \SystemRoot\, C:\@Windows ↔ \SystemRoot\,
    and \Device\HarddiskVolumeN\ ↔ drive letter variations.
    
    .PARAMETER Directory
    The directory component of the path.
    
    .PARAMETER File
    The filename component of the path.
    
    .OUTPUTS
    Array of hashtables with "directory" and "file" keys, or empty array if no alternates apply.
    #>
    param(
        [string]$Directory,
        [string]$File
    )
    
    $alternates = @()
    
    # Rule 1: If directory contains C:\Windows, generate alternate with \SystemRoot\
    if ($Directory -like "*C:\Windows*") {
        $altDir = $Directory -replace "C:\\Windows", "\SystemRoot"
        $alternates += @{
            "directory" = $altDir
            "file"      = $File
        }
    }
    
    # Rule 2: If directory contains C:\@Windows, generate alternate with \SystemRoot\
    if ($Directory -like "*C:\@Windows*") {
        $altDir = $Directory -replace "C:\\@Windows", "\SystemRoot"
        $alternates += @{
            "directory" = $altDir
            "file"      = $File
        }
    }
    
    # Rule 3: If directory contains \SystemRoot\ but NOT C:\Windows\, generate alternate with C:\Windows\
    if ($Directory -like "*\SystemRoot\*" -and $Directory -notlike "*C:\Windows*") {
        $altDir = $Directory -replace "\\SystemRoot\\", "C:\Windows\"
        $alternates += @{
            "directory" = $altDir
            "file"      = $File
        }
    }
    
    # Rule 4: If directory starts with \Device\HarddiskVolumeN\, generate alternate with C:\
    # The RWPML:DEP logs use device paths like \Device\HarddiskVolume2\ which map to C:\ typically
    if ($Directory -match '^\\Device\\HarddiskVolume\d+\\') {
        $altDir = $Directory -replace '^\\Device\\HarddiskVolume\d+\\', 'C:\'
        $alternates += @{
            "directory" = $altDir
            "file"      = $File
        }
        
        # After converting device path to C:\, check if the result contains C:\Windows
        # and generate a \SystemRoot\ alternate as well (Rule 1 applied to the converted path)
        if ($altDir -like "*C:\Windows*") {
            $sysRootDir = $altDir -replace "C:\\Windows", "\SystemRoot"
            $alternates += @{
                "directory" = $sysRootDir
                "file"      = $File
            }
        }
    }
    
    # Rule 5: If directory starts with a drive letter (e.g., C:\) and is NOT a device path,
    # generate alternate with \Device\HarddiskVolume2\ (common default)
    # This is skipped to avoid guessing volume numbers — device paths are only added as alternates
    # when the original path IS a device path (Rule 4 above).
    
    return $alternates
}

function Convert-DatedPathToWildcard {
    <#
    .SYNOPSIS
    Replaces subdirectories that look like dates or long numbers with a wildcard (*).
    This handles Symantec-style upgrade paths where subdirectories are named with
    dates/timestamps (e.g., 20260417.001, 2026-04-17_120000, 14.3.0.1049, etc.)
    
    .PARAMETER Directory
    The directory path to process.
    
    .OUTPUTS
    The directory path with date/number subdirectories replaced by *.
    #>
    param([string]$Directory)
    
    # Split the directory into parts by backslash
    $parts = $Directory -split '\\'
    $newParts = @()
    
    foreach ($part in $parts) {
        if ([string]::IsNullOrEmpty($part)) {
            $newParts += $part
            continue
        }
        
        # Match patterns that look like dates, timestamps, or long version numbers:
        # - Pure digits of 4+ chars: 20260417, 1234567890
        # - Date-like: 2026-04-17, 20260417, 2026.04.17
        # - Timestamp-like: 20260417_120000, 2026-04-17_12-00-00
        # - Version-like with 3+ segments: 14.3.0.1049, 1.2.3.4
        # - Date with extensions: 20260417.001, 20260417.003
        # - Mixed date-number: 041726_1200
        $isDateOrNumber = $false
        
        # Pattern 1: Pure digits, 4+ characters (e.g., 20260417, 1234567890)
        if ($part -match '^\d{4,}$') {
            $isDateOrNumber = $true
        }
        # Pattern 2: Digits separated by dots/dashes/underscores, total 6+ chars (e.g., 2026-04-17, 14.3.0.1049, 20260417.001)
        elseif ($part -match '^[\d][\d.\-_]+[\d]$' -and $part.Length -ge 6) {
            $isDateOrNumber = $true
        }
        # Pattern 3: Digits and separators with at least 3 numeric segments (e.g., 14.3.0.1049)
        elseif ($part -match '^\d+([.\-_]\d+){2,}') {
            $isDateOrNumber = $true
        }
        
        if ($isDateOrNumber) {
            $newParts += '*'
        }
        else {
            $newParts += $part
        }
    }
    
    return $newParts -join '\'
}

function Convert-ResourceDirAtDatedSubdir {
    <#
    .SYNOPSIS
    For resource set directories: truncates the path at the first subdirectory that looks
    like a date, version number, or long numeric string. Everything from that point onward
    is removed, and include_subfolders should be set to true.
    
    Example:
      C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\14.3.7388.4000.105\BIN\
      → C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\
    
    .PARAMETER Directory
    The resource directory path to process.
    
    .OUTPUTS
    The truncated directory path.
    #>
    param([string]$Directory)
    
    # Split the directory into parts by backslash
    $parts = $Directory -split '\\'
    $newParts = @()
    
    foreach ($part in $parts) {
        if ([string]::IsNullOrEmpty($part)) {
            $newParts += $part
            continue
        }
        
        $isDateOrNumber = $false
        
        # Pattern 1: Pure digits, 4+ characters (e.g., 20260417, 1234567890)
        if ($part -match '^\d{4,}$') {
            $isDateOrNumber = $true
        }
        # Pattern 2: Digits separated by dots/dashes/underscores, total 6+ chars (e.g., 2026-04-17, 14.3.0.1049, 20260417.001)
        elseif ($part -match '^[\d][\d.\-_]+[\d]$' -and $part.Length -ge 6) {
            $isDateOrNumber = $true
        }
        # Pattern 3: Digits and separators with at least 3 numeric segments (e.g., 14.3.7388.4000.105)
        elseif ($part -match '^\d+([.\-_]\d+){2,}') {
            $isDateOrNumber = $true
        }
        
        if ($isDateOrNumber) {
            # Stop here — truncate everything from this point onward
            break
        }
        else {
            $newParts += $part
        }
    }
    
    # Rejoin and ensure trailing backslash
    $result = $newParts -join '\'
    if (-not $result.EndsWith('\')) {
        $result += '\'
    }
    return $result
}

function Get-ProcessGroupKey {
    <#
    .SYNOPSIS
    Normalizes the directory by converting C:\Windows, C:\@Windows, \SystemRoot\,
    and \Device\HarddiskVolumeN\ to common keys for deduplication and matching.
    
    .PARAMETER Directory
    The directory component of the path.
    
    .PARAMETER File
    The filename component of the path.
    
    .OUTPUTS
    String key in format "NORMALIZEDDIR|FILE"
    #>
    param(
        [string]$Directory,
        [string]$File
    )
    
    # Normalize \Device\HarddiskVolumeN\ to C:\ before other normalizations
    # This ensures RWPML:DEP log paths match voradmin paths for resource set linking
    $normalizedDir = $Directory -replace '\\Device\\HarddiskVolume\d+\\', 'C:\'
    
    # Normalize all Windows root variations to a common key
    $normalizedDir = $normalizedDir -replace "C:\\Windows", "WINDOWS_ROOT" `
                                    -replace "C:\\@Windows", "WINDOWS_ROOT" `
                                    -replace "\\SystemRoot\\", "WINDOWS_ROOT"
    
    return "${normalizedDir}|${File}"
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

# Resolve the log file path
$resolvedPath = $LogFilePath
if (-not [System.IO.Path]::IsPathRooted($LogFilePath)) {
    $resolvedPath = Join-Path -Path (Get-Location) -ChildPath $LogFilePath
}

# Determine if path is a file or directory
$isDirectory = $false
$logFiles = @()

if (Test-Path -Path $resolvedPath -PathType Container) {
    $isDirectory = $true
    $logDir = $resolvedPath
}
elseif (Test-Path -Path $resolvedPath -PathType Leaf) {
    $isDirectory = $false
    $logDir = Split-Path -Parent $resolvedPath
    $logFiles = @($resolvedPath)
}
else {
    # Path doesn't exist - check if it's meant to be a directory
    if ($resolvedPath -like "*\*" -and -not $resolvedPath.EndsWith(".log")) {
        # Looks like a directory path
        Write-Error "Log directory not found at: $resolvedPath"
        exit 1
    }
    else {
        # Looks like a file path
        Write-Error "Log file not found at: $resolvedPath"
        exit 1
    }
}

# If directory was provided, find log files
if ($isDirectory) {
    if (-not (Test-Path -Path $logDir -PathType Container)) {
        Write-Error "Log directory not found at: $logDir"
        exit 1
    }
    
    if ($SingleFile) {
        # Look for vorvmd.log in the directory
        $defaultLogFile = Join-Path -Path $logDir -ChildPath "vorvmd.log"
        if (Test-Path -Path $defaultLogFile -PathType Leaf) {
            $logFiles = @($defaultLogFile)
        }
        else {
            Write-Error "Log file not found at: $defaultLogFile"
            exit 1
        }
    }
    else {
        # Find all vorvmd.log* files and sort in descending order by name
        $logFiles = @(Get-ChildItem -Path $logDir -Filter "vorvmd.log*" -File | Sort-Object -Property Name -Descending | Select-Object -ExpandProperty FullName)
    }
}

# Read all log files
$logContent = ""
foreach ($logFile in $logFiles) {
    if (Test-Path -Path $logFile -PathType Leaf) {
        $logContent += (Get-Content -Path $logFile -Raw)
    }
}

if ([string]::IsNullOrEmpty($logContent)) {
    # No log content found, output empty process set
    $processSetName = Get-UniqueName
    $emptyProcessSet = @{
        "name"        = $processSetName
        "description" = ""
        "processes"   = @()
    }
    Write-Host ($emptyProcessSet | ConvertTo-Json -Depth 10)
    exit 0
}

# ============================================================================
# EXTRACT PROCESSES
# ============================================================================

# Pattern 1: "Potential Ransomware activity" logs — extracts process from "Process name:" field
$processPattern = "(?=.*Potential Ransomware activity).*?Process name:\s*([^\n]+?)(?:\.\s|,)"
$processMatches = [regex]::Matches($logContent, $processPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)

# Pattern 2: "RWPML:DEP" logs — extracts process from "Process <path> with pid" field
# Example: EVENT: RWPML:DEP: Alert: Process \\Device\\HarddiskVolume2\\...\\wordpad.exe with pid 9888 crossed history read limit
# Note: process paths may contain spaces (e.g., "Program Files"), so we match everything up to " with pid"
$depPattern = "RWPML:DEP:.*?Process\s+(.+?)\s+with\s+pid"
$depMatches = [regex]::Matches($logContent, $depPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)

$processesDict = @{}  # Key: normalized group key, Value: @{ "directory": ..., "file": ..., "alternates": [...] }
$processOrder = @()   # Track order of first appearance

# Helper function to add a process path to the dictionary with deduplication and alternate generation
function Add-ProcessToDict {
    param([string]$ProcessPath)
    
    # Normalize path: convert double backslashes to single
    $ProcessPath = $ProcessPath -replace '\\\\', '\'
    
    # Split the path
    $pathParts = Split-ProcessPath -Path $ProcessPath
    $directory = $pathParts["directory"]
    $file = $pathParts["file"]
    
    # Replace date/number subdirectories with wildcard (for Symantec-style paths)
    $directory = Convert-DatedPathToWildcard -Directory $directory
    
    # Get the group key for deduplication
    $groupKey = Get-ProcessGroupKey -Directory $directory -File $file
    
    if (-not $script:processesDict.ContainsKey($groupKey)) {
        $script:processesDict[$groupKey] = @{
            "directory"  = $directory
            "file"       = $file
            "alternates" = @()
        }
        $script:processOrder += $groupKey
    }
    
    # Generate alternate paths
    $alternates = Get-AlternateProcessPaths -Directory $directory -File $file
    foreach ($alt in $alternates) {
        # Skip if this alternate matches the primary entry itself
        $primaryEntry = $script:processesDict[$groupKey]
        if ($alt["directory"] -eq $primaryEntry["directory"] -and $alt["file"] -eq $primaryEntry["file"]) {
            continue
        }
        
        # Check if this alternate is already in the alternates list
        $altExists = $script:processesDict[$groupKey]["alternates"] | Where-Object { 
            $_.directory -eq $alt["directory"] -and $_.file -eq $alt["file"]
        }
        
        if (-not $altExists) {
            $script:processesDict[$groupKey]["alternates"] += $alt
        }
    }
}

# Process Pattern 1 matches: "Potential Ransomware activity" logs
foreach ($match in $processMatches) {
    $processPath = $match.Groups[1].Value.Trim()
    Add-ProcessToDict -ProcessPath $processPath
}

# Process Pattern 2 matches: "RWPML:DEP" logs
foreach ($match in $depMatches) {
    $processPath = $match.Groups[1].Value.Trim()
    Add-ProcessToDict -ProcessPath $processPath
}

# ============================================================================
# EXTRACT RESOURCES (from voradmin rwp detection-status get)
# ============================================================================

$processResourceMap = @{}  # Key: normalized group key, Value: @{ "resources": [...] }
$seenResources = @{}       # Track seen resources to avoid duplicates per process group

if (-not $SkipResourceSets) {
    # Run voradmin command to get detection status
    try {
        $voradminOutput = & voradmin rwp detection-status get 2>&1
        $voradminText = $voradminOutput -join "`n"
    }
    catch {
        Write-Warning "Failed to run 'voradmin rwp detection-status get': $_"
        $voradminText = ""
    }
    
    if (-not [string]::IsNullOrWhiteSpace($voradminText)) {
        # Parse voradmin output into detection entries
        # Each entry has fields like: id, event, process, guardPath, lastFile, sign, user, nRead, nThreshold
        # Supported event types:
        #   - ransomwareDetected          (from "Potential Ransomware activity" logs)
        #   - dataStealingPreventionReadLimitHit (from "RWPML:DEP" logs)
        # Entries are separated by blank lines or by the start of a new "id:" line
        
        $detectionEntries = @()
        $currentEntry = @{}
        
        foreach ($line in ($voradminText -split "`n")) {
            $line = $line.Trim()
            
            if ([string]::IsNullOrWhiteSpace($line)) {
                # Blank line — save current entry if it has data
                if ($currentEntry.Count -gt 0) {
                    $detectionEntries += $currentEntry
                    $currentEntry = @{}
                }
                continue
            }
            
            # Parse "key: value" lines
            if ($line -match '^(\w+):\s*(.*)$') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                
                # If we encounter a new "id" and already have data, save previous entry
                if ($key -eq "id" -and $currentEntry.Count -gt 0) {
                    $detectionEntries += $currentEntry
                    $currentEntry = @{}
                }
                
                $currentEntry[$key] = $value
            }
        }
        
        # Don't forget the last entry
        if ($currentEntry.Count -gt 0) {
            $detectionEntries += $currentEntry
        }
        
        # Process each detection entry and match to process set
        foreach ($entry in $detectionEntries) {
            $detProcess = $entry["process"]
            $guardPath = $entry["guardPath"]
            $lastFile = $entry["lastFile"]
            
            if ([string]::IsNullOrWhiteSpace($detProcess) -or [string]::IsNullOrWhiteSpace($guardPath) -or [string]::IsNullOrWhiteSpace($lastFile)) {
                continue
            }
            
            # Normalize the detection process path
            $detProcess = $detProcess -replace '\\\\', '\'
            $pathParts = Split-ProcessPath -Path $detProcess
            $detDirectory = $pathParts["directory"]
            $detFile = $pathParts["file"]
            
            # Apply wildcard conversion (must match process extraction processing)
            $detDirectory = Convert-DatedPathToWildcard -Directory $detDirectory
            
            $detGroupKey = Get-ProcessGroupKey -Directory $detDirectory -File $detFile
            
            # Check if this process exists in our process set
            if (-not $processesDict.ContainsKey($detGroupKey)) {
                continue
            }
            
            # Build the full resource path: guardPath + lastFile
            # guardPath is like "E:" and lastFile is like "TestFiles - Copy\testfile_40MB.txt_0001.txt"
            $fullResourcePath = $guardPath.TrimEnd('\') + '\' + $lastFile.TrimStart('\')
            
            # Split to get directory (guardPath + lastFile's directory part) and file = *
            $resourceParts = Split-ResourcePath -Path $fullResourcePath
            $resDirectory = $resourceParts["directory"]
            
            # Apply dated-path truncation for resource directories
            # e.g., C:\Program Files (x86)\Symantec\...\14.3.7388.4000.105\BIN\ → C:\Program Files (x86)\Symantec\...\
            $resDirectory = Convert-ResourceDirAtDatedSubdir -Directory $resDirectory
            
            # Initialize if needed
            if (-not $processResourceMap.ContainsKey($detGroupKey)) {
                $processResourceMap[$detGroupKey] = @{
                    "resources" = @()
                }
            }
            
            # Create resource object with file = * (wildcard) and include_subfolders = true
            $resourceObj = @{
                "directory"          = $resDirectory
                "file"               = "*"
                "include_subfolders" = $true
            }
            
            # Check for duplicates (per process group, by directory since file is always *)
            $resourceKey = "${detGroupKey}||${resDirectory}"
            if (-not $seenResources.ContainsKey($resourceKey)) {
                $processResourceMap[$detGroupKey]["resources"] += $resourceObj
                $seenResources[$resourceKey] = $true
            }
        }
    }
}

# ============================================================================
# GENERATE UNIQUE NAMES AND BUILD OUTPUT
# ============================================================================

$processSetName = Get-UniqueName

# Pre-generate a unique resource set name for each process group that has resources
$processGroupKeyToResourceSetId = @{}

if (-not $SkipResourceSets) {
    foreach ($groupKey in $processOrder) {
        $hasResources = $processResourceMap.ContainsKey($groupKey) -and $processResourceMap[$groupKey]["resources"].Count -gt 0
        if ($hasResources) {
            $processGroupKeyToResourceSetId[$groupKey] = Get-UniqueResourceSetName
        }
    }
}

# Build process set
$processArray = @()

foreach ($groupKey in $processOrder) {
    $processInfo = $processesDict[$groupKey]
    
    # Determine if this process has a resource set
    $hasResources = $processGroupKeyToResourceSetId.ContainsKey($groupKey)
    
    # Create process object
    $processObj = @{
        "directory" = $processInfo["directory"]
        "file"      = $processInfo["file"]
    }
    
    if ($hasResources) {
        $processObj["resource_set_id"] = $processGroupKeyToResourceSetId[$groupKey]
    }
    
    $processArray += $processObj
    
    # Add alternates
    foreach ($alt in $processInfo["alternates"]) {
        $altObj = @{
            "directory" = $alt["directory"]
            "file"      = $alt["file"]
        }
        
        if ($hasResources) {
            $altObj["resource_set_id"] = $processGroupKeyToResourceSetId[$groupKey]
        }
        
        $processArray += $altObj
    }
}

# Build process set JSON
$processSet = @{
    "name"        = $processSetName
    "description" = ""
    "processes"   = $processArray
}

# Output process set
Write-Host ($processSet | ConvertTo-Json -Depth 10)
Write-Host ""

# Output resource sets (only when -r / -SkipResourceSets is NOT specified)
if (-not $SkipResourceSets) {
    foreach ($groupKey in $processOrder) {
        if ($processResourceMap.ContainsKey($groupKey) -and $processResourceMap[$groupKey]["resources"].Count -gt 0) {
            $resourceSet = @{
                "name"        = $processGroupKeyToResourceSetId[$groupKey]
                "description" = ""
                "type"        = "Directory"
                "resources"   = $processResourceMap[$groupKey]["resources"]
            }
            
            Write-Host ($resourceSet | ConvertTo-Json -Depth 10)
        }
    }
}
