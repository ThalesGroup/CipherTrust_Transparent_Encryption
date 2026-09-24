# Ransomware Process Set Generator

## Overview

`Generate-RansomwareProcessSet.ps1` is a PowerShell script that parses Vormetric DataSecurityExpert agent logs (`vorvmd.log`) to extract processes flagged for ransomware or data-exfiltration activity. It produces structured JSON output describing **process sets** and, optionally, **resource sets** that can be consumed by downstream policy-management tooling.

The script correlates two independent data sources:

1. **Log files** — scanned for ransomware and data-stealing-prevention alerts.
2. **`voradmin` live detection status** — queried at runtime to map each flagged process to the guarded resources it touched.

---

## Features

| Category | Details |
|---|---|
| **Dual log-pattern extraction** | Parses both *"Potential Ransomware activity"* entries and *"RWPML:DEP"* (Data Exfiltration Prevention) entries from Vormetric logs. |
| **Resource set generation** | Correlates processes with guarded paths via `voradmin rwp detection-status get` to produce per-process resource sets. |
| **Alternate path generation** | Automatically generates equivalent path variants (`C:\Windows` ↔ `\SystemRoot\`, `\Device\HarddiskVolumeN\` → `C:\`, and combinations). |
| **Dated-path wildcard conversion** | Replaces version/date-stamped subdirectories (e.g., `14.3.7388.4000.105`) with `*` wildcards so rules survive software upgrades. |
| **Cross-source deduplication** | Normalises `C:\Windows`, `C:\@Windows`, `\SystemRoot\`, and `\Device\HarddiskVolumeN\` paths to a common key so the same process is never listed twice. |
| **Multi-file log scanning** | By default reads every `vorvmd.log*` file in the log directory (current + archived logs). |
| **Unique naming** | Every execution produces a unique process-set and resource-set name using a `YYYYMMDD_HHMMSS_<random>` scheme. |
| **JSON output** | All output is valid JSON, ready for piping or redirection. |

---

## Requirements

- **PowerShell 3.0** or higher.
- **Read access** to the Vormetric log directory (default: `C:\ProgramData\Vormetric\DataSecurityExpert\agent\log`).
- **`voradmin`** must be available on `$env:PATH` (required only when resource-set generation is enabled — i.e., when `-SkipResourceSets` is *not* specified).

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `LogFilePath` | `String` | `C:\ProgramData\Vormetric\DataSecurityExpert\agent\log` | Path to a **directory** containing `vorvmd.log*` files, or a path to a **single log file**. When a directory is given the script locates all matching log files automatically. |
| `SingleFile` | `Switch` | `$false` | When set, only the single file `vorvmd.log` inside the specified directory is processed instead of all `vorvmd.log*` files. |
| `SkipResourceSets` (`-r`) | `Switch` | `$false` | When set, the script skips the `voradmin` call and omits resource-set output entirely. Useful when `voradmin` is unavailable or resource mapping is not needed. |

---

## Usage

### Default — scan all logs, include resource sets

```powershell
powershell -ExecutionPolicy Bypass -File "Generate-RansomwareProcessSet.ps1"
```

Scans every `vorvmd.log*` file in the default Vormetric log directory and queries `voradmin` for resource mapping.

### Scan a custom directory

```powershell
# Pass a directory path
powershell -ExecutionPolicy Bypass -File "Generate-RansomwareProcessSet.ps1" -LogFilePath "D:\Logs\Vormetric"

# Or pass a file path — the script resolves the parent directory automatically
powershell -ExecutionPolicy Bypass -File "Generate-RansomwareProcessSet.ps1" -LogFilePath "D:\Logs\Vormetric\vorvmd.log"
```

### Scan only the current (non-archived) log

```powershell
powershell -ExecutionPolicy Bypass -File "Generate-RansomwareProcessSet.ps1" -SingleFile
```

### Skip resource-set generation

```powershell
powershell -ExecutionPolicy Bypass -File "Generate-RansomwareProcessSet.ps1" -r
# or
powershell -ExecutionPolicy Bypass -File "Generate-RansomwareProcessSet.ps1" -SkipResourceSets
```

### Combine options

```powershell
powershell -ExecutionPolicy Bypass -File "Generate-RansomwareProcessSet.ps1" `
    -LogFilePath "D:\Logs" -SingleFile -SkipResourceSets
```

---

## Output Format

The script writes one or more JSON objects to **stdout**.

### 1. Process Set (always emitted)

```json
{
    "name": "RansomwareProcessSet_20260917_083012_kGf1AuXy",
    "description": "",
    "processes": [
        {
            "directory": "C:\\Windows\\System32\\",
            "file": "notepad.exe"
        },
        {
            "directory": "\\SystemRoot\\System32\\",
            "file": "notepad.exe"
        },
        {
            "directory": "C:\\Program Files\\SomeApp\\",
            "file": "malware.exe",
            "resource_set_id": "ResourceSet_20260917_083012_Qw3rTy9z"
        }
    ]
}
```

| Field | Description |
|---|---|
| `name` | Unique identifier: `RansomwareProcessSet_YYYYMMDD_HHMMSS_<8-char random>`. |
| `description` | Always an empty string. |
| `processes[]` | Array of detected processes. Each entry contains `directory`, `file`, and optionally `resource_set_id` linking to a resource set below. |

Alternate-path entries (e.g., the `\SystemRoot\` variant) are automatically appended directly after their primary entry.

### 2. Resource Sets (emitted when `-SkipResourceSets` is not specified)

One JSON object per process group that had matching detection entries in `voradmin`:

```json
{
    "name": "ResourceSet_20260917_083012_Qw3rTy9z",
    "description": "",
    "type": "Directory",
    "resources": [
        {
            "directory": "E:\\GuardedData\\",
            "file": "*",
            "include_subfolders": true
        }
    ]
}
```

| Field | Description |
|---|---|
| `name` | Matches the `resource_set_id` referenced in the process set. |
| `description` | Always an empty string. |
| `type` | Always `"Directory"`. |
| `resources[]` | Array of guarded directories. `file` is always `*` and `include_subfolders` is always `true`. |

If no processes are found the script outputs a process set with an empty `processes` array and exits cleanly.

---

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  1. Resolve log path (file or directory)                 │
│  2. Read all matching vorvmd.log* files into memory      │
├──────────────────────────────────────────────────────────┤
│  3. EXTRACT PROCESSES                                    │
│     a. Regex: "Potential Ransomware activity"            │
│        → captures "Process name: <path>"                 │
│     b. Regex: "RWPML:DEP" alerts                         │
│        → captures "Process <path> with pid"              │
│     c. For each path:                                    │
│        • Normalise double backslashes                    │
│        • Split into directory + file                     │
│        • Replace dated/versioned subdirs with wildcard   │
│        • Deduplicate via normalised group key            │
│        • Generate alternate paths (SystemRoot, etc.)     │
├──────────────────────────────────────────────────────────┤
│  4. EXTRACT RESOURCES  (unless -SkipResourceSets)        │
│     a. Run: voradmin rwp detection-status get            │
│     b. Parse key-value detection entries                 │
│     c. Match each entry's "process" to a known group key │
│     d. Combine guardPath + lastFile → resource directory │
│     e. Truncate resource dir at dated subdirectories     │
│     f. Deduplicate per process group                     │
├──────────────────────────────────────────────────────────┤
│  5. BUILD & OUTPUT JSON                                  │
│     a. Process set (with resource_set_id references)     │
│     b. Resource sets (one per process with resources)    │
└──────────────────────────────────────────────────────────┘
```

---

## Path Normalisation & Alternates

The script applies several normalisation strategies to ensure broad coverage and prevent duplicates:

### Alternate Path Rules

| # | Condition | Generated Alternate |
|---|---|---|
| 1 | Directory contains `C:\Windows` | Replace with `\SystemRoot\` |
| 2 | Directory contains `C:\@Windows` | Replace with `\SystemRoot\` |
| 3 | Directory contains `\SystemRoot\` (but not `C:\Windows`) | Replace with `C:\Windows\` |
| 4 | Directory starts with `\Device\HarddiskVolumeN\` | Replace with `C:\` — and if the result contains `C:\Windows`, a further `\SystemRoot\` alternate is also generated |

### Dated / Versioned Subdirectory Handling

Subdirectories that look like dates, timestamps, or multi-segment version numbers are handled differently depending on context:

- **Process paths**: dated subdirectories are replaced with `*` (wildcard).
  - `C:\Program Files\Symantec\SEP\14.3.7388.4000.105\Bin\smc.exe` → `C:\Program Files\Symantec\SEP\*\Bin\smc.exe`
- **Resource paths**: the directory is *truncated* at the first dated subdirectory and `include_subfolders` is set to `true`.
  - `C:\Program Files\Symantec\SEP\14.3.7388.4000.105\Bin\` → `C:\Program Files\Symantec\SEP\`

Patterns recognised as dated/versioned:
- Pure digits ≥ 4 characters (`20260417`, `1234567890`)
- Digit-separated tokens ≥ 6 characters (`2026-04-17`, `20260417.001`)
- Three or more numeric segments (`14.3.0.1049`, `1.2.3.4`)

### Group Key Normalisation

For deduplication purposes, paths are normalised to a common key:

- `\Device\HarddiskVolumeN\` → `C:\`
- `C:\Windows`, `C:\@Windows`, `\SystemRoot\` → `WINDOWS_ROOT`

This ensures that the same executable reported through different log sources or path formats is counted only once.

---

## Log Patterns Matched

### Pattern 1 — Ransomware Detection

```
2026-02-21 09:14:45.846 [CGA] [ERROR] [3060] [CGA3003E] EVENT: WARNING! Potential Ransomware activity(across-file) detected in process ID 3060, Process name: C:\\Windows\\System32\\notepad.exe. Num original files written to disk: 0.
```

### Pattern 2 — Data Exfiltration Prevention (RWPML:DEP)

```
EVENT: RWPML:DEP: Alert: Process \\Device\\HarddiskVolume2\\Program Files\\WindowsApps\\wordpad.exe with pid 9888 crossed history read limit
```

---

## Example Test Run

```powershell
# Process a test log file, skip voradmin resource-set lookup
powershell -ExecutionPolicy Bypass -File "Generate-RansomwareProcessSet.ps1" `
    -LogFilePath ".\test_vorvmd.log" -SingleFile -SkipResourceSets
```

**Sample output:**

```json
{
    "name": "RansomwareProcessSet_20260917_083012_Ab3xKz9Q",
    "description": "",
    "processes": [
        {
            "directory": "C:\\Windows\\System32\\",
            "file": "notepad.exe"
        },
        {
            "directory": "\\SystemRoot\\System32\\",
            "file": "notepad.exe"
        }
    ]
}
```

---

## Test Files

Several test log files are included in the repository:

| File | Description |
|---|---|
| `test_vorvmd.log` | Basic ransomware entries |
| `test_different_paths.log` | Entries with varying path formats |
| `test_fresh.log` | Single ransomware entry |
| `test_systemroot.log` | Entries using `\SystemRoot\` paths |
| `test_vorvmd_mixed.log` | Mix of ransomware and DEP entries |
| `test_vorvmd_new_process.log` | New process variations |
| `test_multiple_resources.log` | Multiple resource path scenarios |
| `test_new_features.log` | Combined feature coverage |

---

## Troubleshooting

### Log file / directory not found

- Verify the Vormetric agent is installed and the log directory exists.
- Ensure the account running the script has read access to the log path.

### Empty processes array

- The logs may not contain any ransomware or DEP alert entries.
- Double-check the log content for `Potential Ransomware activity` or `RWPML:DEP` strings.

### No resource sets in output

- Resource sets are only generated when `voradmin rwp detection-status get` returns matching entries for the detected processes.
- If `voradmin` is not installed or not on `$env:PATH`, the script will emit a warning and produce process sets only.
- If you used `-SkipResourceSets` (or `-r`), resource output is intentionally suppressed.

### `voradmin` command fails

The script catches errors from `voradmin` gracefully and continues with process-set-only output. A warning is printed to stderr. Ensure `voradmin` is accessible and the Vormetric agent services are running.

---

## Notes

- Each execution produces freshly generated unique names — there is no persistent history file.
- The `description` field is always an empty string per design.
- The script requires `-ExecutionPolicy Bypass` (or an equivalent policy) to run.
- All output is written to **stdout** via `Write-Host`; warnings go to the warning stream.
- The script exits with code `0` on success and `1` on fatal errors (missing log path).
