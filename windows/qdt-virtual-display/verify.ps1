$ErrorActionPreference = 'Stop'

$driver = Get-Content "$PSScriptRoot\Driver.cpp" -Raw
$header = Get-Content "$PSScriptRoot\Driver.h" -Raw
$inf = Get-Content "$PSScriptRoot\QdtVirtualDisplay.inf" -Raw

if ($header -notmatch 'struct QdtMonitorMode') { throw 'mode type declaration is missing' }
if ($driver -notmatch 'QDT_MAX_MONITOR_COUNT = (\d+)') { throw 'monitor maximum is missing' }
if ([int]$Matches[1] -lt 2) { throw 'at least two virtual monitors must be supported' }
if ($driver -notmatch 'QDT_DEFAULT_MONITOR_COUNT = 1') { throw 'default must stay one virtual monitor' }
if ($driver -notmatch '3840,\s*2160,\s*60') { throw '4K mode is missing' }
if ($driver -notmatch '1920,\s*1080,\s*60' -or $driver -notmatch '1280,\s*720,\s*60') { throw 'fallback modes are missing' }
if ($driver -notmatch 'PreferredMonitorModeIdx = 0') { throw 'preferred mode must be the first entry' }
if ($driver -notmatch 'QdtMonitorContainerId\(ConnectorIndex\)') { throw 'each monitor needs its own container id' }
if ($driver -notmatch 'MonitorCount"') { throw 'monitor count must be configurable through the registry' }
if ($inf -notmatch 'Root\\QDTVirtualDisplay') { throw 'hardware ID mismatch' }
if ($inf -match '<Your|TODO: edit') { throw 'sample INF placeholders remain' }

# The reported target modes must cover every monitor mode, otherwise the OS intersection is empty.
$modes = [regex]::Matches($driver, '\{\s*(\d{3,4}),\s*(\d{3,4}),\s*(\d{2,3})\s*\}') | ForEach-Object { $_.Groups[1].Value }
if ($modes.Count -lt 4) { throw 'mode table is too small' }
if ($driver -notmatch 'CreateIddCxTargetMode\(s_QdtModes\[ModeIndex\]') { throw 'target modes must derive from the mode table' }

Write-Host "QDT Virtual Display invariants OK ($($modes.Count) modes)"
