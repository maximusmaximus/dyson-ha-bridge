# start_bridge.ps1 - 24/7 Watchdog for Dyson Desk Lamp HA Bridge
$ErrorActionPreference = "SilentlyContinue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = "C:\Users\worki\.gemini\antigravity\scratch\dyson-ha-bridge" }
Set-Location $scriptDir

$watchdogLog = Join-Path $scriptDir "watchdog.log"
function Log-Watchdog ($msg) {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [WATCHDOG] $msg" | Out-File -FilePath $watchdogLog -Append -Encoding UTF8
}

# Single-instance mutex
$createdNew = $false
$mutex = New-Object System.Threading.Mutex($true, "Global\DysonBridgeWatchdogMutex", [ref]$createdNew)
if (-not $createdNew) {
    Log-Watchdog "Another watchdog instance is already running (mutex locked). Exiting duplicate."
    exit 0
}

$pythonExe = "C:\Users\worki\AppData\Local\Programs\Python\Python312\pythonw.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = "C:\Users\worki\AppData\Local\Programs\Python\Python312\python.exe"
    if (-not (Test-Path $pythonExe)) {
        $pythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
    }
}

Log-Watchdog "Dyson Bridge Watchdog started (PID $PID)."

try {
    while ($true) {
        $existing = Get-CimInstance Win32_Process | Where-Object { 
            $_.Name -match "python" -and 
            $_.CommandLine -like "*dyson-ha-bridge\bridge.py*" -and 
            $_.ProcessId -ne $PID 
        }
        if ($existing) {
            Start-Sleep -Seconds 30
            continue
        }

        Log-Watchdog "Starting dyson bridge.py using $pythonExe..."
        $proc = Start-Process -FilePath $pythonExe -ArgumentList "`"$scriptDir\bridge.py`"" -WorkingDirectory $scriptDir -WindowStyle Hidden -PassThru
        if ($proc) {
            Log-Watchdog "bridge.py started with PID $($proc.Id). Monitoring..."
            $proc.WaitForExit()
            Log-Watchdog "bridge.py (PID $($proc.Id)) exited with code $($proc.ExitCode). Restarting in 5 seconds..."
        } else {
            Log-Watchdog "Failed to launch bridge.py. Retrying in 10 seconds..."
            Start-Sleep -Seconds 5
        }
        Start-Sleep -Seconds 5
    }
} finally {
    if ($mutex) {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
}
