#  CONFIG
$LogDirectory = 'C:\LOGS'
$JsonLogPath  = Join-Path $LogDirectory "AppCrashMonitor.json"
$Threshold    = 3

#  DIRECTORY CHECK 
if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

# RETRIEVE EVENTS
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        Id      = 1000,1026
    } -ErrorAction Stop
}
catch {
    Write-Output "Failed to retrieve events: $($_.Exception.Message)"
    exit
}

if (-not $events) {
    Write-Output "No events found."
    exit
}

$alerts = @()

foreach ($event in $events) {

    $message = $event.Message

    # Extract exception code
    $exceptionCode = if ($message -match '0x[0-9a-fA-F]{8}') { $matches[0] } else { 'N/A' }

    # Extract faulting application name
    $appName = if ($message -match 'Faulting application name:\s(.+?),') { $matches[1] } else { 'N/A' }

    # Suspicious pattern detection
    if ($message -match 'AppData|Temp|Users\\Public|0xc0000005|0xc0000409|0xc0000374') {

        # Create fingerprint
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($message))
        $hash = [System.BitConverter]::ToString($hashBytes).Replace("-", "")

        $alerts += [PSCustomObject]@{
            Timestamp     = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventID       = $event.Id
            Provider      = $event.ProviderName
            Application   = $appName
            ExceptionCode = $exceptionCode
            Host          = $env:COMPUTERNAME
            Fingerprint   = $hash
            Suspicious    = $true
        }
    }
}

# ANOMALY DETECTION
$crashCount = $events.Count

if ($crashCount -ge $Threshold) {
    Write-Output "Crash spike detected: $crashCount events."
}

# DEDUPLICATION + LOGGING 
if ($alerts.Count -gt 0) {

    $existingFingerprints = @()

    if (Test-Path $JsonLogPath) {
        try {
            $existingData = Get-Content $JsonLogPath -Raw | ConvertFrom-Json
            $existingFingerprints = $existingData | Select-Object -ExpandProperty Fingerprint
        }
        catch {
            Write-Output "Warning: Existing JSON file corrupted. Resetting."
        }
    }

    $newAlerts = $alerts | Where-Object {
        $_.Fingerprint -notin $existingFingerprints
    }

    if ($newAlerts.Count -gt 0) {

        $allData = @()

        if (Test-Path $JsonLogPath) {
            $allData = Get-Content $JsonLogPath -Raw | ConvertFrom-Json
        }

        $allData += $newAlerts

        $allData | ConvertTo-Json -Depth 5 | Set-Content $JsonLogPath

        Write-Output "New suspicious crash patterns logged."
    }
    else {
        Write-Output "Duplicate crash pattern detected. No new logging."
    }
}
else {
    Write-Output "No suspicious activity detected."
}
