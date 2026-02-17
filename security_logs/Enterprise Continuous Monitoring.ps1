$JsonLogPath = "C:\Logs\SecurityAlerts.json"
$Interval = 300
$Threshold = 5

while ($true) {

    $StartTime = (Get-Date).AddSeconds(-$Interval)

    # 4625 - Failed Logons
    $failed = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4625
        StartTime=$StartTime
    } -ErrorAction SilentlyContinue

    if ($failed.Count -ge $Threshold) {

        $alert = [PSCustomObject]@{
            Time      = Get-Date
            AlertType = "Brute Force"
            Count     = $failed.Count
        }

        $alert | ConvertTo-Json -Depth 5 | Add-Content $JsonLogPath
        Write-Output "Brute force detected"
    }

    # 4672 - Privilege Escalation
    $priv = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4672
        StartTime=$StartTime
    } -ErrorAction SilentlyContinue

    foreach ($event in $priv) {
        Write-Output "Privilege escalation at $($event.TimeCreated)"
    }

    # 4688 - Suspicious Process
    $proc = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4688
        StartTime=$StartTime
    } -ErrorAction SilentlyContinue

    foreach ($event in $proc) {
        if ($event.Message -match "powershell.exe|cmd.exe|rundll32.exe") {
            Write-Output "Suspicious process execution"
        }
    }

    Start-Sleep -Seconds $Interval
}
