$events = Get-WinEvent -FilterHashtable @{
    LogName='Application'
    Id=1000
}

$count = $events.Count

if ($count -gt 10) {
    Write-Output "ALERT: High crash volume detected ($count crashes in last hour)"
}
else {
    Write-Output "Crash volume normal ($count in last hour)"
}
