$startTime = (Get-Date).AddMinutes(-5)

$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
    StartTime=$startTime
}

$parsedEvents = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    [PSCustomObject]@{
        Time = $event.TimeCreated
        User = $xml.Event.EventData.Data[5].'#text'
        IP   = $xml.Event.EventData.Data[19].'#text'
    }
}

$grouped = $parsedEvents | Group-Object IP

foreach ($group in $grouped) {
    if ($group.Count -ge 5) {
        Write-Output "Brute force suspected from IP: $($group.Name)"
    }
}
