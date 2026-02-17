# =========================
# LEVEL 8 - Privilege Escalation
# =========================

$StartTime = (Get-Date).AddMinutes(-10)

$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4672
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

foreach ($event in $events) {

    $xml = [xml]$event.ToXml()

    $user = $xml.Event.EventData.Data[1].'#text'

    Write-Output "Privilege escalation detected"
    Write-Output "Time: $($event.TimeCreated)"
    Write-Output "User: $user"
}
