
$StartTime = (Get-Date).AddMinutes(-10)

$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4688
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

foreach ($event in $events) {

    $xml = [xml]$event.ToXml()
    $processName = $xml.Event.EventData.Data[5].'#text'

    if ($processName -match "powershell.exe|cmd.exe|rundll32.exe|wmic.exe") {

        Write-Output "Suspicious Process Detected"
        Write-Output "Time: $($event.TimeCreated)"
        Write-Output "Process: $processName"
    }
}
