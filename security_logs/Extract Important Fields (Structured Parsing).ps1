$events=Get-WinEvents -FilterHashtable @{
    LogName="Security";
    Id=4625;
    StartTime=(Get-Date).AddDays(-1)
}

foreach($event in $events){
    $xml=[xml]$event.ToXml()

    $username = $xml.Event.EventData.Data[5]."#text"
    $ip = $xml.Event.EventData.Data[19]."#text"

    Write-Output "Time : $($event.TimeCreated)"
    Write-Output "User : $username"
    Write-Output "Ip : $ip"
}