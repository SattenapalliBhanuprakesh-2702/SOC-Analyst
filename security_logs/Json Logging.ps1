$JsonLogPath = 'C:\Logs\SecurityAlerts.json'
$startTime=(Get-Data).AddMinutes(-10)
$Thresold=10

$events = Get-WinEvents -FilterHashtable @{
    LogName="Security"
    Id=4625
    StartTime=$startTime
} -ErrorAction SilentlyContinue

if($events){
    $parsed=foreach($event in $events){
        $xml=[xml]$event.ToXml()
        [psCustomObject]@{
            Time=$event.TimeCreated
            $User=$xml.Event.EventData.Data[5]."#text"
            $IP=$xml.Event.EventData.Data[19]."#text"
        }
    }

    $grouped = $parsed | Group-Object $IP

    foreach($group in $grouped){
        if($group.Count -ge $Thresold){
            $alert =[psCustomObject]@{
                Time=Get-Date
                Computer=$env:COMPUTERNAME
                AlertType="BruteForce"
                IP=$group.Name
                Count=$group.Count 
            }
            $alert | ConvertTo-Json -Depth 5  | Add-COntent -Path $JsonLogPath
        }
    }
}