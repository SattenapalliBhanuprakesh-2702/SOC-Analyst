$startTime=(Get-Date).AddMinutes(-5)

$events=Get-WinEvent -FilterHashtable @{
    LogName="Security";
    Id=4625,4624;
    StartTime=$startTime
}

$events | Select TimeCreated, Id