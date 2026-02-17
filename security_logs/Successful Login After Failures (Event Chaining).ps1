$startTime=(Get-Data).AddMinutes(-10)

$Failed = Get-WinEvent -FilterHashtable @{
    LogName="Security"
    Id=4625
    StartTime=$startTime
}

$Success = Get-WinEvent -FilterHashtable @{
    LogName="Security"
    Id=4624
    StartTime=$startTime
}

if ($Failed.Count -ge 5 -and $Success){
    Write-Output "Possible Compromise detected"
}