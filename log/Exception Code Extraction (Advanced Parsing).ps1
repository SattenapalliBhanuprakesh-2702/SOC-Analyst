$events=Get-WinEvent -FilterHashtable @{
    LogName='Application';
    Id=1000
}

foreach($event in $events){
    if($event.Message -match '0xc0000005|0x0000409|0x0000374'){
        Write-Output "Suspicious Crash Detected"
        Write-Output "Time : $($event.TimeCreated)"
        Write-Output "Details : $($event.Message)"
        Write-Output "----------------------------------------"
    }
}