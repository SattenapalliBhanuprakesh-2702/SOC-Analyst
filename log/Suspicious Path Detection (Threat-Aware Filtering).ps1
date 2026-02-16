$events = Get-WinEvent -FilterHashtable @{
    LogName='Application';
    id=1000,1026;
}

$suspicious = $events | Where-Object{
    $_.Message -match 'AppData|Temp|Users\\Public'
}

$suspicious | Select-Object TimeCreated,ProviderName,Message