$logPath = "C:\Users\satte\OneDrive\Documents\cybersecurity\soc analyst\log\.csv"

$events=Get-WinEvent -FilterHashtable @{
    LogName='Application';
    id=1000;
}

$filtered = $events | Where-Object {
    $_.Message -match 'AppData|Temp|0x0000005|0x0000409'
}

$filtered | Select-Object TimCreated, Id, ProviderName, Message |
Export-Csv -Path $logPath  -Append -NoTypeInformation