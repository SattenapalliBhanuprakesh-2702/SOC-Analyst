Get-WinEvent -LogName Security -MaxEvents 10 |
Where-Object {
    $_.Id -eq 4625
} | Select-Object TimeCreated,Id,Message