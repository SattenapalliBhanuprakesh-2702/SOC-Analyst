Get-WinEvent -FilterHashTable @{
    LogName='Application' ;
    id=1000,1026; 
    StartTime=(Get-Date).AddMinutes(-500)
} | 
Select-Object TimeCreated, Id,ProviderName,Message