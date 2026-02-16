
Get-WinEvent -LogName Application -MaxEvents 5|
Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
