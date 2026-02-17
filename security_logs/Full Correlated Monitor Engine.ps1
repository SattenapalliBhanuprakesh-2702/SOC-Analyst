$JsonLogPath = "C:\Logs\SecurityAlerts.json"
$Interval = 300
$BruteForceThreshold = 5

# Whitelist (edit as needed)
$WhitelistedUsers = @("Administrator","SYSTEM")
$WhitelistedIPs   = @("127.0.0.1","::1")

#----------------------------------------------------------------------------------------------------
# FUNCTION: Write Alert


function Write-Alert {
    param ($Type, $Details)

    $alert = [PSCustomObject]@{
        Time      = Get-Date
        Computer  = $env:COMPUTERNAME
        AlertType = $Type
        Details   = $Details
    }

    $alert | ConvertTo-Json -Depth 5 | Add-Content $JsonLogPath
    Write-Output "$Type detected: $Details"
}


# MAIN LOOP


while ($true) {

    $StartTime = (Get-Date).AddSeconds(-$Interval)

    # --------------------------------------------------------------------------------------------------------------------------------
    #Get Successful Logons
    

    $logons = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4624
        StartTime=$StartTime
    } -ErrorAction SilentlyContinue

    foreach ($logon in $logons) {

        $xml = [xml]$logon.ToXml()

        $user = $xml.Event.EventData.Data[5].'#text'
        $ip   = $xml.Event.EventData.Data[18].'#text'
        $logonID = $xml.Event.EventData.Data[7].'#text'
        $logonType = $xml.Event.EventData.Data[8].'#text'

        if ($WhitelistedUsers -contains $user) { continue }
        if ($WhitelistedIPs -contains $ip) { continue }

        # --------------------------------------------------------------------------------------------------------------------------------------
        #Lateral Movement Detection
        

        if ($logonType -eq 3 -or $logonType -eq 10) {
            Write-Alert "Lateral Movement" "User $user logged in from $ip (LogonType $logonType)"
        }

        # ---------------------------------------------------------------------------------------------------------------------------
        # Privilege Escalation Correlation
        

        $privEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=4672
            StartTime=$StartTime
        } -ErrorAction SilentlyContinue

        foreach ($priv in $privEvents) {

            $privXml = [xml]$priv.ToXml()
            $privLogonID = $privXml.Event.EventData.Data[3].'#text'

            if ($privLogonID -eq $logonID) {
                Write-Alert "Privilege Escalation" "User $user received admin privileges"
            }
        }

        # ------------------------------------------------------------------------------------------------------------------------------
        # Suspicious Process Correlation
        

        $processEvents = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            Id=4688
            StartTime=$StartTime
        } -ErrorAction SilentlyContinue

        foreach ($proc in $processEvents) {

            $procXml = [xml]$proc.ToXml()
            $procLogonID = $procXml.Event.EventData.Data[8].'#text'
            $processName = $procXml.Event.EventData.Data[5].'#text'

            if ($procLogonID -eq $logonID -and
                $processName -match "powershell.exe|cmd.exe|rundll32.exe|wmic.exe") {

                Write-Alert "Suspicious Process" "User $user executed $processName"
            }
        }
    }

    Start-Sleep -Seconds $Interval
}
