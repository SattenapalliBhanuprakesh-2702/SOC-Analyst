# =========================
# LEVEL 7 - Email Alerting
# =========================

$StartTime = (Get-Date).AddMinutes(-10)
$Threshold = 5

$SmtpServer = "smtp.company.com"
$ToEmail = "soc@company.com"
$FromEmail = "monitor@company.com"

$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4625
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

if ($events.Count -ge $Threshold) {

    $Body = "Brute force detected. Failed attempts: $($events.Count)"

    Send-MailMessage `
        -To $ToEmail `
        -From $FromEmail `
        -Subject "Security Alert: Brute Force Detected" `
        -Body $Body `
        -SmtpServer $SmtpServer
}
