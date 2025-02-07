# Name: check_ssl_domains.ps1
# Description: Checks SSL certificate expiration for specified domains,
#              saves results to a CSV file, and emails the report.
# Author: Solomon Williams
# Last Modified: 2025-02

# Email notification settings
$EMAIL = "support@techtrend.us"
$SMTPServer = "smtp.techtrend.us"  # Update with your SMTP server
$THRESHOLD1 = 30  # First alert (30 days before expiration)
$THRESHOLD2 = 7   # Final alert (7 days before expiration)

# List of domains to check
$DOMAINS = @("jenkins.azurecloudgov.us:443", "github.azurecloudgov.us:443", "artifactory.azurecloudgov.us:443", "jira.azurecloudgov.us:443", "sca.azurecloudgov.us:443")

# CSV output file
$CSV_FILE = "ssl_expiry_report.csv"

# Initialize CSV file with headers
"Domain,Expiration Date,Days Until Expiry,Issuer" | Out-File -FilePath $CSV_FILE -Encoding utf8

# Function to check SSL certificate expiry
function Check-SSLExpiry {
    param ($Domain)

    try {
        $hostname, $port = $Domain -split ":", 2
        if (-not $port) { $port = 443 }  # Default to port 443

        # Get certificate info
        $cert = New-Object System.Net.Sockets.TcpClient($hostname, $port)
        $stream = $cert.GetStream()
        $sslStream = New-Object System.Net.Security.SslStream($stream, $false)
        $sslStream.AuthenticateAsClient($hostname)

        $certificate = $sslStream.RemoteCertificate
        $expiryDate = $certificate.NotAfter
        $issuer = $certificate.Issuer
        $expiryDays = (New-TimeSpan -Start (Get-Date) -End $expiryDate).Days

        # Save result to CSV
        "$Domain,$expiryDate,$expiryDays,$issuer" | Out-File -FilePath $CSV_FILE -Append -Encoding utf8

        # Send alerts if nearing expiration
        if ($expiryDays -le $THRESHOLD1 -and $expiryDays -gt $THRESHOLD2) {
            Send-MailMessage -To $EMAIL -From "monitor@azurecloudgov.us" -SmtpServer $SMTPServer -Subject "SSL Expiry Warning (30 days) for $Domain" -Body "SSL Certificate for $Domain expires in $expiryDays days ($expiryDate).`nIssuer: $issuer"
        } elseif ($expiryDays -le $THRESHOLD2) {
            Send-MailMessage -To $EMAIL -From "monitor@azurecloudgov.us" -SmtpServer $SMTPServer -Subject "FINAL NOTICE: SSL Expiry (7 days) for $Domain" -Body "FINAL NOTICE: SSL Certificate for $Domain expires in $expiryDays days ($expiryDate).`nIssuer: $issuer"
        }

        $sslStream.Close()
        $stream.Close()
        $cert.Close()
    } catch {
        "$Domain,ERROR,Could not retrieve certificate," | Out-File -FilePath $CSV_FILE -Append -Encoding utf8
    }
}

# Check each domain
foreach ($domain in $DOMAINS) {
    Check-SSLExpiry $domain
}

# Email the CSV report
Send-MailMessage -To $EMAIL -From "monitor@azurecloudgov.us" -SmtpServer $SMTPServer -Subject "SSL Expiry Report" -Attachments $CSV_FILE -Body "SSL Certificate Expiry Report Attached."

Write-Output "SSL check completed. Report saved to $CSV_FILE and emailed to $EMAIL."
