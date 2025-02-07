#!/usr/bin/env python3
"""
Name: check_ssl_domains.py
Description: Checks SSL certificate expiration for specified domains, saves results to a CSV file, and emails the report.
Last Modified: 2025-02 by Solomon Williams
"""

import ssl
import smtplib
import csv
import socket
from datetime import datetime
from email.message import EmailMessage

# Email notification settings
EMAIL = "support@techtrend.us"
SMTP_SERVER = "smtp.techtrend.us"  # Update with your SMTP server
SMTP_PORT = 587  # Change if needed
SMTP_USER = "monitor@azurecloudgov.us"
SMTP_PASSWORD = "yourpassword"  # Use environment variables instead for security

THRESHOLD1 = 30  # First alert (30 days before expiration)
THRESHOLD2 = 7   # Final alert (7 days before expiration)

# List of domains to check
DOMAINS = ["jenkins.azurecloudgov.us:443", "github.azurecloudgov.us:443", "artifactory.azurecloudgov.us:443", "jira.azurecloudgov.us:443", "sca.azurecloudgov.us:443"]

# CSV output file
CSV_FILE = "ssl_expiry_report.csv"

# Initialize CSV file with headers
with open(CSV_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Domain", "Expiration Date", "Days Until Expiry", "Issuer"])

# Function to check SSL certificate expiry
def check_ssl_expiry(domain):
    try:
        host, port = domain.split(":") if ":" in domain else (domain, "443")
        port = int(port)

        # Get SSL certificate
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as sslsock:
                cert = sslsock.getpeercert()

        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        expiry_days = (expiry_date - datetime.utcnow()).days
        issuer = dict(x[0] for x in cert["issuer"])["organizationName"]

        # Save result to CSV
        with open(CSV_FILE, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([domain, expiry_date, expiry_days, issuer])

        # Send alerts if nearing expiration
        if THRESHOLD2 < expiry_days <= THRESHOLD1:
            send_email(f"SSL Expiry Warning (30 days) for {domain}", f"SSL Certificate for {domain} expires in {expiry_days} days ({expiry_date}).\nIssuer: {issuer}")
        elif expiry_days <= THRESHOLD2:
            send_email(f"FINAL NOTICE: SSL Expiry (7 days) for {domain}", f"FINAL NOTICE: SSL Certificate for {domain} expires in {expiry_days} days ({expiry_date}).\nIssuer: {issuer}")

    except Exception as e:
        with open(CSV_FILE, "a", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([domain, "ERROR", "Could not retrieve certificate", ""])
        print(f"Error checking {domain}: {e}")

# Function to send email notifications
def send_email(subject, body):
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = EMAIL

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        print(f"Email sent: {subject}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Check each domain
for domain in DOMAINS:
    check_ssl_expiry(domain)

# Email the CSV report
send_email("SSL Expiry Report", "SSL Certificate Expiry Report Attached.")
with open(CSV_FILE, "rb") as attachment:
    msg = EmailMessage()
    msg["Subject"] = "SSL Expiry Report"
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL
    msg.set_content("SSL Certificate Expiry Report Attached.")
    msg.add_attachment(attachment.read(), maintype="application", subtype="csv", filename=CSV_FILE)

print(f"SSL check completed. Report saved to {CSV_FILE} and emailed to {EMAIL}.")
