"""
Alert module for dispatching security findings to Slack, Email, and SMS.

All functions gracefully degrade when credentials are missing — they log a warning
and return False rather than raising exceptions.
"""

import json
import logging
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


def send_slack(message: str) -> bool:
    """
    Send a message to Slack via webhook.

    Reads SLACK_WEBHOOK_URL from environment. If not set, logs a warning
    and returns False without error.

    Returns:
        True if message sent successfully, False otherwise.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        logger.warning("SLACK_WEBHOOK_URL not configured — skipping Slack notification")
        return False

    try:
        import urllib.request

        payload = json.dumps({"text": message}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            if 200 <= response.status < 300:
                logger.info("Slack notification sent successfully")
                return True
            else:
                logger.warning(
                    "Slack webhook returned status %s", response.status
                )
                return False
    except Exception as e:
        logger.warning("Failed to send Slack notification: %s", e)
        return False


def send_email(subject: str, body: str, to_email: str | None = None) -> bool:
    """
    Send an email alert via SMTP.

    Reads SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD from environment.
    If SMTP_HOST is not set, logs a warning and returns False.

    Args:
        subject: Email subject line
        body: Plain-text email body
        to_email: Recipient address. If None, uses SMTP_USER (self-send).

    Returns:
        True if message sent successfully, False otherwise.
    """
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    if not smtp_host:
        logger.warning("SMTP_HOST not configured — skipping email notification")
        return False

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    recipient = to_email or smtp_user

    if not recipient:
        logger.warning("No recipient email available — skipping email notification")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user or "alerts@localhost"
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            server.ehlo()
            if smtp_port == 587:
                server.starttls()
                server.ehlo()

        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)

        server.send_message(msg)
        server.quit()
        logger.info("Email sent to %s", recipient)
        return True
    except Exception as e:
        logger.warning("Failed to send email: %s", e)
        return False


def send_sms(phone: str, message: str) -> bool:
    """
    Send an SMS alert via Twilio.

    Reads TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER from
    environment. If Twilio is not configured or the library is unavailable,
    logs a warning and returns False.

    Args:
        phone: Destination phone number (E.164 format recommended)
        message: SMS body text

    Returns:
        True if message sent successfully, False otherwise.
    """
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    from_number = os.environ.get("TWILIO_PHONE_NUMBER", "").strip()

    if not (account_sid and auth_token and from_number):
        logger.warning(
            "Twilio credentials not fully configured — skipping SMS notification"
        )
        return False

    try:
        from twilio.rest import Client
    except ImportError:
        logger.warning("Twilio library not installed — skipping SMS notification")
        return False

    try:
        client = Client(account_sid, auth_token)
        msg = client.messages.create(body=message, from_=from_number, to=phone)
        logger.info("SMS sent to %s (SID: %s)", phone, msg.sid)
        return True
    except Exception as e:
        logger.warning("Failed to send SMS: %s", e)
        return False


def send_critical_alert(result: dict) -> dict:
    """
    Format and dispatch a critical security alert to all configured channels.

    Args:
        result: Dictionary with keys:
            - target (str): The target URL/host scanned
            - risk_level (str): Risk classification (e.g. 'CRITICAL')
            - summary (str): One-line description of the finding
            - findings (list): List of finding dicts, used for count
            - timestamp (str): ISO-8601 timestamp

    Returns:
        dict with keys: slack, email, sms (bool each), any_sent (bool)
    """
    try:
        target = result.get("target", "N/A")
        risk_level = result.get("risk_level", "UNKNOWN")
        summary = result.get("summary", "No summary provided")
        findings = result.get("findings", [])
        timestamp = result.get("timestamp", "N/A")

        finding_count = len(findings) if isinstance(findings, list) else 0

        message = (
            "🚨 CRITICAL SECURITY FINDING\n"
            f"Target: {target}\n"
            f"Risk: {risk_level}\n"
            f"Summary: {summary}\n"
            f"Findings: {finding_count}\n"
            f"Time: {timestamp}"
        )

        subject = f"[{risk_level}] Security Finding — {target}"

        slack_ok = send_slack(message)
        email_ok = send_email(subject, message)
        sms_ok = send_sms("", message)  # No phone configured by default

    except Exception as e:
        logger.warning("send_critical_alert encountered an error: %s", e)
        slack_ok = False
        email_ok = False
        sms_ok = False

    return {
        "slack": slack_ok,
        "email": email_ok,
        "sms": sms_ok,
        "any_sent": slack_ok or email_ok or sms_ok,
    }
