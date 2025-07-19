import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from typing import List

from config.settings import settings

async def send_email(
    recipient_email: str,
    subject: str,
    body: str,
    smtp_server: str = settings.SMTP_SERVER,
    smtp_port: int = settings.SMTP_PORT,
    smtp_email: str = settings.SMTP_EMAIL,
    smtp_password: str = settings.SMTP_PASSWORD,
    email_from_name: str = settings.PROJECT_NAME
):
    """
    Sends an email using SMTP.
    Raises an exception if email sending fails.
    """
    if not smtp_email or not smtp_password or not smtp_server:
        raise ValueError("SMTP settings (email, password, or server) are not fully configured in .env")

    msg = MIMEMultipart("alternative")
    msg["From"] = f"{Header(email_from_name, 'utf-8')} <{smtp_email}>"
    msg["To"] = recipient_email
    msg["Subject"] = Header(subject, 'utf-8')

    plain_text_body = body
    html_body = body

    msg.attach(MIMEText(plain_text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, recipient_email, msg.as_string())
        print(f"Email sent successfully to {recipient_email}")
    except smtplib.SMTPAuthenticationError as e:
        print(f"Failed to send email to {recipient_email}: SMTP Authentication Error - {e}")
        raise ConnectionRefusedError(f"SMTP authentication failed. Check SMTP_EMAIL and SMTP_PASSWORD in .env. Details: {e}")
    except smtplib.SMTPConnectError as e:
        print(f"Failed to send email to {recipient_email}: SMTP Connection Error - {e}")
        raise ConnectionRefusedError(f"Could not connect to SMTP server. Check SMTP_SERVER and SMTP_PORT in .env. Details: {e}")
    except Exception as e:
        print(f"Failed to send email to {recipient_email}: General Email Error - {e}")
        raise RuntimeError(f"An unexpected error occurred while sending email. Details: {e}")

