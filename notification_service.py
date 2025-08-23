import os
import smtplib
import ssl
import secrets
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# อ่านค่า SMTP จาก .env
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SMTP_SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SMTP_SENDER_PASSWORD")

def generate_otp(length: int = 6) -> str:
    """สร้างรหัส OTP ที่เป็นตัวเลข 6 หลัก"""
    digits = string.digits
    return ''.join(secrets.choice(digits) for i in range(length))

def send_otp_email(recipient_email: str, otp_code: str) -> bool:
    """ส่งอีเมลที่มีรหัส OTP ไปยังผู้รับ"""
    if not all([SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD]):
        print("ERROR: SMTP settings are not configured in .env file.")
        return False

    message = MIMEMultipart("alternative")
    message["Subject"] = f"Your Password Reset Code: {otp_code}"
    message["From"] = SENDER_EMAIL
    message["To"] = recipient_email

    # เนื้อหาอีเมล (Plain text และ HTML)
    text = f"""
    Hi,
    Your password reset code is: {otp_code}
    This code will expire in 5 minutes.
    If you did not request this, please ignore this email.
    """
    html = f"""
    <html>
    <body>
        <h3>Password Reset Request</h3>
        <p>Your one-time password (OTP) is:</p>
        <h1 style="font-size: 2em; letter-spacing: 5px;">{otp_code}</h1>
        <p>This code will expire in 5 minutes.</p>
        <p>If you did not request a password reset, you can safely ignore this email.</p>
    </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")
    message.attach(part1)
    message.attach(part2)

    # สร้างการเชื่อมต่อและส่งอีเมล
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls(context=context)  # เข้ารหัสการเชื่อมต่อ
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, message.as_string())
        print(f"Successfully sent OTP email to {recipient_email}")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False