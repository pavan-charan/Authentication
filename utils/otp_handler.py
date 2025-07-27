import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone # <--- IMPORT timezone
from typing import Optional
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database.models import OtpVerification, User
from config.settings import settings
from utils.email_sender import send_email

logger = logging.getLogger(__name__)

# OTP configuration
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 10

class OTPHandler:
    @staticmethod
    def generate_otp() -> str:
        """Generates a random numeric OTP and returns it as a string."""
        return str(secrets.randbelow(10**OTP_LENGTH)).zfill(OTP_LENGTH)

    @staticmethod
    def hash_otp(otp_code: str) -> str:
        """Hashes the OTP code (string) using SHA-256."""
        return hashlib.sha256(otp_code.encode('utf-8')).hexdigest()

    @staticmethod
    async def send_otp(
        db: AsyncSession,
        user: User,
        otp_type: str,
        email_template_path: Optional[str] = None,
        subject: Optional[str] = None,
        message_body: Optional[str] = None
    ) -> OtpVerification:
        """
        Generates, stores, and sends an OTP to the user's email.
        COMMITS the OTP record to ensure it's persisted immediately.
        """
        otp_code_str = OTPHandler.generate_otp()
        hashed_otp = OTPHandler.hash_otp(otp_code_str)
        # Ensure expires_at is timezone-aware (UTC)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES) # <--- CHANGE HERE

        new_otp_record = OtpVerification(
            user_id=user.customer_id,
            otp_code=otp_code_str,
            otp_hash=hashed_otp,
            is_used=False,
            verified=False,
            expires_at=expires_at,
        )
        db.add(new_otp_record)
        await db.commit()
        await db.refresh(new_otp_record)
        logger.info(f"OTP generated and stored for user {user.customer_id}, type: {otp_type}.")

        # Prepare email content
        if not subject:
            subject = f"Your {otp_type.replace('_', ' ').title()} OTP Code"
        if not message_body:
            message_body = f"""
                <html>
                <body>
                    <p>Dear {user.email},</p>
                    <p>Your One-Time Password ({otp_type.replace('_', ' ').title()}) is: <strong>{otp_code_str}</strong></p>
                    <p>This OTP is valid for {OTP_EXPIRY_MINUTES} minutes.</p>
                    <p>If you did not request this, please ignore this email.</p>
                    <p>Thanks,</p>
                    <p>The {settings.PROJECT_NAME} Team</p>
                </body>
                </html>
            """
        else:
            message_body = message_body.format(
                otp_code=otp_code_str,
                otp_expiry_minutes=OTP_EXPIRY_MINUTES,
                project_name=settings.PROJECT_NAME,
                otp_type=otp_type.replace('_', ' ').title()
            )

        try:
            await send_email(
                recipient_email=user.email,
                subject=subject,
                body=message_body
            )
            logger.info(f"OTP email sent to {user.email} for {otp_type}.")
        except Exception as e:
            logger.error(f"Failed to send OTP email to {user.email} for {otp_type}: {e}")
            raise

        return new_otp_record

    @staticmethod
    async def verify_otp(db: AsyncSession, user_customer_id: str, otp_code: str) -> Optional[OtpVerification]:
        """
        Verifies an OTP code for a given user.
        Updates OTP record status. COMMITS the OTP record.
        """
        # Ensure the comparison datetime is timezone-aware (UTC)
        current_utc_time = datetime.now(timezone.utc) # <--- CHANGE HERE

        # Select the latest valid OTP for the user
        result = await db.execute(
            select(OtpVerification)
            .where(
                OtpVerification.user_id == user_customer_id,
                OtpVerification.is_used == False,
                OtpVerification.verified == False,
                OtpVerification.expires_at > current_utc_time, # <--- CHANGE HERE
            )
            .order_by(OtpVerification.created_at.desc())
            .limit(1)
        )
        otp_record = result.scalars().first()

        if not otp_record:
            logger.warning(f"OTP verification failed for user {user_customer_id}: No valid/active OTP record found.")
            return None

        # Check if already expired (redundant if WHERE clause is effective, but good for clarity)
        if otp_record.expires_at < current_utc_time: # <--- CHANGE HERE
            otp_record.is_used = True
            await db.commit()
            logger.warning(f"OTP verification failed for user {user_customer_id}: OTP expired (marked as used).")
            return None

        provided_otp_hash = OTPHandler.hash_otp(otp_code)

        if provided_otp_hash == otp_record.otp_hash:
            otp_record.is_used = True
            otp_record.verified = True
            otp_record.verified_at = datetime.now(timezone.utc) # <--- CHANGE HERE for consistency
            await db.commit()
            await db.refresh(otp_record)
            logger.info(f"OTP successfully verified for user {user_customer_id}.")
            return otp_record
        else:
            return None