from datetime import datetime
from enum import Enum
import uuid
from typing import Optional

from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# ===================== ENUMS =====================
class UserRole(str, Enum):
    ADMIN = "admin"
    BRAND_USER = "brand_user"
    INFLUENCER = "influencer"
    SUPER_ADMIN = "super_admin"

class BusinessType(str, Enum):
    STARTUP = "startup"
    SME = "sme"
    ENTERPRISE = "enterprise"
    AGENCY = "agency"
    ECOMMERCE = "ecommerce"
    RETAIL = "retail"
    MANUFACTURING = "manufacturing"
    SERVICES = "services"
    OTHER = "other"

class AccountStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"

class SocialPlatform(str, Enum):
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    YOUTUBE = "youtube"
    TIKTOK = "tiktok"
    OTHER = "other"


# ===================== MIXINS =====================
class TimestampMixin:
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


# ===================== USER MODEL =====================
class User(Base, TimestampMixin):
    __tablename__ = "users"

    customer_id = Column(String(50), primary_key=True, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_onboarded = Column(Boolean, default=False, nullable=False)
    status = Column(String(50), default=AccountStatus.PENDING_VERIFICATION.value, nullable=False)
    role = Column(String(50), default=UserRole.BRAND_USER.value, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    deleted_at = Column(DateTime, nullable=True)

    numeric_customer_id = Column(String(10), unique=True, nullable=True, index=True)


    otp_verifications = relationship("OtpVerification", back_populates="user")
    onboarding_details = relationship("OnboardingDetails", uselist=False, back_populates="user")
    signup_temp_data = relationship("SignupTempData", uselist=False, back_populates="user")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user")
    login_history = relationship("LoginHistory", back_populates="user")
    terms_acceptance = relationship("TermsAcceptance", uselist=False, back_populates="user")
    social_media_links = relationship("SocialMediaLink", back_populates="user")

    def is_deleted(self) -> bool:
        return self.deleted_at is not None


# ===================== OTP VERIFICATION =====================
class OtpVerification(Base, TimestampMixin):
    __tablename__ = "otp_verifications"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(50), ForeignKey("users.customer_id"), nullable=False)
    otp_code = Column(String(6), nullable=False)
    otp_hash = Column(String(64), nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    verified = Column(Boolean, default=False, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="otp_verifications")

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at


# ===================== ONBOARDING DETAILS =====================
class OnboardingDetails(Base, TimestampMixin):
    __tablename__ = "onboarding_details"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(50), ForeignKey("users.customer_id"), unique=True, nullable=False)

    company_name = Column(String(200), nullable=True)
    logo_url = Column(String(500), nullable=True)
    registered_name = Column(String(200), nullable=True)
    address = Column(String(500), nullable=True)
    pincode = Column(String(20), nullable=True)
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    locality = Column(String(100), nullable=True)
    landmark = Column(String(100), nullable=True)
    business_type = Column(String(50), nullable=True)
    website_link = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)

    full_name = Column(String(100), nullable=True)
    designation = Column(String(100), nullable=True)
    phone_number = Column(String(20), nullable=True)

    verified = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="onboarding_details")


# ===================== SOCIAL MEDIA LINKS =====================
class SocialMediaLink(Base, TimestampMixin):
    __tablename__ = "social_media_links"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(50), ForeignKey("users.customer_id"), nullable=False)
    platform = Column(String(50), nullable=False)
    url = Column(String(500), nullable=False)

    user = relationship("User", back_populates="social_media_links")


# ===================== PASSWORD RESET TOKEN =====================
class PasswordResetToken(Base, TimestampMixin):
    __tablename__ = "password_reset_tokens"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(50), ForeignKey("users.customer_id"), nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="password_reset_tokens")

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at


# ===================== LOGIN HISTORY =====================
class LoginHistory(Base, TimestampMixin):
    __tablename__ = "login_history"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(50), ForeignKey("users.customer_id"), nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)

    user = relationship("User", back_populates="login_history")


# ===================== TERMS ACCEPTANCE =====================
class TermsAcceptance(Base, TimestampMixin):
    __tablename__ = "terms_acceptance"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String(50), ForeignKey("users.customer_id"), unique=True, nullable=False)
    terms_version = Column(String(50), default="1.0", nullable=False)
    accepted_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="terms_acceptance")


# ===================== SIGNUP TEMP DATA =====================
class SignupTempData(Base, TimestampMixin):
    __tablename__ = "signup_temp_data"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(String(50), ForeignKey("users.customer_id"), nullable=True)
    saved_data = Column(Text, nullable=False)

    user = relationship("User", back_populates="signup_temp_data")

