from datetime import datetime, timezone # <--- IMPORT timezone
from enum import Enum
import uuid
from typing import Optional, List

from sqlalchemy import String, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column
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
    # Use timezone-aware datetime for creation and updates
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


# ===================== USER MODEL =====================
class User(Base, TimestampMixin):
    __tablename__ = "users"

    customer_id: Mapped[str] = mapped_column(String(50), primary_key=True, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_onboarded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default=AccountStatus.PENDING_VERIFICATION.value, nullable=False)
    role: Mapped[str] = mapped_column(String(50), default=UserRole.BRAND_USER.value, nullable=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    numeric_customer_id: Mapped[Optional[str]] = mapped_column(String(10), unique=True, nullable=True, index=True)


    otp_verifications: Mapped[List["OtpVerification"]] = relationship("OtpVerification", back_populates="user")
    onboarding_details: Mapped[Optional["OnboardingDetails"]] = relationship("OnboardingDetails", uselist=False, back_populates="user")
    signup_temp_data: Mapped[Optional["SignupTempData"]] = relationship("SignupTempData", uselist=False, back_populates="user")
    password_reset_tokens: Mapped[List["PasswordResetToken"]] = relationship("PasswordResetToken", back_populates="user")
    login_history: Mapped[List["LoginHistory"]] = relationship("LoginHistory", back_populates="user")
    terms_acceptance: Mapped[Optional["TermsAcceptance"]] = relationship("TermsAcceptance", uselist=False, back_populates="user")
    social_media_links: Mapped[List["SocialMediaLink"]] = relationship("SocialMediaLink", back_populates="user")

    def is_deleted(self) -> bool:
        return self.deleted_at is not None


# ===================== OTP VERIFICATION =====================
class OtpVerification(Base, TimestampMixin):
    __tablename__ = "otp_verifications"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.customer_id"), nullable=False, index=True)
    # Consider not storing otp_code in prod for security, only hash for verification
    otp_code: Mapped[str] = mapped_column(String(6), nullable=False)
    otp_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    user: Mapped["User"] = relationship("User", back_populates="otp_verifications")

    # Composite index for efficient OTP lookup (user_id, is_used, expires_at)
    __table_args__ = (
        Index('ix_otp_user_active_expires', 'user_id', 'is_used', 'expires_at', postgresql_where=is_used.is_(False)),
    )

    def is_expired(self) -> bool:
        # Consistent timezone-aware comparison
        return datetime.now(timezone.utc) > self.expires_at


# ===================== ONBOARDING DETAILS =====================
class OnboardingDetails(Base, TimestampMixin):
    __tablename__ = "onboarding_details"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.customer_id"), unique=True, nullable=False, index=True)

    company_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    logo_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    registered_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    pincode: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    locality: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    landmark: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    business_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True) # Stores enum value as string
    website_link: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    full_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    designation: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    phone_number: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="onboarding_details")


# ===================== SOCIAL MEDIA LINKS =====================
class SocialMediaLink(Base, TimestampMixin):
    __tablename__ = "social_media_links"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.customer_id"), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(50), nullable=False) # Stores enum value as string
    url: Mapped[str] = mapped_column(String(500), nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="social_media_links")


# ===================== PASSWORD RESET TOKEN =====================
class PasswordResetToken(Base, TimestampMixin):
    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.customer_id"), nullable=False, index=True)
    token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    user: Mapped["User"] = relationship("User", back_populates="password_reset_tokens")

    # Composite index for efficient token lookup
    __table_args__ = (
        Index('ix_reset_token_active_expires', 'token', 'is_used', 'expires_at',
              postgresql_where=is_used.is_(False)), # Filter for is_used=False for active tokens
    )

    def is_expired(self) -> bool:
        # Consistent timezone-aware comparison
        return datetime.now(timezone.utc) > self.expires_at


# ===================== LOGIN HISTORY =====================
class LoginHistory(Base, TimestampMixin):
    __tablename__ = "login_history"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.customer_id"), nullable=False, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="login_history")


# ===================== TERMS ACCEPTANCE =====================
class TermsAcceptance(Base, TimestampMixin):
    __tablename__ = "terms_acceptance"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.customer_id"), unique=True, nullable=False, index=True)
    terms_version: Mapped[str] = mapped_column(String(50), default="1.0", nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="terms_acceptance")


# ===================== SIGNUP TEMP DATA =====================
class SignupTempData(Base, TimestampMixin):
    __tablename__ = "signup_temp_data"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.customer_id"), nullable=True, index=True)
    saved_data: Mapped[str] = mapped_column(Text, nullable=False)

    user: Mapped[Optional["User"]] = relationship("User", back_populates="signup_temp_data")