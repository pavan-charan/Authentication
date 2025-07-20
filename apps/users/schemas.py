from datetime import datetime
from typing import Optional, List, Any
from uuid import UUID
import re

from pydantic import BaseModel, EmailStr, Field, HttpUrl, ValidationError
from pydantic import field_validator, ValidationInfo # <--- Correct Pydantic V2 imports
from database.models import AccountStatus, SocialPlatform, BusinessType


# --- Unified Response Schema ---
class UnifiedResponse(BaseModel):
    is_success: bool = Field(..., description="Indicates if the operation was successful.")
    message: str = Field(..., description="A human-readable message about the operation's outcome.")
    data: Optional[Any] = Field(None, description="A dictionary or map containing relevant data, or null if no data.")
    errors: Optional[List[str]] = Field(None, description="A list of error messages, or null if no errors.")


# --- Base Schemas ---
class TimestampSchema(BaseModel):
    created_at: datetime
    updated_at: datetime

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password_hash: Optional[str] = None

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password_hash: Optional[str] = None
    is_verified: Optional[bool] = None
    status: Optional[AccountStatus] = None
    is_onboarded: Optional[bool] = None
    last_login_at: Optional[datetime] = None
    numeric_customer_id: Optional[str] = None

    # This validator was removed in a previous iteration to simplify and
    # rely on Pydantic's core Optional handling and specific field validators.
    # If you later find a need for it, re-implement carefully with V2 syntax.
    pass

class UserInDB(UserBase, TimestampSchema):
    customer_id: str
    password_hash: Optional[str] = None
    is_verified: bool
    status: AccountStatus
    last_login_at: Optional[datetime] = None
    is_onboarded: bool
    numeric_customer_id: Optional[str] = None

    class Config:
        from_attributes = True

# --- Password Input Base ---
class PasswordInput(BaseModel):
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.")
    confirm_password: str = Field(..., description="Confirm password")

    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if not v or v.strip() == "": raise ValueError('Password cannot be empty.')
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[a-z]", v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Password must contain at least one special character')
        return v

    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo) -> str:
        if not v or v.strip() == "": raise ValueError('Confirm password cannot be empty.')
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v

# --- Authentication & Signup Schemas ---
class UserCreateInitial(UserBase, PasswordInput):
    @field_validator('email')
    @classmethod
    def validate_business_email(cls, v: EmailStr) -> EmailStr:
        if not v or v.strip() == "": raise ValueError('Email cannot be empty.')
        free_email_domains = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "protonmail.com", "icloud.com", "mail.com",
            "yandex.com", "zoho.com"
        ]
        domain = v.split('@')[-1].lower()
        if domain in free_email_domains:
            raise ValueError("Please use a business email address for signup.")
        return v

class OtpRequest(BaseModel):
    email: EmailStr

class OtpVerificationInput(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")

    @field_validator('otp_code')
    @classmethod
    def otp_code_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("OTP code cannot be empty.")
        return v.title()

class OtpStatusResponse(UnifiedResponse):
    data: Optional[dict] = Field(None, description="Contains otp_sent, customer_id, expires_in_minutes")


class SignupCompletionResponse(UnifiedResponse):
    data: Optional[dict] = Field(None, description="Contains customer_id, email, status, is_onboarded, terms_accepted, numeric_customer_id")


class TermsAcceptanceInput(BaseModel):
    email: EmailStr
    terms_version: str = Field("1.0", description="Version of terms being accepted")
    accept_terms: bool = Field(True, description="Must be true to accept terms")

    @field_validator('terms_version')
    @classmethod
    def terms_version_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("Terms version cannot be empty.")
        return v

    @field_validator('accept_terms')
    @classmethod
    def check_acceptance(cls, v: bool) -> bool:
        if v is False:
            raise ValueError("You must accept the terms and conditions to proceed.")
        return v

class SocialMediaLinkCreate(BaseModel):
    platform: SocialPlatform
    url: HttpUrl

    @field_validator('platform')
    @classmethod
    def platform_not_empty(cls, v: SocialPlatform) -> SocialPlatform:
        if v is None:
            raise ValueError("Social media platform cannot be empty.")
        return v

    @field_validator('url')
    @classmethod
    def url_not_empty(cls, v: HttpUrl) -> HttpUrl:
        if not v or str(v).strip() == "":
            raise ValueError("Social media URL cannot be empty.")
        return v


class OnboardingDetailsCreate(BaseModel):
    full_name: str = Field(..., max_length=255)
    phone_number: Optional[str] = Field(None, max_length=20)
    country: Optional[str] = Field(None, max_length=100)
    city: Optional[str] = Field(None, max_length=100)
    company_name: Optional[str] = None
    logo_url: Optional[str] = None
    registered_name: Optional[str] = None
    address: Optional[str] = None
    pincode: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    landmark: Optional[str] = None
    business_type: Optional[BusinessType] = None
    website_link: Optional[str] = None
    description: Optional[str] = None
    designation: Optional[str] = None
    social_media_links: Optional[List[SocialMediaLinkCreate]] = None

    @field_validator('full_name', 'phone_number', 'country', 'city', 'company_name',
               'registered_name', 'address', 'pincode', 'state', 'locality',
               'landmark', 'website_link', 'description', 'designation',
               mode='before')
    @classmethod
    def check_empty_strings(cls, v: Any, info: ValidationInfo) -> Any:
        if isinstance(v, str) and not v.strip():
            if info.field.outer_type.__origin__ is Optional:
                return None
            else:
                raise ValueError(f"{info.field.name} cannot be empty.")
        return v

    @field_validator('full_name')
    @classmethod
    def full_name_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("Full name cannot be empty.")
        return v


class OnboardingDetailsResponse(UnifiedResponse):
    data: Optional[dict] = Field(None, description="Contains onboarding details data.")


# --- New: Onboarding Verification Schemas ---
class OnboardingVerifyRequest(BaseModel):
    email: EmailStr

class OnboardingVerifyResponse(UnifiedResponse):
    data: Optional[dict] = Field(None, description="Contains customer_id, email, onboarding_verified, numeric_customer_id")


# --- Login & Token Schemas ---
class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)

    @field_validator('password')
    @classmethod
    def password_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("Password cannot be empty.")
        return v


class NumericIdLogin(BaseModel):
    numeric_customer_id: str = Field(..., min_length=10, max_length=10, description="10-digit numeric customer ID")
    password: str = Field(..., min_length=1)

    @field_validator('numeric_customer_id')
    @classmethod
    def numeric_customer_id_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("Numeric Customer ID cannot be empty.")
        if not v.isdigit():
            raise ValueError("Numeric Customer ID must contain only digits.")
        return v

    @field_validator('password')
    @classmethod
    def password_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("Password cannot be empty.")
        return v


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    customer_id: str
    is_onboarded: bool
    numeric_customer_id: Optional[str] = None

class LoginResponse(UnifiedResponse):
    data: Optional[dict] = Field(None, description="Contains customer_id, email, status, is_onboarded, redirect_to, numeric_customer_id")


class OtpLoginRequest(BaseModel):
    email: EmailStr

class OtpLoginVerify(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")

    @field_validator('otp_code')
    @classmethod
    def otp_code_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("OTP code cannot be empty.")
        return v.title()


# --- Password Reset/Forgot Schemas ---
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(PasswordInput):
    token: str = Field(..., description="Password reset token received via email")

    @field_validator('token')
    @classmethod
    def token_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("Reset token cannot be empty.")
        return v


class ChangePasswordRequest(PasswordInput):
    email: EmailStr
    old_password: str = Field(..., min_length=1)

    @field_validator('old_password')
    @classmethod
    def old_password_not_empty(cls, v: str) -> str:
        if not v or v.strip() == "":
            raise ValueError("Old password cannot be empty.")
        return v