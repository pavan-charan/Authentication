from datetime import datetime
from typing import Optional, List
from uuid import UUID
import re

from pydantic import BaseModel, EmailStr, Field, validator, HttpUrl
from database.models import AccountStatus, SocialPlatform, BusinessType # Import BusinessType for validation


# --- Base Schemas ---
class TimestampSchema(BaseModel):
    created_at: datetime
    updated_at: datetime

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase): # Used internally by CRUD, might not be directly exposed
    password_hash: Optional[str] = None

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password_hash: Optional[str] = None
    is_verified: Optional[bool] = None
    status: Optional[AccountStatus] = None
    is_onboarded: Optional[bool] = None
    last_login_at: Optional[datetime] = None
    numeric_customer_id: Optional[str] = None # Added for updates

class UserInDB(UserBase, TimestampSchema):
    customer_id: str
    password_hash: Optional[str] = None
    is_verified: bool
    status: AccountStatus
    last_login_at: Optional[datetime] = None
    is_onboarded: bool
    numeric_customer_id: Optional[str] = None # Added for response

    class Config:
        from_attributes = True

# --- Password Input Base (Defined Early) ---
class PasswordInput(BaseModel):
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.")
    confirm_password: str = Field(..., description="Confirm password")

    @validator('password')
    def validate_password_complexity(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[a-z]", v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Password must contain at least one special character')
        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class SetPasswordInput(PasswordInput): # Used for old signup flow, now deprecated but kept for reference
    email: EmailStr


# --- Authentication & Signup Schemas ---
# Schema for the initial signup step (email + password)
class UserCreateInitial(UserBase):
    password: str = Field(..., min_length=8, description="Password for the user")
    confirm_password: str = Field(..., description="Confirm password")

    @validator('password')
    def validate_password_complexity(cls, v): # Re-adding validator for this specific schema
        if not re.search(r"[A-Z]", v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r"[a-z]", v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r"[0-9]", v):
            raise ValueError('Password must contain at least one number')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Password must contain at least one special character')
        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values): # Re-adding validator for this specific schema
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

    @validator('email') # New validator for business email
    def validate_business_email(cls, v):
        free_email_domains = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "protonmail.com", "icloud.com", "mail.com",
            "yandex.com", "zoho.com"
        ]
        domain = v.split('@')[-1].lower()
        if domain in free_email_domains:
            raise ValueError("Please use a business email address for signup.")
        return v


class OtpRequest(BaseModel): # Used for requesting OTP *after* password set in new flow
    email: EmailStr

class OtpVerificationInput(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")

class OtpStatusResponse(BaseModel):
    message: str
    otp_sent: bool
    customer_id: Optional[str] = None
    expires_in_minutes: Optional[int] = None

class SignupCompletionResponse(BaseModel):
    message: str
    customer_id: str
    email: EmailStr
    status: AccountStatus
    is_onboarded: bool
    terms_accepted: bool = False
    numeric_customer_id: Optional[str] = None # Added for response

class TermsAcceptanceInput(BaseModel):
    email: EmailStr
    terms_version: str = Field("1.0", description="Version of terms being accepted")
    accept_terms: bool = Field(True, description="Must be true to accept terms")

    @validator('accept_terms')
    def check_acceptance(cls, v):
        if not v:
            raise ValueError("You must accept the terms and conditions to proceed.")
        return v

class SocialMediaLinkCreate(BaseModel):
    platform: SocialPlatform
    url: HttpUrl

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
    business_type: Optional[BusinessType] = None # Use BusinessType Enum for validation
    website_link: Optional[str] = None
    description: Optional[str] = None
    designation: Optional[str] = None
    social_media_links: Optional[List[SocialMediaLinkCreate]] = None

class OnboardingDetailsResponse(OnboardingDetailsCreate, TimestampSchema):
    id: UUID
    user_id: str
    verified: bool # Added for response
    class Config:
        from_attributes = True

# --- New: Onboarding Verification Schemas ---
class OnboardingVerifyRequest(BaseModel):
    email: EmailStr
    # You might add a secret key or admin token here for authorization in a real app
    # admin_secret: str = Field(..., description="Admin secret key for verification")

class OnboardingVerifyResponse(BaseModel):
    message: str
    customer_id: str
    email: EmailStr
    onboarding_verified: bool
    numeric_customer_id: Optional[str] = None # Include the newly assigned ID


# --- Login & Token Schemas ---
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# New: Login with Numeric ID
class NumericIdLogin(BaseModel):
    numeric_customer_id: str = Field(..., min_length=10, max_length=10, description="10-digit numeric customer ID")
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    customer_id: str
    is_onboarded: bool
    numeric_customer_id: Optional[str] = None # Added for token response

class LoginResponse(BaseModel):
    message: str
    customer_id: str
    email: EmailStr
    status: AccountStatus
    is_onboarded: bool
    redirect_to: str
    numeric_customer_id: Optional[str] = None # Added for login response

class OtpLoginRequest(BaseModel):
    email: EmailStr

class OtpLoginVerify(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")

# --- Password Reset/Forgot Schemas ---
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(PasswordInput): # Inherits password and confirm_password validation
    token: str = Field(..., description="Password reset token received via email")

class ChangePasswordRequest(PasswordInput): # Inherits password and confirm_password validation
    email: EmailStr
    old_password: str
