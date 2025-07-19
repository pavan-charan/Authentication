from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from apps.users.schemas import (
    OtpVerificationInput, OtpRequest, OtpStatusResponse,
    SignupCompletionResponse, OnboardingDetailsCreate,
    UserLogin, LoginResponse, OtpLoginRequest, OtpLoginVerify,
    ForgotPasswordRequest, ResetPasswordRequest, ChangePasswordRequest,
    TermsAcceptanceInput, UserCreateInitial, OnboardingVerifyRequest, OnboardingVerifyResponse,
    NumericIdLogin # New import
)
from apps.users.services import UserAuthService
from database.connection import get_async_session

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Dependency for database session
DBSession = Annotated[AsyncSession, Depends(get_async_session)]

# --- Signup Flow (Reordered) ---
@router.post("/signup/step1-email-password", response_model=OtpStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def signup_step1_email_password(user_create_initial: UserCreateInitial, db: DBSession):
    """
    New Step 1: User enters email, sets and confirms password.
    A new user record is created, and OTP is sent to the email.
    """
    response = await UserAuthService.initiate_signup_email_password(db, user_create_initial.email, user_create_initial.password)
    return response

@router.post("/signup/step2-verify-otp", response_model=SignupCompletionResponse, status_code=status.HTTP_200_OK)
async def signup_step2_verify_otp(otp_input: OtpVerificationInput, db: DBSession):
    """
    New Step 2: User verifies the OTP received in their email.
    Email verification status is updated.
    """
    response = await UserAuthService.verify_signup_otp(db, otp_input.email, otp_input.otp_code)
    return response

@router.post("/signup/step3-accept-terms", response_model=SignupCompletionResponse, status_code=status.HTTP_200_OK)
async def signup_step3_accept_terms(terms_input: TermsAcceptanceInput, db: DBSession):
    """
    New Step 3: User accepts terms and conditions.
    This step is required after email verification and before onboarding.
    """
    response = await UserAuthService.accept_terms_and_conditions(db, terms_input.email, terms_input.terms_version)
    return response

@router.post("/signup/step4-onboarding", response_model=SignupCompletionResponse, status_code=status.HTTP_200_OK)
async def signup_step4_onboarding(email: str, onboarding_data: OnboardingDetailsCreate, db: DBSession):
    """
    New Step 4: User completes their initial onboarding details, including social media links.
    """
    response = await UserAuthService.complete_signup_onboarding(db, email, onboarding_data)
    return response

# --- Onboarding Verification Route (Admin Action) ---
@router.post("/onboarding/verify", response_model=OnboardingVerifyResponse, status_code=status.HTTP_200_OK)
async def verify_onboarding(verify_request: OnboardingVerifyRequest, db: DBSession):
    """
    Admin route to verify a user's onboarding details and assign a unique 10-digit ID.
    (In a real application, this route would be protected by admin authentication/authorization).
    """
    response = await UserAuthService.verify_onboarding_details(db, verify_request.email)
    return response


# --- Login Flow ---
@router.post("/login/password", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login_with_password(user_login: UserLogin, db: DBSession, request: Request):
    """
    Logs in a user using email and password.
    Redirects based on onboarding status.
    """
    response = await UserAuthService.login_user_password(db, user_login.email, user_login.password)
    return response

@router.post("/login/numeric-id", response_model=LoginResponse, status_code=status.HTTP_200_OK) # New Login Route
async def login_with_numeric_id(numeric_id_login: NumericIdLogin, db: DBSession, request: Request):
    """
    Logs in a user using their unique 10-digit numeric ID and password.
    Redirects based on onboarding status.
    """
    response = await UserAuthService.login_user_numeric_id(db, numeric_id_login.numeric_customer_id, numeric_id_login.password)
    return response

@router.post("/login/otp/request", response_model=OtpStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def request_otp_login(otp_request: OtpLoginRequest, db: DBSession):
    """
    Requests an OTP for login.
    """
    response = await UserAuthService.initiate_otp_login(db, otp_request.email)
    return response

@router.post("/login/otp/verify", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def verify_otp_login(otp_verify: OtpLoginVerify, db: DBSession, request: Request):
    """
    Verifies OTP for login and logs in the user.
    Redirects based on onboarding status.
    """
    response = await UserAuthService.verify_otp_login(db, otp_verify.email, otp_verify.otp_code)
    return response

# --- Password Management ---
@router.post("/password/forgot", status_code=status.HTTP_200_OK)
async def forgot_password(forgot_request: ForgotPasswordRequest, db: DBSession):
    """
    Initiates the forgot password process by sending a reset link via email.
    """
    response = await UserAuthService.forgot_password(db, forgot_request.email)
    return response

@router.post("/password/reset", status_code=status.HTTP_200_OK)
async def reset_password(reset_request: ResetPasswordRequest, db: DBSession):
    """
    Resets the user's password using a valid reset token.
    """
    response = await UserAuthService.reset_password(db, reset_request.token, reset_request.password)
    return response

@router.post("/password/change", status_code=status.HTTP_200_OK)
async def change_password(change_request: ChangePasswordRequest, db: DBSession):
    """
    Allows a logged-in user to change their password (requires old password).
    """
    response = await UserAuthService.change_password(db, change_request.email, change_request.old_password, change_request.password)
    return response
