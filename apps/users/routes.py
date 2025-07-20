from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException, Request, Response # <--- IMPORT Request
import logging

from sqlalchemy.ext.asyncio import AsyncSession # <--- IMPORT AsyncSession

from apps.users.schemas import (
    OtpVerificationInput, OtpRequest, OtpStatusResponse,
    SignupCompletionResponse, OnboardingDetailsCreate,
    UserLogin, LoginResponse, OtpLoginRequest, OtpLoginVerify,
    ForgotPasswordRequest, ResetPasswordRequest, ChangePasswordRequest,
    TermsAcceptanceInput, UserCreateInitial, OnboardingVerifyRequest, OnboardingVerifyResponse,
    NumericIdLogin, UnifiedResponse
)
from apps.users.services import UserAuthService
from database.connection import get_async_session

router = APIRouter(prefix="/auth", tags=["Authentication"])

logger = logging.getLogger(__name__)

# Dependency for database session
DBSession = Annotated[AsyncSession, Depends(get_async_session)]

# --- Signup Flow (Reordered) ---
@router.post("/signup/step1-email-password", response_model=OtpStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def signup_step1_email_password(user_create_initial: UserCreateInitial, db: DBSession):
    """
    New Step 1: User enters email, sets and confirms password.
    A new user record is created, and OTP is sent to the email.
    """
    response_data = await UserAuthService.initiate_signup_email_password(db, user_create_initial.email, user_create_initial.password)
    return OtpStatusResponse(
        is_success=True,
        message="Account created and OTP sent to your email. Please verify to proceed.",
        data=response_data
    )


@router.post("/signup/step2-verify-otp", response_model=SignupCompletionResponse, status_code=status.HTTP_200_OK)
async def signup_step2_verify_otp(otp_input: OtpVerificationInput, db: DBSession):
    """
    New Step 2: User verifies the OTP received in their email.
    Email verification status is updated.
    """
    response_data = await UserAuthService.verify_signup_otp(db, otp_input.email, otp_input.otp_code)
    return SignupCompletionResponse(
        is_success=True,
        message="Email verified successfully. You can now proceed to terms acceptance.",
        data=response_data
    )


@router.post("/signup/step3-accept-terms", response_model=SignupCompletionResponse, status_code=status.HTTP_200_OK)
async def signup_step3_accept_terms(terms_input: TermsAcceptanceInput, db: DBSession):
    """
    New Step 3: User accepts terms and conditions.
    This step is required after email verification and before onboarding.
    """
    response_data = await UserAuthService.accept_terms_and_conditions(db, terms_input.email, terms_input.terms_version)
    return SignupCompletionResponse(
        is_success=True,
        message="Terms and conditions accepted successfully. Proceed to onboarding.",
        data=response_data
    )


@router.post("/signup/step4-onboarding", response_model=SignupCompletionResponse, status_code=status.HTTP_200_OK)
async def signup_step4_onboarding(email: str, onboarding_data: OnboardingDetailsCreate, db: DBSession):
    """
    New Step 4: User completes their initial onboarding details, including social media links.
    """
    response_data = await UserAuthService.complete_signup_onboarding(db, email, onboarding_data)
    message = response_data.pop("message", "Onboarding details saved successfully. Signup complete!")
    return SignupCompletionResponse(
        is_success=True,
        message=message,
        data=response_data
    )

# --- Onboarding Verification Route (Admin Action) ---
@router.post("/onboarding/verify", response_model=OnboardingVerifyResponse, status_code=status.HTTP_200_OK)
async def verify_onboarding(verify_request: OnboardingVerifyRequest, db: DBSession):
    """
    Admin route to verify a user's onboarding details and assign a unique 10-digit ID.
    (In a real application, this route would be protected by admin authentication/authorization).
    """
    response_data = await UserAuthService.verify_onboarding_details(db, verify_request.email)
    message = response_data.pop("message", "Onboarding verification successful.")
    return OnboardingVerifyResponse(
        is_success=True,
        message=message,
        data=response_data
    )


# --- Login Flow ---
@router.post("/login/password", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login_with_password(user_login: UserLogin, db: DBSession, request: Request):
    """
    Logs in a user using email and password.
    Redirects based on onboarding status.
    """
    response_data = await UserAuthService.login_user_password(db, user_login.email, user_login.password)
    return LoginResponse(
        is_success=True,
        message="Login successful.",
        data=response_data
    )


@router.post("/login/numeric-id", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login_with_numeric_id(numeric_id_login: NumericIdLogin, db: DBSession, request: Request):
    """
    Logs in a user using their unique 10-digit numeric ID and password.
    Redirects based on onboarding status.
    """
    response_data = await UserAuthService.login_user_numeric_id(db, numeric_id_login.numeric_customer_id, numeric_id_login.password)
    return LoginResponse(
        is_success=True,
        message="Login successful.",
        data=response_data
    )


@router.post("/login/otp/request", response_model=OtpStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def request_otp_login(otp_request: OtpLoginRequest, db: DBSession):
    """
    Requests an OTP for login.
    """
    response_data = await UserAuthService.initiate_otp_login(db, otp_request.email)
    return OtpStatusResponse(
        is_success=True,
        message="OTP sent to your email for login.",
        data=response_data
    )


@router.post("/login/otp/verify", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def verify_otp_login(otp_verify: OtpLoginVerify, db: DBSession, request: Request):
    """
    Verifies OTP for login and logs in the user.
    Redirects based on onboarding status.
    """
    response_data = await UserAuthService.verify_otp_login(db, otp_verify.email, otp_verify.otp_code)
    return LoginResponse(
        is_success=True,
        message="Login successful via OTP.",
        data=response_data
    )

# --- Password Management ---
@router.post("/password/forgot", response_model=UnifiedResponse, status_code=status.HTTP_200_OK)
async def forgot_password(forgot_request: ForgotPasswordRequest, db: DBSession):
    """
    Initiates the forgot password process by sending a reset link via email.
    """
    await UserAuthService.forgot_password(db, forgot_request.email)
    return UnifiedResponse(
        is_success=True,
        message="If an account with that email exists, a password reset link has been sent.",
        data={}
    )


@router.post("/password/reset", response_model=UnifiedResponse, status_code=status.HTTP_200_OK)
async def reset_password(reset_request: ResetPasswordRequest, db: DBSession):
    """
    Resets the user's password using a valid reset token.
    """
    await UserAuthService.reset_password(db, reset_request.token, reset_request.password)
    return UnifiedResponse(
        is_success=True,
        message="Password has been successfully reset.",
        data={}
    )


@router.post("/password/change", response_model=UnifiedResponse, status_code=status.HTTP_200_OK)
async def change_password(change_request: ChangePasswordRequest, db: DBSession):
    """
    Allows a logged-in user to change their password (requires old password).
    """
    await UserAuthService.change_password(db, change_request.email, change_request.old_password, change_request.password)
    return UnifiedResponse(
        is_success=True,
        message="Password has been successfully changed.",
        data={}
    )