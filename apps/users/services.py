import json
from datetime import datetime, timedelta
from typing import Optional, List
import secrets
import string

import bcrypt
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.users.crud import UserCRUD
from database.models import User, OtpVerification, OnboardingDetails, AccountStatus, PasswordResetToken, \
    TermsAcceptance
from apps.users.schemas import UserCreate, UserCreateInitial, OnboardingDetailsCreate, UserLogin, Token, LoginResponse, \
    UserUpdate, TermsAcceptanceInput, SocialMediaLinkCreate, OnboardingVerifyResponse
from utils.otp_handler import OTPHandler, OTP_EXPIRY_MINUTES
from config.settings import settings
from utils.email_sender import send_email


# Placeholder for JWT creation (will be implemented later or use a library)
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    # This is a placeholder. In a real app, you'd use a JWT library like `python-jose` or `PyJWT`.
    # For now, we'll just return a simple string representation.
    # return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return f"mock_jwt_token_for_{to_encode.get('sub')}_exp_{expire.isoformat()}"


class UserAuthService:
    @staticmethod
    async def initiate_signup_email_password(db: AsyncSession, email: str, password: str) -> dict:
        """
        New Step 1: User enters email, sets password.
        Creates a user record, then proceeds to send OTP.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if user:
            if user.is_verified:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Account with this email already exists and is verified. Please log in or reset password."
                )
            elif user.status == AccountStatus.PENDING_VERIFICATION.value:
                # If user exists but is pending, allow them to retry setting password
                if user.password_hash:  # If password already set, just resend OTP
                    try:
                        await OTPHandler.send_otp(db, user, "signup")
                    except (ValueError, ConnectionRefusedError, RuntimeError) as e:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to resend OTP email. Please check server logs and SMTP settings. Error: {e}"
                        )
                    return {
                        "message": "Account already exists, OTP re-sent for verification.",
                        "otp_sent": True,
                        "customer_id": user.customer_id,
                        "expires_in_minutes": OTP_EXPIRY_MINUTES
                    }
                else:  # If no password, update it
                    hashed_password = UserAuthService.hash_password(password)
                    user = await UserCRUD.update_user_password(db, user, hashed_password)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="An account exists with this email with a different status. Please contact support."
                )
        else:
            hashed_password = UserAuthService.hash_password(password)
            user_data = UserCreate(email=email, password_hash=hashed_password)
            user = await UserCRUD.create_user(db, user_data)

        # Send OTP after password is set/updated
        try:
            await OTPHandler.send_otp(db, user, "signup")
        except (ValueError, ConnectionRefusedError, RuntimeError) as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to send OTP email. Please check server logs and SMTP settings. Error: {e}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during OTP generation/sending: {e}"
            )

        # Store temporary data for OTP verification step
        await UserCRUD.create_signup_temp_data(db, email,
                                               json.dumps({"customer_id": str(user.customer_id), "password_set": True}),
                                               user_customer_id=user.customer_id)

        return {
            "message": "Account created and OTP sent to your email. Please verify to proceed.",
            "otp_sent": True,
            "customer_id": user.customer_id,
            "expires_in_minutes": OTP_EXPIRY_MINUTES
        }

    @staticmethod
    async def verify_signup_otp(db: AsyncSession, email: str, otp_code: str) -> dict:
        """
        New Step 2: Verifies the OTP sent during signup.
        Updates user status to active and verified if successful.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or email mismatch."
            )

        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account already verified. Please log in or proceed to terms acceptance."
            )

        # Check temporary data to ensure password was set
        temp_data_record = await UserCRUD.get_signup_temp_data(db, email)
        if not temp_data_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signup process not initiated or password not set. Please start from step 1."
            )
        try:
            temp_data = json.loads(temp_data_record.saved_data)
            if not temp_data.get("password_set") or str(user.customer_id) != temp_data.get("customer_id"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password not set for this user. Please complete password setup step."
                )
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal error: Invalid temporary data format."
            )

        verified_otp = await OTPHandler.verify_otp(db, user.customer_id, otp_code)

        if not verified_otp:
            latest_otp = await UserCRUD.get_latest_otp_for_user(db, user.customer_id)
            if latest_otp and latest_otp.is_expired():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="OTP expired. Please request a new OTP."
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid OTP. Please try again."
                )

        user = await UserCRUD.update_user_verification_status(db, user, True)
        user = await UserCRUD.update_user_status(db, user, AccountStatus.ACTIVE)

        # Clear temporary data after OTP is verified
        await UserCRUD.delete_signup_temp_data(db, email)

        return {
            "message": "Email verified successfully. You can now proceed to terms acceptance.",
            "customer_id": user.customer_id,
            "email": user.email,
            "is_verified": user.is_verified,
            "status": AccountStatus(user.status),  # Added for response
            "is_onboarded": user.is_onboarded  # Added for response
        }

    @staticmethod
    async def accept_terms_and_conditions(db: AsyncSession, email: str, terms_version: str) -> dict:
        """
        Records the user's acceptance of terms and conditions.
        This step is required after password setup and OTP verification.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        if not user.password_hash:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password not set for this account. Please complete password setup step."
            )

        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified. Please complete OTP verification step."
            )

        terms_accepted_record = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
        if terms_accepted_record and terms_accepted_record.terms_version == terms_version:
            return {
                "message": f"Terms version {terms_version} already accepted.",
                "customer_id": user.customer_id,
                "email": user.email,
                "terms_accepted": True,
                "accepted_version": terms_accepted_record.terms_version,
                "status": AccountStatus(user.status),
                "is_onboarded": user.is_onboarded,
                "numeric_customer_id": user.numeric_customer_id  # Added for response
            }

        await UserCRUD.create_terms_acceptance(db, user.customer_id, terms_version)

        return {
            "message": "Terms and conditions accepted successfully. Proceed to onboarding.",
            "customer_id": user.customer_id,
            "email": user.email,
            "terms_accepted": True,
            "accepted_version": terms_version,
            "status": AccountStatus(user.status),
            "is_onboarded": user.is_onboarded,
            "numeric_customer_id": user.numeric_customer_id  # Added for response
        }

    @staticmethod
    async def complete_signup_onboarding(
        db: AsyncSession, email: str, onboarding_data: OnboardingDetailsCreate
    ) -> dict:
        """
        Completes the signup process by adding onboarding details.
        Requires password to be set and terms to be accepted.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        if not user.password_hash:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password not set for this account. Please complete password setup step."
            )

        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email not verified. Please complete OTP verification step."
            )

        terms_accepted_record = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
        if not terms_accepted_record:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Terms and conditions must be accepted before proceeding to onboarding."
            )

        if user.is_onboarded:
            existing_onboarding = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
            if existing_onboarding:
                onboarding_dict = onboarding_data.model_dump(exclude_unset=True)
                social_links_data = onboarding_dict.pop("social_media_links", [])

                for key, value in onboarding_dict.items():
                    setattr(existing_onboarding, key, value)
                existing_onboarding.updated_at = datetime.utcnow()
                await db.commit()
                await db.refresh(existing_onboarding)

                if social_links_data:
                    for link_data in social_links_data:
                        await UserCRUD.create_social_media_link(db, user.customer_id, SocialMediaLinkCreate(
                            **link_data.model_dump()))  # Ensure it's a model

                return {
                    "message": "Onboarding details updated successfully. Signup complete!",
                    "customer_id": user.customer_id,
                    "email": user.email,
                    "status": AccountStatus(user.status),
                    "is_onboarded": user.is_onboarded,
                    "terms_accepted": True,
                    "numeric_customer_id": user.numeric_customer_id  # Added for response
                }

        # Original flow for creating new onboarding details
        social_links_data = onboarding_data.social_media_links  # This is already a list of SocialMediaLinkCreate objects

        # Create a dictionary from onboarding_data excluding social_media_links for model creation
        onboarding_dict_for_model = onboarding_data.model_dump(exclude_unset=True)
        if "social_media_links" in onboarding_dict_for_model:
            del onboarding_dict_for_model["social_media_links"]

        new_onboarding = OnboardingDetails(user_id=user.customer_id, **onboarding_dict_for_model)
        db.add(new_onboarding)
        await db.commit()
        await db.refresh(new_onboarding)

        # Create social media links using the Pydantic models directly
        if social_links_data:
            for link_data in social_links_data:
                await UserCRUD.create_social_media_link(db, user.customer_id, link_data)

        user = await UserCRUD.update_user_onboarding_status(db, user, True)

        return {
            "message": "Signup complete! Welcome to the onboarding page.",
            "customer_id": user.customer_id,
            "email": user.email,
            "status": AccountStatus(user.status),
            "is_onboarded": user.is_onboarded,
            "terms_accepted": True,
            "numeric_customer_id": user.numeric_customer_id  # Added for response
        }

    @staticmethod
    async def verify_onboarding_details(db: AsyncSession, email: str) -> OnboardingVerifyResponse:
        """
        Verifies onboarding details for a user and assigns a unique 10-digit numeric ID.
        This is typically an admin-level action.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
        if not onboarding_details:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Onboarding details not found for this user.")

        if onboarding_details.verified:
            return OnboardingVerifyResponse(
                message="Onboarding already verified.",
                customer_id=user.customer_id,
                email=user.email,
                onboarding_verified=True,
                numeric_customer_id=user.numeric_customer_id
            )

        # Update onboarding details to verified
        await UserCRUD.update_onboarding_verified_status(db, onboarding_details, True)

        # Generate unique 10-digit numeric ID
        numeric_id = await UserAuthService._generate_unique_numeric_id(db)
        user = await UserCRUD.assign_numeric_customer_id(db, user, numeric_id)  # User object is updated here

        # Refresh the user object to get the newly assigned numeric_customer_id
        await db.refresh(user)  # <--- ADDED: Refresh user object

        return OnboardingVerifyResponse(
            message="Onboarding details verified and numeric ID assigned successfully.",
            customer_id=user.customer_id,
            email=user.email,
            onboarding_verified=True,
            numeric_customer_id=user.numeric_customer_id
        )

    @staticmethod
    async def _generate_unique_numeric_id(db: AsyncSession, length: int = 10) -> str:
        """Generates a unique 10-digit numeric ID."""
        while True:
            numeric_id = ''.join(secrets.choice(string.digits) for _ in range(length))
            existing_user = await UserCRUD.get_user_by_numeric_customer_id(db, numeric_id)
            if not existing_user:
                return numeric_id

    @staticmethod
    def hash_password(password: str) -> str:
        """Hashes a password using bcrypt."""
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verifies a plain password against a hashed password."""
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

    @staticmethod
    def _get_redirect_path(user: User) -> str:
        """Determines the redirection path based on user's onboarding status."""
        if user.is_onboarded:
            return "/home"
        else:
            return "/onboarding"

    @staticmethod
    async def login_user_password(db: AsyncSession, email: str, password: str) -> LoginResponse:
        """
        Authenticates a user via email and password.
        Checks onboarding status for redirection.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user or not user.password_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials."
            )

        if not UserAuthService.verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials."
            )

        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account not verified. Please verify your email."
            )

        if user.status != AccountStatus.ACTIVE.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is {user.status}. Please contact support."
            )

        terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
        if not terms_accepted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Terms and conditions must be accepted to log in. Please complete signup."
            )

        onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
        if not onboarding_details or not onboarding_details.verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Onboarding details not yet verified. Please wait for verification."
            )

        await UserCRUD.update_user(db, user, UserUpdate(last_login_at=datetime.utcnow()))
        await UserCRUD.create_login_history(db, user.customer_id, ip_address="127.0.0.1", user_agent="Postman/FastAPI")

        redirect_to = UserAuthService._get_redirect_path(user)

        return LoginResponse(
            message="Login successful.",
            customer_id=user.customer_id,
            email=user.email,
            status=AccountStatus(user.status),
            is_onboarded=user.is_onboarded,
            redirect_to=redirect_to,
            numeric_customer_id=user.numeric_customer_id
        )

    @staticmethod
    async def initiate_otp_login(db: AsyncSession, email: str) -> dict:
        """
        Initiates login via OTP. Sends an OTP to the user's email.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account not verified. Please verify your email."
            )

        if user.status != AccountStatus.ACTIVE.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is {user.status}. Please contact support."
            )

        terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
        if not terms_accepted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Terms and conditions must be accepted to log in. Please complete signup."
            )

        onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
        if not onboarding_details or not onboarding_details.verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Onboarding details not yet verified. Please wait for verification."
            )

        try:
            await OTPHandler.send_otp(db, user, "login")
        except (ValueError, ConnectionRefusedError, RuntimeError) as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to send OTP email for login. Error: {e}"
            )
        except Exception as e:
            print(f"ERROR: Failed to send OTP email for login. Error: {e}")
            pass

        return {
            "message": "OTP sent to your email for login.",
            "otp_sent": True,
            "customer_id": user.customer_id,
            "expires_in_minutes": OTP_EXPIRY_MINUTES
        }

    @staticmethod
    async def verify_otp_login(db: AsyncSession, email: str, otp_code: str) -> LoginResponse:
        """
        Verifies OTP for login.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or email mismatch."
            )

        verified_otp = await OTPHandler.verify_otp(db, user.customer_id, otp_code)

        if not verified_otp:
            latest_otp = await UserCRUD.get_latest_otp_for_user(db, user.customer_id)
            if latest_otp and latest_otp.is_expired():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="OTP expired. Please request a new OTP."
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid OTP. Please try again."
                )

        terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
        if not terms_accepted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Terms and conditions must be accepted to log in. Please complete signup."
            )

        onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
        if not onboarding_details or not onboarding_details.verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Onboarding details not yet verified. Please wait for verification."
            )

        await UserCRUD.update_user(db, user, UserUpdate(last_login_at=datetime.utcnow()))
        await UserCRUD.create_login_history(db, user.customer_id, ip_address="127.0.0.1", user_agent="Postman/FastAPI")

        redirect_to = UserAuthService._get_redirect_path(user)

        return LoginResponse(
            message="Login successful via OTP.",
            customer_id=user.customer_id,
            email=user.email,
            status=AccountStatus(user.status),
            is_onboarded=user.is_onboarded,
            redirect_to=redirect_to,
            numeric_customer_id=user.numeric_customer_id
        )

    @staticmethod
    async def login_user_numeric_id(db: AsyncSession, numeric_customer_id: str, password: str) -> LoginResponse:
        """
        Authenticates a user via their numeric customer ID and password.
        Checks onboarding status for redirection.
        """
        user = await UserCRUD.get_user_by_numeric_customer_id(db, numeric_customer_id)

        if not user or not user.password_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials."
            )

        if not UserAuthService.verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials."
            )

        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account not verified. Please verify your email."
            )

        if user.status != AccountStatus.ACTIVE.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is {user.status}. Please contact support."
            )

        terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
        if not terms_accepted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Terms and conditions must be accepted to log in. Please complete signup."
            )

        onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
        if not onboarding_details or not onboarding_details.verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Onboarding details not yet verified. Please wait for verification."
            )

        await UserCRUD.update_user(db, user, UserUpdate(last_login_at=datetime.utcnow()))
        await UserCRUD.create_login_history(db, user.customer_id, ip_address="127.0.0.1", user_agent="Postman/FastAPI")

        redirect_to = UserAuthService._get_redirect_path(user)

        return LoginResponse(
            message="Login successful.",
            customer_id=user.customer_id,
            email=user.email,
            status=AccountStatus(user.status),
            is_onboarded=user.is_onboarded,
            redirect_to=redirect_to,
            numeric_customer_id=user.numeric_customer_id
        )

    @staticmethod
    async def forgot_password(db: AsyncSession, email: str) -> dict:
        """
        Initiates the forgot password flow by sending a reset token via email.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user:
            return {"message": "If an account with that email exists, a password reset link has been sent."}

        terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
        if not terms_accepted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot reset password for an account that has not accepted terms."
            )

        onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
        if not onboarding_details or not onboarding_details.verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot reset password for an account with unverified onboarding details."
            )

        reset_token_value = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)

        await UserCRUD.create_password_reset_token(db, user.customer_id, reset_token_value, expires_at)

        reset_link = f"http://your-frontend-domain/reset-password?token={reset_token_value}"
        email_body = f"""
        <html>
        <body>
            <p>Dear {user.email},</p>
            <p>You have requested to reset your password for your {settings.PROJECT_NAME} account.</p>
            <p>Please click on the following link to reset your password:</p>
            <p><a href="{reset_link}">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you did not request a password reset, please ignore this email.</p>
            <p>Thanks,</p>
            <p>The {settings.PROJECT_NAME} Team</p>
        </body>
        </html>
        """
        try:
            await send_email(
                recipient_email=user.email,
                subject="Password Reset Request for Your Account",
                body=email_body
            )
        except Exception as e:
            print(f"ERROR: Failed to send password reset email to {user.email}: {e}")
            pass

        return {"message": "If an account with that email exists, a password reset link has been sent."}

    @staticmethod
    async def reset_password(db: AsyncSession, token: str, new_password: str) -> dict:
        """
        Resets a user's password using a valid reset token.
        """
        reset_token_record = await UserCRUD.get_password_reset_token(db, token)

        if not reset_token_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired password reset token."
            )

        user = await UserCRUD.get_user_by_customer_id(db, reset_token_record.user_id)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User associated with this token not found."
            )

        hashed_password = UserAuthService.hash_password(new_password)
        await UserCRUD.update_user_password(db, user, hashed_password)
        await UserCRUD.invalidate_password_reset_token(db, reset_token_record)

        return {"message": "Password has been successfully reset."}

    @staticmethod
    async def change_password(db: AsyncSession, email: str, old_password: str, new_password: str) -> dict:
        """
        Allows a logged-in user to change their password, requiring their old password.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        if not user or not user.password_hash:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found or password not set."
            )

        if not UserAuthService.verify_password(old_password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect old password."
            )

        hashed_new_password = UserAuthService.hash_password(new_password)
        await UserCRUD.update_user_password(db, user, hashed_new_password)

        return {"message": "Password has been successfully changed."}
