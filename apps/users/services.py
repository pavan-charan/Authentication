import json
from datetime import datetime, timedelta, timezone # <--- IMPORT timezone
from typing import Optional, List
import secrets
import string
import logging

import bcrypt
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import ValidationError

from apps.users.crud import UserCRUD
from database.models import User, OtpVerification, OnboardingDetails, AccountStatus, PasswordResetToken, \
    TermsAcceptance, SocialMediaLink
from apps.users.schemas import UserCreate, UserCreateInitial, OnboardingDetailsCreate, UserLogin, Token, LoginResponse, \
    UserUpdate, TermsAcceptanceInput, SocialMediaLinkCreate, OnboardingVerifyResponse, UnifiedResponse
from utils.otp_handler import OTPHandler, OTP_EXPIRY_MINUTES
from config.settings import settings
from utils.email_sender import send_email

logger = logging.getLogger(__name__)

# Placeholder for JWT creation (will be implemented later or use a library)
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": int(expire.timestamp())}) # Convert to timestamp for JWT 'exp' claim
    return f"mock_jwt_token_for_{to_encode.get('sub')}_exp_{expire.isoformat()}"

class UserAuthService:
    @staticmethod
    async def initiate_signup_email_password(db: AsyncSession, email: str, password: str) -> dict:
        """
        New Step 1: User enters email, sets password.
        Creates a user record, then proceeds to send OTP.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if user:
                if user.is_verified:
                    logger.warning(f"Signup attempt for already verified email: {email}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Account with this email already exists and is verified. Please log in or reset password."
                    )
                elif user.status == AccountStatus.PENDING_VERIFICATION.value:
                    # If user exists but is pending, allow them to retry setting password
                    if user.password_hash:  # If password already set, just resend OTP
                        logger.info(f"Account {user.customer_id} exists and is pending, re-sending OTP.")
                        pass
                    else:  # If no password, update it
                        hashed_password = UserAuthService.hash_password(password)
                        await UserCRUD.update_user_password_no_commit(db, user, hashed_password)
                        logger.info(f"Password updated for pending user {user.customer_id}.")
                else:
                    logger.warning(f"Signup attempt for email {email} with unexpected status: {user.status}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="An account exists with this email with a different status. Please contact support."
                    )
            else:
                hashed_password = UserAuthService.hash_password(password)
                user_data = UserCreate(email=email, password_hash=hashed_password)
                user = await UserCRUD.create_user_no_commit(db, user_data)
                logger.info(f"New user staged for creation: Email: {email}")

            # Flush the session to get the customer_id for new users or update existing ones
            await db.flush()
            await db.refresh(user) # Refresh user object to get the assigned customer_id

            # Send OTP after password is set/updated and user object is fresh
            await OTPHandler.send_otp(db, user, "signup") # OTPHandler.send_otp commits its own record
            logger.info(f"OTP sent for signup to user {user.customer_id}.")

            # Store temporary data for OTP verification step
            await UserCRUD.create_signup_temp_data_no_commit(db, email,
                                                           json.dumps({"customer_id": str(user.customer_id), "password_set": True}),
                                                           user_customer_id=user.customer_id)
            logger.info(f"Signup temp data staged for {email}.")

            # Commit the entire transaction
            await db.commit()
            logger.info(f"Signup step 1 completed and committed for user {user.customer_id}.")

            return {
                "otp_sent": True,
                "customer_id": user.customer_id,
                "expires_in_minutes": OTP_EXPIRY_MINUTES
            }
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during signup initiation for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during signup initiation. Details: {e}"
            )

    @staticmethod
    async def verify_signup_otp(db: AsyncSession, email: str, otp_code: str) -> dict:
        """
        New Step 2: Verifies the OTP sent during signup.
        Updates user status to active and verified if successful.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user:
                logger.warning(f"OTP verification attempt for non-existent email: {email}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found or email mismatch."
                )

            if user.is_verified:
                logger.warning(f"OTP verification attempt for already verified user: {user.customer_id}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Account already verified. Please log in or proceed to terms acceptance."
                )

            temp_data_record = await UserCRUD.get_signup_temp_data(db, email)
            if not temp_data_record:
                logger.warning(f"OTP verification attempt without temp data for user: {user.customer_id}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Signup process not initiated or password not set. Please start from step 1."
                )
            try:
                temp_data = json.loads(temp_data_record.saved_data)
                if not temp_data.get("password_set") or str(user.customer_id) != temp_data.get("customer_id"):
                    logger.warning(f"OTP verification: Password not set or customer ID mismatch in temp data for user: {user.customer_id}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Password not set for this user. Please complete password setup step."
                    )
            except json.JSONDecodeError:
                logger.exception(f"Invalid temporary data format for user: {user.customer_id}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal error: Invalid temporary data format."
                )

            verified_otp = await OTPHandler.verify_otp(db, user.customer_id, otp_code) # This commits OTP record

            if not verified_otp:
                latest_otp = await UserCRUD.get_latest_otp_for_user(db, user.customer_id)
                # is_expired() method now correctly handles timezone-aware comparison
                if latest_otp and latest_otp.is_expired():
                    logger.warning(f"OTP verification failed for user {user.customer_id}: OTP expired")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="OTP expired. Please request a new OTP."
                    )
                else:
                    logger.warning(f"OTP verification failed for user {user.customer_id}: Invalid OTP")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid OTP. Please try again."
                    )

            await UserCRUD.update_user_verification_status_no_commit(db, user, True)
            await UserCRUD.update_user_status_no_commit(db, user, AccountStatus.ACTIVE)
            logger.info(f"User {user.customer_id} email verification and status update staged.")

            # Clear temporary data after OTP is verified - This operation commits itself.
            await UserCRUD.delete_signup_temp_data(db, email)
            logger.info(f"Signup temp data cleared for {email}.")

            # Commit the entire transaction
            await db.commit()
            await db.refresh(user) # Refresh user to get latest status after commit
            logger.info(f"Signup step 2 committed for user {user.customer_id}.")

            return {
                "customer_id": user.customer_id,
                "email": user.email,
                "is_verified": user.is_verified,
                "status": AccountStatus(user.status).value,
                "is_onboarded": user.is_onboarded
            }
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during OTP verification for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during OTP verification. Details: {e}"
            )

    @staticmethod
    async def accept_terms_and_conditions(db: AsyncSession, email: str, terms_version: str) -> dict:
        """
        Records the user's acceptance of terms and conditions.
        This step is required after password setup and OTP verification.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user:
                logger.warning(f"Terms acceptance attempt for non-existent email: {email}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found."
                )

            if not user.password_hash:
                logger.warning(f"Terms acceptance: Password not set for user {user.customer_id}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password not set for this account. Please complete password setup step."
                )

            if not user.is_verified:
                logger.warning(f"Terms acceptance: Email not verified for user {user.customer_id}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Email not verified. Please complete OTP verification step."
                )

            # Use the unified CRUD method for create/update, no commit here
            terms_acceptance = await UserCRUD.create_or_update_terms_acceptance_no_commit(db, user.customer_id, terms_version)
            logger.info(f"User {user.customer_id} terms acceptance staged for version {terms_version}.")

            # Commit the entire transaction
            await db.commit()
            await db.refresh(terms_acceptance) # Refresh to ensure latest accepted_at/updated_at
            logger.info(f"Terms acceptance committed for user {user.customer_id}.")

            return {
                "customer_id": user.customer_id,
                "email": user.email,
                "terms_accepted": True,
                "accepted_version": terms_acceptance.terms_version,
                "status": AccountStatus(user.status).value,
                "is_onboarded": user.is_onboarded,
                "numeric_customer_id": user.numeric_customer_id
            }
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during terms acceptance for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during terms acceptance. Details: {e}"
            )

    @staticmethod
    async def complete_signup_onboarding(
        db: AsyncSession, email: str, onboarding_data: OnboardingDetailsCreate
    ) -> dict:
        """
        Completes the signup process by adding onboarding details.
        Requires password to be set and terms to be accepted.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user:
                logger.warning(f"Onboarding attempt for non-existent email: {email}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found."
                )

            if not user.password_hash:
                logger.warning(f"Onboarding: Password not set for user {user.customer_id}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password not set for this account. Please complete password setup step."
                )

            if not user.is_verified:
                logger.warning(f"Onboarding: Email not verified for user {user.customer_id}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Email not verified. Please complete OTP verification step."
                )

            terms_accepted_record = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
            if not terms_accepted_record:
                logger.warning(f"Onboarding: Terms not accepted for user {user.customer_id}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Terms and conditions must be accepted before proceeding to onboarding."
                )

            onboarding_message = "Onboarding details saved successfully. Signup complete!"

            # Extract social media links from onboarding_data for separate handling
            social_links_data = onboarding_data.social_media_links
            onboarding_dict_for_model = onboarding_data.model_dump(exclude_unset=True)
            if "social_media_links" in onboarding_dict_for_model:
                del onboarding_dict_for_model["social_media_links"]

            existing_onboarding = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)

            if existing_onboarding:
                logger.info(f"Updating existing onboarding details for user {user.customer_id}.")
                await UserCRUD.update_onboarding_details_no_commit(db, existing_onboarding, onboarding_data)
                onboarding_message = "Onboarding details updated successfully. Signup complete!"

                # Handle social media links update: Delete existing, then add new ones
                if social_links_data is not None:
                    await UserCRUD.delete_social_media_links_by_user(db, user.customer_id) # This CRUD operation commits
                    logger.info(f"Deleted existing social media links for user {user.customer_id}.")

                    if social_links_data: # If there are new links to add
                        new_social_link_objects = [
                            SocialMediaLink(user_id=user.customer_id, platform=link_data.platform.value, url=str(link_data.url))
                            for link_data in social_links_data
                        ]
                        db.add_all(new_social_link_objects)
                        logger.info(f"Staged new social media links for user {user.customer_id}.")
            else:
                logger.info(f"Creating new onboarding details for user {user.customer_id}.")
                new_onboarding = await UserCRUD.create_onboarding_details_no_commit(db, user.customer_id, onboarding_data)

                # Create social media links for new onboarding
                if social_links_data:
                    new_social_link_objects = [
                        SocialMediaLink(user_id=user.customer_id, platform=link_data.platform.value, url=str(link_data.url))
                        for link_data in social_links_data
                    ]
                    db.add_all(new_social_link_objects)
                    logger.info(f"Staged initial social media links for user {user.customer_id}.")

            await UserCRUD.update_user_onboarding_status_no_commit(db, user, True)
            logger.info(f"User {user.customer_id} onboarding status staged to True.")

            # Commit the entire transaction
            await db.commit()
            await db.refresh(user)
            logger.info(f"Onboarding committed for user {user.customer_id}.")

            return {
                "message": onboarding_message,
                "customer_id": user.customer_id,
                "email": user.email,
                "status": AccountStatus(user.status).value,
                "is_onboarded": user.is_onboarded,
                "terms_accepted": True if terms_accepted_record else False,
                "numeric_customer_id": user.numeric_customer_id
            }
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during onboarding completion for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during onboarding completion. Details: {e}"
            )

    @staticmethod
    async def verify_onboarding_details(db: AsyncSession, email: str) -> dict:
        """
        Verifies onboarding details for a user and assigns a unique 10-digit numeric ID.
        This is typically an admin-level action.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user:
                logger.warning(f"Onboarding verification attempt for non-existent email: {email}")
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

            onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
            if not onboarding_details:
                logger.warning(f"Onboarding verification: Details not found for user {user.customer_id}")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="Onboarding details not found for this user.")

            if onboarding_details.verified:
                logger.info(f"Onboarding for user {user.customer_id} already verified.")
                return {
                    "message": "Onboarding already verified.",
                    "customer_id": user.customer_id,
                    "email": user.email,
                    "onboarding_verified": True,
                    "numeric_customer_id": user.numeric_customer_id
                }

            # Update onboarding details to verified
            await UserCRUD.update_onboarding_verified_status_no_commit(db, onboarding_details, True)
            logger.info(f"Onboarding for user {user.customer_id} marked as verified (staged).")

            # Generate unique 10-digit numeric ID
            numeric_id = await UserAuthService._generate_unique_numeric_id(db)
            await UserCRUD.assign_numeric_customer_id_no_commit(db, user, numeric_id)
            logger.info(f"User {user.customer_id} numeric ID assignment staged: {numeric_id}")

            # Commit the entire transaction
            await db.commit()
            await db.refresh(user)
            logger.info(f"Onboarding verification committed for user {user.customer_id}.")

            return {
                "message": "Onboarding details verified and numeric ID assigned successfully.",
                "customer_id": user.customer_id,
                "email": user.email,
                "onboarding_verified": True,
                "numeric_customer_id": user.numeric_customer_id
            }
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during onboarding verification for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during onboarding verification. Details: {e}"
            )

    @staticmethod
    async def _generate_unique_numeric_id(db: AsyncSession, length: int = 10) -> str:
        """Generates a unique 10-digit numeric ID."""
        for _ in range(10): # Limit retries to prevent infinite loop on extreme collision
            numeric_id = ''.join(secrets.choice(string.digits) for _ in range(length))
            existing_user = await UserCRUD.get_user_by_numeric_customer_id(db, numeric_id)
            if not existing_user:
                return numeric_id
        logger.critical("Failed to generate a unique numeric ID after multiple attempts.")
        raise RuntimeError("Could not generate a unique numeric ID. Please try again.")

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
    async def login_user_password(db: AsyncSession, email: str, password: str) -> dict:
        """
        Authenticates a user via email and password.
        Checks onboarding status for redirection.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user or not user.password_hash:
                logger.warning(f"Login attempt (password) failed for email {email}: Invalid credentials (user not found or no password hash).")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials."
                )

            if not UserAuthService.verify_password(password, user.password_hash):
                logger.warning(f"Login attempt (password) failed for user {user.customer_id}: Incorrect password.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials."
                )

            if not user.is_verified:
                logger.warning(f"Login attempt (password) failed for user {user.customer_id}: Account not verified.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account not verified. Please verify your email."
                )

            if user.status != AccountStatus.ACTIVE.value:
                logger.warning(f"Login attempt (password) failed for user {user.customer_id}: Account status {user.status}.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account is {user.status}. Please contact support."
                )

            terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
            if not terms_accepted:
                logger.warning(f"Login attempt (password) failed for user {user.customer_id}: Terms not accepted.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Terms and conditions must be accepted to log in. Please complete signup."
                )

            onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
            if not onboarding_details or not onboarding_details.verified:
                logger.warning(f"Login attempt (password) failed for user {user.customer_id}: Onboarding not verified.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Onboarding details not yet verified. Please wait for verification."
                )

            await UserCRUD.update_user_no_commit(db, user, UserUpdate(last_login_at=datetime.now(timezone.utc))) # <--- CHANGE HERE
            logger.info(f"User {user.customer_id} last login updated (staged).")

            await UserCRUD.create_login_history(db, user.customer_id, ip_address="127.0.0.1", user_agent="Postman/FastAPI") # This commits
            logger.info(f"Login history created for user {user.customer_id}.")

            await db.commit()
            await db.refresh(user)
            logger.info(f"User {user.customer_id} logged in successfully via password.")

            redirect_to = UserAuthService._get_redirect_path(user)

            return {
                "customer_id": user.customer_id,
                "email": user.email,
                "status": AccountStatus(user.status).value,
                "is_onboarded": user.is_onboarded,
                "redirect_to": redirect_to,
                "numeric_customer_id": user.numeric_customer_id
            }
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during password login for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during password login. Details: {e}"
            )

    @staticmethod
    async def initiate_otp_login(db: AsyncSession, email: str) -> dict:
        """
        Initiates login via OTP. Sends an OTP to the user's email.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user:
                logger.warning(f"OTP login request for non-existent email: {email}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found."
                )

            if not user.is_verified:
                logger.warning(f"OTP login request for user {user.customer_id}: Account not verified.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account not verified. Please verify your email."
                )

            if user.status != AccountStatus.ACTIVE.value:
                logger.warning(f"OTP login request for user {user.customer_id}: Account status {user.status}.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account is {user.status}. Please contact support."
                )

            terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
            if not terms_accepted:
                logger.warning(f"OTP login request for user {user.customer_id}: Terms not accepted.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Terms and conditions must be accepted to log in. Please complete signup."
                )

            onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
            if not onboarding_details or not onboarding_details.verified:
                logger.warning(f"OTP login request for user {user.customer_id}: Onboarding not verified.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Onboarding details not yet verified. Please wait for verification."
                )

            await OTPHandler.send_otp(db, user, "login")
            logger.info(f"OTP sent for login to user {user.customer_id}.")

            return {
                "otp_sent": True,
                "customer_id": user.customer_id,
                "expires_in_minutes": OTP_EXPIRY_MINUTES
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Failed to send OTP email for login to user {user.customer_id}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to send OTP email for login. Please try again later. Details: {e}"
            )

    @staticmethod
    async def verify_otp_login(db: AsyncSession, email: str, otp_code: str) -> dict:
        """
        Verifies OTP for login.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user:
                logger.warning(f"OTP login verification attempt for non-existent email: {email}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found or email mismatch."
                )

            verified_otp = await OTPHandler.verify_otp(db, user.customer_id, otp_code)

            if not verified_otp:
                latest_otp = await UserCRUD.get_latest_otp_for_user(db, user.customer_id)
                if latest_otp and latest_otp.is_expired():
                    logger.warning(f"OTP login verification failed for user {user.customer_id}: OTP expired.")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="OTP expired. Please request a new OTP."
                    )
                else:
                    logger.warning(f"OTP login verification failed for user {user.customer_id}: Invalid OTP.")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid OTP. Please try again."
                    )

            terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
            if not terms_accepted:
                logger.warning(f"OTP login verification failed for user {user.customer_id}: Terms not accepted.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Terms and conditions must be accepted to log in. Please complete signup."
                )

            onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
            if not onboarding_details or not onboarding_details.verified:
                logger.warning(f"OTP login verification failed for user {user.customer_id}: Onboarding not verified.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Onboarding details not yet verified. Please wait for verification."
                )

            await UserCRUD.update_user_no_commit(db, user, UserUpdate(last_login_at=datetime.now(timezone.utc))) # <--- CHANGE HERE
            logger.info(f"User {user.customer_id} last login updated (staged).")

            await UserCRUD.create_login_history(db, user.customer_id, ip_address="127.0.0.1", user_agent="Postman/FastAPI") # This commits
            logger.info(f"Login history created for user {user.customer_id}.")

            await db.commit()
            await db.refresh(user)
            logger.info(f"User {user.customer_id} logged in successfully via OTP.")

            redirect_to = UserAuthService._get_redirect_path(user)

            return {
                "customer_id": user.customer_id,
                "email": user.email,
                "status": AccountStatus(user.status).value,
                "is_onboarded": user.is_onboarded,
                "redirect_to": redirect_to,
                "numeric_customer_id": user.numeric_customer_id
            }
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during OTP login verification for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during OTP login verification. Details: {e}"
            )

    @staticmethod
    async def login_user_numeric_id(db: AsyncSession, numeric_customer_id: str, password: str) -> dict:
        """
        Authenticates a user via their numeric customer ID and password.
        Checks onboarding status for redirection.
        """
        user = await UserCRUD.get_user_by_numeric_customer_id(db, numeric_customer_id)

        try:
            if not user or not user.password_hash:
                logger.warning(f"Login attempt (numeric ID) failed for numeric_id {numeric_customer_id}: Invalid credentials (user not found or no password hash).")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials."
                )

            if not UserAuthService.verify_password(password, user.password_hash):
                logger.warning(f"Login attempt (numeric ID) failed for user {user.customer_id}: Incorrect password.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials."
                )

            if not user.is_verified:
                logger.warning(f"Login attempt (numeric ID) failed for user {user.customer_id}: Account not verified.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account not verified. Please verify your email."
                )

            if user.status != AccountStatus.ACTIVE.value:
                logger.warning(f"Login attempt (numeric ID) failed for user {user.customer_id}: Account status {user.status}.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account is {user.status}. Please contact support."
                )

            terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
            if not terms_accepted:
                logger.warning(f"Login attempt (numeric ID) failed for user {user.customer_id}: Terms not accepted.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Terms and conditions must be accepted to log in. Please complete signup."
                )

            onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
            if not onboarding_details or not onboarding_details.verified:
                logger.warning(f"Login attempt (numeric ID) failed for user {user.customer_id}: Onboarding not verified.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Onboarding details not yet verified. Please wait for verification."
                )

            await UserCRUD.update_user_no_commit(db, user, UserUpdate(last_login_at=datetime.now(timezone.utc))) # <--- CHANGE HERE
            logger.info(f"User {user.customer_id} last login updated (staged).")

            await UserCRUD.create_login_history(db, user.customer_id, ip_address="127.0.0.1", user_agent="Postman/FastAPI") # This commits
            logger.info(f"Login history created for user {user.customer_id}.")

            await db.commit()
            await db.refresh(user)
            logger.info(f"User {user.customer_id} logged in successfully via numeric ID.")

            redirect_to = UserAuthService._get_redirect_path(user)

            return {
                "customer_id": user.customer_id,
                "email": user.email,
                "status": AccountStatus(user.status).value,
                "is_onboarded": user.is_onboarded,
                "redirect_to": redirect_to,
                "numeric_customer_id": user.numeric_customer_id
            }
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during numeric ID login for {numeric_customer_id}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during numeric ID login. Details: {e}"
            )

    @staticmethod
    async def forgot_password(db: AsyncSession, email: str) -> None:
        """
        Initiates the forgot password flow by sending a reset token via email.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user:
                logger.info(f"Forgot password request for non-existent email: {email} (returning generic success).")
                return

            terms_accepted = await UserCRUD.get_terms_acceptance_by_user_id(db, user.customer_id)
            if not terms_accepted:
                logger.warning(f"Forgot password attempt for user {user.customer_id}: Terms not accepted.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot reset password for an account that has not accepted terms."
                )

            onboarding_details = await UserCRUD.get_onboarding_details_by_user_id(db, user.customer_id)
            if not onboarding_details or not onboarding_details.verified:
                logger.warning(f"Forgot password attempt for user {user.customer_id}: Onboarding not verified.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot reset password for an account with unverified onboarding details."
                )

            reset_token_value = secrets.token_urlsafe(32)
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1) # <--- CHANGE HERE

            await UserCRUD.create_password_reset_token(db, user.customer_id, reset_token_value, expires_at)
            logger.info(f"Password reset token created for user {user.customer_id}.")

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
                logger.info(f"Password reset email sent to {user.email}.")
            except Exception as e:
                logger.exception(f"Failed to send password reset email to {user.email}.")
                pass
        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"An unexpected error occurred during forgot password process for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during forgot password request. Details: {e}"
            )

    @staticmethod
    async def reset_password(db: AsyncSession, token: str, new_password: str) -> None:
        """
        Resets a user's password using a valid reset token.
        """
        try:
            reset_token_record = await UserCRUD.get_password_reset_token(db, token)

            if not reset_token_record:
                logger.warning(f"Password reset attempt with invalid/expired token: {token}.")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired password reset token."
                )

            user = await UserCRUD.get_user_by_customer_id(db, reset_token_record.user_id)

            if not user:
                logger.error(f"User associated with reset token {token} not found (customer_id: {reset_token_record.user_id}).")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User associated with this token not found."
                )

            hashed_password = UserAuthService.hash_password(new_password)
            await UserCRUD.update_user_password_no_commit(db, user, hashed_password)
            logger.info(f"User {user.customer_id} password update staged using token {token}.")

            await UserCRUD.invalidate_password_reset_token(db, reset_token_record)
            logger.info(f"Password reset token {token} invalidated.")

            await db.commit()
            await db.refresh(user)
            logger.info(f"Password reset successfully for user {user.customer_id}.")
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during password reset with token {token}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during password reset. Details: {e}"
            )

    @staticmethod
    async def change_password(db: AsyncSession, email: str, old_password: str, new_password: str) -> None:
        """
        Allows a logged-in user to change their password, requiring their old password.
        """
        user = await UserCRUD.get_user_by_email(db, email)

        try:
            if not user or not user.password_hash:
                logger.warning(f"Change password attempt for non-existent email {email} or no password set.")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found or password not set."
                )

            if not UserAuthService.verify_password(old_password, user.password_hash):
                logger.warning(f"Change password attempt for user {user.customer_id}: Incorrect old password.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect old password."
                )

            hashed_new_password = UserAuthService.hash_password(new_password)
            await UserCRUD.update_user_password_no_commit(db, user, hashed_new_password)
            logger.info(f"Password change staged for user {user.customer_id}.")

            await db.commit()
            await db.refresh(user)
            logger.info(f"Password changed successfully for user {user.customer_id}.")
        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            logger.exception(f"An unexpected error occurred during password change for {email}.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred during password change. Details: {e}"
            )