import json
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import User, OtpVerification, OnboardingDetails, SignupTempData, AccountStatus, PasswordResetToken, LoginHistory, TermsAcceptance, SocialMediaLink
from apps.users.schemas import UserCreate, OnboardingDetailsCreate, UserUpdate, TermsAcceptanceInput, SocialMediaLinkCreate


class UserCRUD:
    @staticmethod
    async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
        """Fetches a user by their email address."""
        result = await db.execute(select(User).where(User.email == email))
        return result.scalars().first()

    @staticmethod
    async def get_user_by_customer_id(db: AsyncSession, customer_id: str) -> Optional[User]:
        """Fetches a user by their customer ID."""
        result = await db.execute(select(User).where(User.customer_id == customer_id))
        return result.scalars().first()

    @staticmethod
    async def get_user_by_numeric_customer_id(db: AsyncSession, numeric_customer_id: str) -> Optional[User]:
        """Fetches a user by their unique 10-digit numeric customer ID."""
        result = await db.execute(select(User).where(User.numeric_customer_id == numeric_customer_id))
        return result.scalars().first()

    @staticmethod
    async def create_user(db: AsyncSession, user_data: UserCreate) -> User:
        """Creates a new user record."""
        new_user = User(
            email=user_data.email,
            password_hash=user_data.password_hash,
            status=AccountStatus.PENDING_VERIFICATION.value,
            is_verified=False,
            is_onboarded=False
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        return new_user

    @staticmethod
    async def update_user(db: AsyncSession, user: User, user_update: UserUpdate) -> User:
        """Updates an existing user record."""
        for field, value in user_update.model_dump(exclude_unset=True).items():
            if field == 'status' and isinstance(value, AccountStatus):
                setattr(user, field, value.value)
            else:
                setattr(user, field, value)
        user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def update_user_verification_status(db: AsyncSession, user: User, is_verified: bool) -> User:
        """Updates a user's email verification status."""
        user.is_verified = is_verified
        user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def update_user_status(db: AsyncSession, user: User, status: AccountStatus) -> User:
        """Updates a user's account status (e.g., active, suspended)."""
        user.status = status.value
        user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def update_user_password(db: AsyncSession, user: User, password_hash: str) -> User:
        """Updates a user's password hash."""
        user.password_hash = password_hash
        user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def update_user_onboarding_status(db: AsyncSession, user: User, is_onboarded: bool) -> User:
        """Updates a user's onboarding completion status."""
        user.is_onboarded = is_onboarded
        user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)
        return user

    # OTP Verification CRUD
    @staticmethod
    async def get_latest_otp_for_user(db: AsyncSession, user_customer_id: str) -> Optional[OtpVerification]:
        """Fetches the latest OTP record for a given user."""
        result = await db.execute(
            select(OtpVerification)
            .where(OtpVerification.user_id == user_customer_id)
            .order_by(OtpVerification.created_at.desc())
            .limit(1)
        )
        return result.scalars().first()

    @staticmethod
    async def get_onboarding_details_by_user_id(db: AsyncSession, user_customer_id: str) -> Optional[OnboardingDetails]:
        """Fetches onboarding details for a given user ID."""
        result = await db.execute(select(OnboardingDetails).where(OnboardingDetails.user_id == user_customer_id))
        return result.scalars().first()

    @staticmethod
    async def create_onboarding_details(db: AsyncSession, user_customer_id: str, onboarding_data: OnboardingDetailsCreate) -> OnboardingDetails:
        """Creates onboarding details for a user."""
        onboarding_dict = onboarding_data.model_dump(exclude_unset=True)
        social_links_data = onboarding_dict.pop("social_media_links", [])

        new_onboarding = OnboardingDetails(user_id=user_customer_id, **onboarding_dict)
        db.add(new_onboarding)
        await db.commit()
        await db.refresh(new_onboarding)

        if social_links_data:
            for link_data in social_links_data:
                await UserCRUD.create_social_media_link(db, user_customer_id, link_data)

        return new_onboarding

    # Update Onboarding Details Verified Status
    @staticmethod
    async def update_onboarding_verified_status(db: AsyncSession, onboarding_details: OnboardingDetails, verified: bool) -> OnboardingDetails:
        """Updates the verified status of onboarding details."""
        onboarding_details.verified = verified
        onboarding_details.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(onboarding_details)
        return onboarding_details

    # Assign Numeric Customer ID
    @staticmethod
    async def assign_numeric_customer_id(db: AsyncSession, user: User, numeric_id: str) -> User:
        """Assigns a unique 10-digit numeric customer ID to a user."""
        user.numeric_customer_id = numeric_id
        user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)
        return user

    # Signup Temporary Data CRUD
    @staticmethod
    async def get_signup_temp_data(db: AsyncSession, email: str) -> Optional[SignupTempData]:
        """Fetches temporary signup data by email."""
        result = await db.execute(select(SignupTempData).where(SignupTempData.email == email))
        return result.scalars().first()

    @staticmethod
    async def create_signup_temp_data(db: AsyncSession, email: str, saved_data: str, user_customer_id: Optional[str] = None) -> SignupTempData:
        """Creates or updates temporary signup data."""
        temp_data = await UserCRUD.get_signup_temp_data(db, email)
        if temp_data:
            temp_data.saved_data = saved_data
            temp_data.updated_at = datetime.utcnow()
            if user_customer_id:
                temp_data.user_id = user_customer_id
        else:
            temp_data = SignupTempData(email=email, saved_data=saved_data, user_id=user_customer_id)
            db.add(temp_data)
        await db.commit()
        await db.refresh(temp_data)
        return temp_data

    @staticmethod
    async def delete_signup_temp_data(db: AsyncSession, email: str):
        """Deletes temporary signup data by email."""
        temp_data = await UserCRUD.get_signup_temp_data(db, email)
        if temp_data:
            await db.delete(temp_data)
            await db.commit()

    # Password Reset Token CRUD
    @staticmethod
    async def create_password_reset_token(db: AsyncSession, user_customer_id: str, token: str, expires_at: datetime) -> PasswordResetToken:
        """Creates a new password reset token for a user."""
        new_token = PasswordResetToken(
            user_id=user_customer_id,
            token=token,
            is_used=False,
            expires_at=expires_at
        )
        db.add(new_token)
        await db.commit()
        await db.refresh(new_token)
        return new_token

    @staticmethod
    async def get_password_reset_token(db: AsyncSession, token: str) -> Optional[PasswordResetToken]:
        """Fetches a password reset token by its value."""
        result = await db.execute(
            select(PasswordResetToken)
            .where(
                PasswordResetToken.token == token,
                PasswordResetToken.is_used == False,
                PasswordResetToken.expires_at > datetime.utcnow()
            )
        )
        return result.scalars().first()

    @staticmethod
    async def invalidate_password_reset_token(db: AsyncSession, reset_token: PasswordResetToken) -> PasswordResetToken:
        """Marks a password reset token as used."""
        reset_token.is_used = True
        reset_token.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(reset_token)
        return reset_token

    # Login History CRUD
    @staticmethod
    async def create_login_history(db: AsyncSession, user_customer_id: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> LoginHistory:
        """Records a user's login event."""
        new_login_record = LoginHistory(
            user_id=user_customer_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.add(new_login_record)
        await db.commit()
        await db.refresh(new_login_record)
        return new_login_record

    # Terms Acceptance CRUD
    @staticmethod
    async def create_terms_acceptance(db: AsyncSession, user_customer_id: str, terms_version: str) -> TermsAcceptance:
        """Records a user's acceptance of terms and conditions."""
        existing_terms = await UserCRUD.get_terms_acceptance_by_user_id(db, user_customer_id)
        if existing_terms:
            existing_terms.terms_version = terms_version
            existing_terms.accepted_at = datetime.utcnow()
            existing_terms.updated_at = datetime.utcnow()
            await db.commit()
            await db.refresh(existing_terms)
            return existing_terms
        else:
            new_terms = TermsAcceptance(
                user_id=user_customer_id,
                terms_version=terms_version,
                accepted_at=datetime.utcnow()
            )
            db.add(new_terms)
            await db.commit()
            await db.refresh(new_terms)
            return new_terms

    @staticmethod
    async def get_terms_acceptance_by_user_id(db: AsyncSession, user_customer_id: str) -> Optional[TermsAcceptance]:
        """Fetches a user's terms acceptance record."""
        result = await db.execute(select(TermsAcceptance).where(TermsAcceptance.user_id == user_customer_id))
        return result.scalars().first()

    # Social Media Link CRUD
    @staticmethod
    async def create_social_media_link(db: AsyncSession, user_customer_id: str, link_data: SocialMediaLinkCreate) -> SocialMediaLink:
        """Creates a new social media link for a user."""
        new_link = SocialMediaLink(
            user_id=user_customer_id,
            platform=link_data.platform.value,
            url=str(link_data.url)
        )
        db.add(new_link)
        await db.commit()
        await db.refresh(new_link)
        return new_link

    @staticmethod
    async def get_social_media_links_by_user_id(db: AsyncSession, user_customer_id: str) -> List[SocialMediaLink]:
        """Fetches all social media links for a user."""
        result = await db.execute(select(SocialMediaLink).where(SocialMediaLink.user_id == user_customer_id))
        return list(result.scalars().all())
