import os
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from supabase import create_client, Client
from dotenv import load_dotenv

from app.schemas.user_schema import UserRole
from app.utils.dependencies import get_refresh_token_for_user, store_new_tokens

load_dotenv()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/users/login")


client: Client = create_client(
    os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))


def get_client():
    return client


# def get_current_user(token: str = Depends(oauth2_scheme), supabase: Client = Depends(get_client)):
#     user = supabase.auth.get_user(token)

#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

#     company_data = supabase.table("companies").select(
#         "role", 'id').eq("id", user.user.id).single().execute()

#     user_data = supabase.table("users").select(
#         "role", 'id').eq("id", user.user.id).single().execute()

#     if not company_data:
#         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
#                             detail="Please create a profile")

#     return user_data.data if user_data.data else company_data.data

# async def get_current_user(token: str = Depends(oauth2_scheme), supabase: Client = Depends(get_client)) -> dict:
#     if not token:
#         return None  # Allow optional auth for public endpoints

#     # Validate token and get user from Supabase auth
#     auth_user = supabase.auth.get_user(token)
#     if not auth_user:
#         raise HTTPException(status_code=401, detail="Invalid token")

#     user_id = auth_user.user.id

#     # Fetch from users table (staff, guests)
#     user_data = supabase.table("users").select(
#         "id, role").eq("id", user_id).execute()

#     # Fetch from companies table (company users)
#     company_data = supabase.table("companies").select(
#         "id, role").eq("id", user_id).execute()

#     # Handle user type and return unified response
#     if user_data.data and len(user_data.data) > 0:
#         # Staff or guest user
#         return {
#             "id": user_data.data[0]["id"],
#             "role": user_data.data[0]["role"],

#         }
#     elif company_data.data and len(company_data.data) > 0:
#         # Company user
#         return {
#             "id": company_data.data[0]["id"],
#             "role": company_data.data[0]["role"],

#         }
#     else:
#         raise HTTPException(
#             status_code=404, detail="User not found in users or companies table")

def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    supabase: Client = Depends(get_client)
) -> dict:
    if not token:
        return None  # Allow optional auth for public endpoints

    try:
        # Try to validate token and get user from Supabase auth
        auth_user = supabase.auth.get_user(token)
        user_id = auth_user.user.id
    except Exception as e:
        # Token might be expired, try to refresh it
        try:
            # Get the refresh token from Redis
            refresh_token = get_refresh_token_for_user(token)

            if not refresh_token:
                raise HTTPException(
                    status_code=401, detail="Session expired. Please log in again.")

            # Refresh the session
            refresh_response = supabase.auth.refresh_session(refresh_token)

            if refresh_response.error:
                raise HTTPException(
                    status_code=401, detail="Unable to refresh session. Please log in again.")

            # Get user with the new token
            auth_user = supabase.auth.get_user(
                refresh_response.session.access_token)
            user_id = auth_user.user.id

            # Store the new tokens in Redis
            store_new_tokens(
                user_id,
                refresh_response.session.access_token,
                refresh_response.session.refresh_token,
                refresh_response.session.expires_in
            )

            # Set token to the new access token to continue with the request
            token = refresh_response.session.access_token

            # Set a header to inform the client about the new token
            request.state.new_access_token = refresh_response.session.access_token

        except Exception as refresh_error:
            raise HTTPException(
                status_code=401, detail="Invalid token and unable to refresh session")

    # Fetch from users table (staff, guests)
    user_data = supabase.table("users").select(
        "id, role").eq("id", user_id).execute()

    # Fetch from companies table (company users)
    company_data = supabase.table("companies").select(
        "id, role").eq("id", user_id).execute()

    # Handle user type and return unified response
    if user_data.data and len(user_data.data) > 0:
        # Staff or guest user
        return {
            "id": user_data.data[0]["id"],
            "role": user_data.data[0]["role"],
        }
    elif company_data.data and len(company_data.data) > 0:
        # Company user
        return {
            "id": company_data.data[0]["id"],
            "role": company_data.data[0]["role"],
        }
    else:
        raise HTTPException(
            status_code=404, detail="User not found in users or companies table")


def get_company_user(user: dict = Depends(get_current_user)):

    if user["role"] != UserRole.COMPANY:
        raise HTTPException(
            status_code=403, detail="Only company users allowed")
    return user
