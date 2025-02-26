
import json
from typing import List, Dict
from fastapi import HTTPException
import redis
from supabase import Client
import uuid
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from supabase import AuthApiError, Client

from app.utils.dependencies import REDIS_PREFIX, remove_tokens, store_tokens
from ..schemas.user_schema import (
    CompanyResponse, GroupPermissionResponse,
    GuestResponse, NoPostResponse, OutletResponse, PermissionAction,
    PermissionGroupResponse,
    PermissionResource, QRCodeResponse,
    RolePermissionResponse, StaffCreate, StaffResponse,
    UserCreate, NoPostCreate,
    OutletCreate, QRCodeCreate,
    PermissionGroupCreate,
    RolePermissionCreate,
    UserRole
)

staff_role = [UserRole.CHEF, UserRole.MANAGER,
              UserRole.WAITER, UserRole.LAUNDRY]

# Initialize Redis client
redis_client = redis.Redis(host='localhost', port=6379, db=0)


def assign_role_permissions_to_user(supabase: Client, user_id: uuid.UUID, role: UserRole) -> None:
    """
    Assign default permissions to a user based on their role upon creation.
    Used for initial creation of super-admin, company, and guest users.
    """
    # Define permission mappings based on role
    permission_mappings: Dict[UserRole, List[tuple[PermissionResource, List[PermissionAction]]]] = {
        UserRole.SUPER_ADMIN: [
            (PermissionResource.ORDER, [
             PermissionAction.CREATE, PermissionAction.READ, PermissionAction.UPDATE, PermissionAction.DELETE]),
            (PermissionResource.ITEM, [
             PermissionAction.CREATE, PermissionAction.READ]),
            (PermissionResource.STOCK, [
             PermissionAction.CREATE, PermissionAction.READ]),
            (PermissionResource.PAYMENT, [PermissionAction.READ]),
        ],
        UserRole.COMPANY: [
            # Company users manage their resources
            (PermissionResource.ORDER, [
             PermissionAction.READ, PermissionAction.UPDATE]),
            (PermissionResource.ITEM, [
             PermissionAction.CREATE, PermissionAction.READ, PermissionAction.UPDATE, PermissionAction.DELETE]),
            (PermissionResource.STOCK, [
             PermissionAction.CREATE, PermissionAction.READ, PermissionAction.UPDATE, PermissionAction.DELETE]),
            (PermissionResource.PAYMENT, [PermissionAction.READ]),
        ],
        UserRole.GUEST: [
            # Guests have limited permissions
            (PermissionResource.ORDER, [
             PermissionAction.CREATE, PermissionAction.READ, PermissionAction.UPDATE]),
            (PermissionResource.ITEM, [PermissionAction.READ]),
            (PermissionResource.PAYMENT, [PermissionAction.READ])
        ],

    }

    # Get permissions for the specified role
    role_perms = permission_mappings.get(role, [])

    # Insert permissions into role_permissions table
    for resource, actions in role_perms:
        perm_data = {
            "user_id": user_id,
            "resource": resource.value,
            "action": [action.value for action in actions],
        }
        try:
            supabase.table("role_permissions").insert(perm_data).execute()

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to assign permissions: {str(e)}")


def get_user_permissions(supabase: Client, user_id: uuid.UUID) -> List[RolePermissionCreate]:
    permissions: List[RolePermissionCreate] = []

    # Fetch direct role permissions
    role_perms = supabase.table("role_permissions").select(
        "resource, action").eq("user_id", user_id).execute()
    for perm in role_perms.data:
        permissions.append(RolePermissionCreate(
            resource=PermissionResource(perm["resource"]),
            action=[PermissionAction(action) for action in perm["action"]]
        ))

    # Fetch group permissions
    group_ids = supabase.table("user_permission_groups").select(
        "group_id").eq("user_id", user_id).execute()
    if group_ids.data:
        group_perms = supabase.table("group_permissions").select("resource, action").in_(
            "group_id", [group_id["group_id"] for group_id in group_ids.data]).execute()
        for perm in group_perms.data:
            permissions.append(RolePermissionCreate(
                resource=PermissionResource(perm["resource"]),
                action=[PermissionAction(action) for action in perm["action"]]
            ))

    # Remove duplicates by converting to dict and back to list
    permissions_dict = {(permission.resource, tuple(
        sorted(permission.action))): permission for permission in permissions}
    return list(permissions_dict.values())


def check_permission(supabase: Client, user_id: uuid.UUID, resource: str, action: str) -> bool:
    permissions = get_user_permissions(supabase, user_id)
    for perm in permissions:
        if perm.resource.value == resource and action in [a.value for a in perm.action]:
            return True
    return False


def login_user(supabase: Client, user: OAuth2PasswordRequestForm):
    response = supabase.auth.sign_in_with_password(
        {"email": user.username, "password": user.password})

    if not response:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Store both access and refresh tokens in Redis
    user_id = response.user.id
    store_tokens(
        user_id,
        response.session.access_token,
        response.session.refresh_token,
        response.session.expires_in
    )

    return {
        "access_token": response.session.access_token,
        "token_type": "bearer",
        "expires_in": response.session.expires_in
    }


def logout_user(
    token: str,
    supabase: Client
):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Sign out from Supabase
    supabase.auth.sign_out(token)

    # Clean up token store
    token_key = f"{REDIS_PREFIX}token:{token}"
    user_id = redis_client.get(token_key)
    if user_id:
        remove_tokens(user_id, token)

    return {"message": "Successfully logged out"}


def create_guest_user(supabase: Client, user: UserCreate) -> GuestResponse:
    # Create guest user in Supabase auth
    auth_response = supabase.auth.sign_up(
        {"email": user.email, "password": user.password})
    if not auth_response.user:
        raise HTTPException(status_code=400, detail="Failed to create user")

    # Insert into users table
    user_data = {
        "id": auth_response.user.id,
        "user_id": auth_response.user.id,
        "role": UserRole.GUEST,

    }
    new_user = supabase.table("users").insert(user_data).execute()

    assign_role_permissions_to_user(
        supabase, auth_response.user.id, UserRole.GUEST)

    permissions = get_user_permissions(supabase, auth_response.user.id)

    return GuestResponse(
        email=auth_response.user.user_metadata['email'],
        user_id=auth_response.user.id,
        role=new_user.data[0]['role'],
        permissions=permissions


    )


def create_company_user(supabase: Client, user: UserCreate) -> CompanyResponse:
    # Create company user in Supabase auth
    auth_response = supabase.auth.sign_up(
        {"email": user.email, "password": user.password})
    if not auth_response.user:
        raise HTTPException(status_code=400, detail="Failed to create user")

    print(auth_response)

    # Insert into companies table
    user_data = {
        "id": auth_response.user.id
    }
    supabase.table("companies").insert(user_data).execute()

    assign_role_permissions_to_user(
        supabase, auth_response.user.id, UserRole.COMPANY)

    permissions = get_user_permissions(supabase, auth_response.user.id)

    return CompanyResponse(
        email=auth_response.user.user_metadata['email'],
        user_id=auth_response.user.id,
        permissions=permissions
    )


def create_staff_user(supabase: Client, user: StaffCreate, current_user: dict) -> StaffResponse:
    # Create staff user in Supabase auth

    company_profile = supabase.table(
        'companies').select('id').eq('id', current_user['id']).single().execute()

    if not company_profile:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Please update your profile.')

    try:

        auth_response = supabase.auth.sign_up(
            {"email": user.email, "password": user.password})

        if not auth_response.user:
            raise HTTPException(
                status_code=400, detail="Failed to create user")

        role_permissions = []

        for resource_perm in user.permissions:
            role_permissions.append(
                RolePermissionCreate(
                    resource=resource_perm.resource, permission=resource_perm.action
                )
            )

        # Insert into users table
        user_data = {
            "id": auth_response.user.id,
            "user_id": auth_response.user.id,
            "role": user.role,
            "company_id": current_user['id'],
            "full_name": user.full_name,
            "permissions": role_permissions

        }
        new_user = supabase.table("users").insert(user_data).execute()

        return StaffResponse(
            user_id=auth_response.user.id,
            role=new_user.data[0]['role'],
            company_id=new_user.data[0]['company_id'],
            full_name=new_user.data[0]['full_name'],

        )
    except AuthApiError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def get_company_staff(supabase: Client, current_user: dict) -> list[StaffResponse]:
    cache_key = f"company_staff_{current_user['id']}"

    # Check if data is in cache
    cached_data = redis_client.get(cache_key)
    if cached_data:
        return json.loads(cached_data)

    # If not in cache, fetch from database
    staff = supabase.table(
        'users').select('user_id, company_id, full_name, role').eq('company_id', current_user['id']).execute()

    # Store the result in cache
    redis_client.set(cache_key, json.dumps(
        staff.data), ex=3600)  # Cache for 1 hour

    return staff.data


def create_no_post(supabase: Client, company_id: uuid.UUID, no_post: NoPostCreate) -> NoPostResponse:
    data = {"company_id": company_id, "no_post_list": no_post.no_post_list}
    response = supabase.table("no_post_list").insert(data).execute()
    return NoPostResponse(**response.data[0])


def create_outlet(supabase: Client, company_id: uuid.UUID, outlet: OutletCreate) -> OutletResponse:
    data = {"company_id": company_id, "name": outlet.name}
    response = supabase.table("outlets").insert(data).execute()
    return OutletResponse(**response.data[0])


def create_qrcode(supabase: Client, company_id: uuid.UUID, qrcode: QRCodeCreate) -> QRCodeResponse:
    data = {"company_id": company_id,
            'room_or_table_numbers': qrcode.room_or_table_numbers,
            'fill_color': qrcode.fill_color,
            'back_color': qrcode.back_color,
            'back_color': qrcode.back_color,
            'outlet_type': qrcode.outlet_type
            }
    response = supabase.table("qrcodes").insert(data).execute()
    return QRCodeResponse(**response.data[0])


def create_permission_group(supabase: Client, company_id: uuid.UUID, group: PermissionGroupCreate) -> PermissionGroupResponse:
    group_data = {"company_id": company_id,
                  "name": group.name, "description": group.description}
    group_response = supabase.table(
        "permission_groups").insert(group_data).execute()
    group_id = group_response.data[0]["id"]

    permissions = []
    for perm in group.permissions:
        perm_data = {"group_id": group_id,
                     "resource": perm.resource, "action": perm.action}
        perm_response = supabase.table(
            "group_permissions").insert(perm_data).execute()
        permissions.append(GroupPermissionResponse(**perm_response.data[0]))

    return PermissionGroupResponse(**group_response.data[0], permissions=permissions)


def assign_role_permission(supabase: Client, user_id: uuid.UUID, permission: RolePermissionCreate) -> RolePermissionResponse:
    data = {"user_id": user_id, "resource": permission.resource,
            "action": permission.action}
    response = supabase.table("role_permissions").insert(data).execute()
    return RolePermissionResponse(**response.data[0])


def assign_user_to_group(supabase: Client, user_id: uuid.UUID, group_id: uuid.UUID):
    data = {"user_id": user_id, "group_id": group_id}
    supabase.table("user_permission_groups").insert(data).execute()
