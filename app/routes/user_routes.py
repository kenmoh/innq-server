import uuid
from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from supabase import Client

from app import supabas_client
from ..schemas.user_schema import (
    CompanyResponse, GuestResponse, StaffCreate, StaffResponse, UserCreate, NoPostCreate, NoPostResponse,
    OutletCreate, OutletResponse, QRCodeCreate, QRCodeResponse,
    PermissionGroupCreate, PermissionGroupResponse, RolePermissionCreate, RolePermissionResponse
)
from ..services import user_services


user_router = APIRouter(prefix='/api/v1/users', tags=['User'])


@user_router.post("/login", status_code=status.HTTP_200_OK)
async def login_user(user: OAuth2PasswordRequestForm = Depends(), supabase: Client = Depends(supabas_client.get_client)):
    user_services.login_user(supabase=supabase, user=user)


@user_router.post("/logout", status_code=status.HTTP_200_OK)
async def logout_user(supabase: Client = Depends(supabas_client.get_client), current_user=Depends(supabas_client.get_current_user)):
    user_services.logout_user(supabase=supabase, token=current_user)


@user_router.post("/guest-users", response_model=GuestResponse, status_code=status.HTTP_201_CREATED)
async def create_company_user(user: UserCreate, supabase: Client = Depends(supabas_client.get_client)):
    return user_services.create_guest_user(supabase=supabase, user=user)


@user_router.post("/company-users", response_model=CompanyResponse, status_code=status.HTTP_201_CREATED)
async def create_company_user(user: UserCreate, supabase: Client = Depends(supabas_client.get_client)):
    return user_services.create_company_user(supabase=supabase, user=user)


@user_router.post("/staff-users", response_model=StaffResponse, status_code=status.HTTP_201_CREATED)
async def create_staff_user(user: StaffCreate, supabase: Client = Depends(supabas_client.get_client), current_user=Depends(supabas_client.get_company_user)):
    return user_services.create_staff_user(supabase=supabase, user=user, current_user=current_user)


@user_router.get("/company-staff-users", response_model=list[StaffResponse], status_code=status.HTTP_200_OK)
async def company_staff_user(supabase: Client = Depends(supabas_client.get_client), current_user=Depends(supabas_client.get_company_user)):
    return user_services.get_company_staff(supabase=supabase, current_user=current_user)


@user_router.post("/no-post", response_model=NoPostResponse, status_code=status.HTTP_201_CREATED)
async def create_no_post_route(
    no_post: NoPostCreate,
    user: dict = Depends(supabas_client.get_company_user),
    supabase: Client = Depends(supabas_client.get_client)
):
    return user_services.create_no_post(supabase, user["company_id"], no_post)


@user_router.post("/outlets", response_model=OutletResponse, status_code=status.HTTP_201_CREATED)
async def create_outlet_route(
    outlet: OutletCreate,
    user: dict = Depends(supabas_client.get_company_user),
    supabase: Client = Depends(supabas_client.get_client)
):
    return user_services.create_outlet(supabase, user["company_id"], outlet)


@user_router.post("/qrcodes", response_model=QRCodeResponse, status_code=status.HTTP_201_CREATED)
async def create_qrcode_route(
    qrcode: QRCodeCreate,
    user: dict = Depends(supabas_client.get_company_user),
    supabase: Client = Depends(supabas_client.get_client)
):
    return user_services.create_qrcode(supabase, user["company_id"], qrcode)


@user_router.post("/permission-groups", response_model=PermissionGroupResponse, status_code=status.HTTP_201_CREATED)
async def create_permission_group_route(
    group: PermissionGroupCreate,
    user: dict = Depends(supabas_client.get_company_user),
    supabase: Client = Depends(supabas_client.get_client)
):
    return user_services.create_permission_group(supabase, user["company_id"], group)


@user_router.post("/role-permissions", response_model=RolePermissionResponse, status_code=status.HTTP_201_CREATED)
async def assign_role_permission_route(
    permission: RolePermissionCreate,
    user_id: uuid.UUID,
    user: dict = Depends(supabas_client.get_company_user),
    supabase: Client = Depends(supabas_client.get_client)
):
    return user_services.assign_role_permission(supabase, user_id, permission)


@user_router.post("/users/{user_id}/permission-groups/{group_id}", status_code=status.HTTP_201_CREATED)
async def assign_user_to_group_route(
    user_id: uuid.UUID,
    group_id: uuid.UUID,
    user: dict = Depends(supabas_client.get_company_user),
    supabase: Client = Depends(supabas_client.get_client)
):
    user_services.assign_user_to_group(supabase, user_id, group_id)
    return {"message": "User assigned to group"}
