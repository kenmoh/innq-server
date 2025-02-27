from pydantic import BaseModel, EmailStr, Field, validator
from typing import List, Optional
from enum import Enum
from datetime import datetime
import uuid

# ============= Enums ==============


class UserRole(str, Enum):
    GUEST = "guest"
    COMPANY = "company"
    WAITER = "waiter"
    CHEF = "chef"
    MANAGER = "manager"
    LAUNDRY = "laundry_attendant"
    SUPER_ADMIN = "super_admin"


class PaymentGatewayEnum(str, Enum):
    FLUTTERWAVE = "flutterwave"
    PAYSTACK = "paystack"
    STRIPE = "stripe"
    PAYPAL = "paypal"


class SubscriptionType(str, Enum):
    BASIC = "basic"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


class OutletType(str, Enum):
    RESTAURANT = "restaurant"
    ROOM_SERVICE = "room_service"


class PermissionResource(str, Enum):
    ORDER = "orders"
    ITEM = "items"
    STOCK = "stocks"
    PAYMENT = "payments"


class PermissionAction(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"


# ============= Schemas ==============


class CurrentUser(BaseModel):
    id: uuid.UUID
    role: str


class ProfileCreate(BaseModel):
    phone_number: str
    address: str
    cac_reg_number: str
    opening_hours: str
    logo_url: Optional[str] = None


class ProfileResponse(ProfileCreate):
    user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class PaymentGatewayCreate(BaseModel):
    payment_gateway_key: str
    payment_gateway_secret: str
    payment_gateway_provider: PaymentGatewayEnum


class PaymentGatewayResponse(PaymentGatewayCreate):
    user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class NoPostCreate(BaseModel):
    no_post_list: str


class NoPostResponse(NoPostCreate):
    id: uuid.UUID
    company_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class OutletCreate(BaseModel):
    name: str


class OutletResponse(OutletCreate):
    id: uuid.UUID
    company_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class QRCodeCreate(BaseModel):
    room_or_table_numbers: str
    fill_color: str | None = None
    back_color: str | None = None
    outlet_type: OutletType


class QRCodeResponse(QRCodeCreate):
    id: uuid.UUID
    company_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class GroupPermissionCreate(BaseModel):
    resource: PermissionResource
    action: list[PermissionAction] = []


class GroupPermissionResponse(GroupPermissionCreate):
    id: uuid.UUID
    group_id: uuid.UUID
    created_at: datetime


class PermissionGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: List[GroupPermissionCreate] = []


class PermissionGroupResponse(PermissionGroupCreate):
    id: uuid.UUID
    company_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    permissions: List[GroupPermissionResponse]


class RolePermissionCreate(BaseModel):
    resource: PermissionResource
    action: list[PermissionAction] = []


class RolePermissionResponse(RolePermissionCreate):
    id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime


# Permission Update Model
class PermissionUpdate(BaseModel):
    resource: PermissionResource
    actions: List[PermissionAction]


# Staff Update Schemas


class StaffPermissionUpdate(BaseModel):
    # Direct permissions to set
    direct_permissions: Optional[List[PermissionUpdate]] = None
    group_permissions: Optional[List[str]] = None  # Group names to add/remove
    groups_to_remove: Optional[List[str]] = None  # Group names to remove


class UserCreate(BaseModel):
    email: EmailStr
    is_subscribed: bool = False
    password: str


class StaffCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: UserRole
    permissions: RolePermissionCreate | None = None
    permission_group_name: PermissionGroupCreate | None = None

    @validator("permissions", pre=True, always=True)
    def check_at_least_one_permission(cls, v, values):
        if not v and not values.get("permission_group_name"):
            raise ValueError(
                "At least one of permissions or permission_group_name must be provided"
            )
        return v

    @validator("permission_group_name", pre=True, always=True)
    def check_at_least_one_permission_with_groups(cls, v, values):
        if not v and not values.get("permissions"):
            raise ValueError(
                "At least one of permissions or permission_group_name must be provided"
            )
        return v


class GuestResponse(BaseModel):
    user_id: uuid.UUID
    email: EmailStr
    full_name: str | None = None
    role: UserRole | None = None
    permissions: list[RolePermissionCreate]


class CompanyResponse(BaseModel):
    user_id: uuid.UUID
    email: EmailStr
    permissions: list[RolePermissionCreate]


class StaffResponse(BaseModel):
    user_id: str
    full_name: str
    role: UserRole
    company_id: uuid.UUID
    permissions: RolePermissionCreate | None = None
    permission_group: PermissionGroupCreate | None = None


class CompanyProfileCreate(BaseModel):
    company_name: str
    address: str
    cac_reg_number: str
    open_hours: str | None
    logo_url: str | None


class CompanyProfileResponse(CompanyProfileCreate):
    id: uuid.UUID


class PaymentGatewayCreate(BaseModel):
    payment_gateway_api_key: str
    payment_gateway_secret_key: str
    payment_gateway_provider: str


class PaymentGatewayResponse(PaymentGatewayCreate):
    company_id: uuid.UUID
