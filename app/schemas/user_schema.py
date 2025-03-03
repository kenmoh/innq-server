from pydantic import BaseModel, EmailStr, Field, field_validator, validator
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
    LAUNDRY = 'laundry_attendant'
    SUPER_ADMIN = 'super_admin'


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


class UserType(BaseModel):
    name: str


class UserTypeResponse(UserType):
    id: int


class NavItem(BaseModel):
    path_name: str
    path: str


class NavItemResponse(NavItem):
    id: int


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


class RolePermissionCreate(BaseModel):
    resource: PermissionResource
    actions: list[PermissionAction] = []


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
    permissions: list[RolePermissionCreate]


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
    permissions: list[RolePermissionCreate] = []


class CompanyProfileCreate(BaseModel):
    company_name: str
    address: str
    cac_reg_number: str
    opening_hours: str | None
    logo_url: str | None


class CompanyProfileResponse(CompanyProfileCreate):
    id: uuid.UUID
    company_name: str
    address: str
    cac_reg_number: str
    opening_hours: str | None = None
    logo_url: str | None = None


class LoginResponse(BaseModel):
    id: str
    access_token: str
    refresh_token: str
    role: str


class CurrentUserResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    phone: str | None = None


"""

{
  "user": {
    "id": "11111111-1111-1111-1111-111111111111",
    "app_metadata": {
      "provider": "email",
      "providers": []
    },
    "user_metadata": {},
    "aud": "authenticated",
    "confirmation_sent_at": "2023-02-19T00:01:51.147035Z",
    "recovery_sent_at": "2024-07-21T22:20:00.366959Z",
    "email_change_sent_at": null,
    "new_email": null,
    "new_phone": null,
    "invited_at": null,
    "action_link": null,
    "email": "email@example.com",
    "phone": "",
    "created_at": "2023-02-19T00:01:51.142802Z",
    "confirmed_at": "2023-02-19T00:01:51.351735Z",
    "email_confirmed_at": "2023-02-19T00:01:51.351735Z",
    "phone_confirmed_at": null,
    "last_sign_in_at": "2024-07-24T22:24:57.642878Z",
    "role": "authenticated",
    "updated_at": "2024-07-24T22:24:57.650021Z",
    "identities": [],
    "is_anonymous": false,
    "factors": null
  }
}


"""
