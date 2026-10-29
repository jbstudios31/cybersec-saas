import re
from datetime import datetime
from typing import List, Optional

import pydantic
from pydantic import BaseModel, Field

PYDANTIC_V2 = pydantic.VERSION.startswith("2")

if PYDANTIC_V2:
    from pydantic import ConfigDict

    class ORMModel(BaseModel):
        model_config = ConfigDict(from_attributes=True)
else:  # pragma: no cover - compatibilidad con pydantic v1 (entornos de desarrollo)
    class ORMModel(BaseModel):
        class Config:
            orm_mode = True


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VALID_SEVERITIES = ("low", "medium", "high", "critical")
VALID_STATUSES = ("pending", "resolved", "false_positive")


def normalize_email(value: str) -> str:
    """Normaliza y valida un email. Lanza ValueError si no es válido."""
    value = (value or "").strip().lower()
    if not EMAIL_RE.match(value):
        raise ValueError("email inválido")
    return value


class UserCreate(ORMModel):
    email: str = Field(max_length=255)
    password: str = Field(min_length=1, max_length=256)
    is_admin: bool = False


class UserOut(ORMModel):
    id: int
    email: str
    is_active: bool
    is_admin: bool


class TargetCreate(ORMModel):
    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=500)
    owner_id: int = Field(gt=0)


class TargetOut(ORMModel):
    id: int
    name: str
    url: str
    owner_id: int
    is_active: bool


class TargetList(ORMModel):
    items: List[TargetOut]
    total: int
    page: int
    page_size: int
    pages: int


class FindingOut(ORMModel):
    id: int
    scan_run_id: int
    severity: str
    title: str
    description: str
    remediation: str
    status: str
    created_at: datetime


class FindingStatusUpdate(ORMModel):
    status: str


class FindingList(ORMModel):
    items: List[FindingOut]
    total: int
    page: int
    page_size: int
    pages: int


class ScanRunOut(ORMModel):
    id: int
    target_id: int
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None


class Token(ORMModel):
    access_token: str
    token_type: str


class TokenData(ORMModel):
    email: Optional[str] = None
