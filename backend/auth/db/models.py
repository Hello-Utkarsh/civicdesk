from typing import Optional
from sqlalchemy import Nullable
from sqlmodel import Field, SQLModel
from enum import Enum
import uuid


class Status(str, Enum):
    DISABLED = "disabled"
    ACTIVE = "active"
    PENDING = "pending"


class Department(str, Enum):
    WATER = "water"
    GAS = "gas"
    ELECTRICITY = "electricity"
    MUNICIPAL = "municipal"


class Citizen(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str
    email: str | None = Field(default=None, unique=True)
    mobile: str | None = Field(default=None, unique=True)
    role: str = Field(default="citizen")


class Admin(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str
    email: str = Field(unique=True)
    password: str
    role: str = Field(default="admin")
    status: Status = Field(default=Status.ACTIVE)
    jurisdiction_id: uuid.UUID = Field(foreign_key="jurisdiction.id")


class Employee(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: Optional[str] = Field(default=None)
    email: str = Field(unique=True)
    password: Optional[str] = Field(default=None)
    role: str = Field(default="employee")
    status: Status = Field(default=Status.PENDING)
    jurisdiction_id: uuid.UUID = Field(foreign_key="jurisdiction.id")
    department: Department | None


class Jurisdiction(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True)
    type: str
    parent_id: uuid.UUID | None = Field(default=None, foreign_key="jurisdiction.id")
