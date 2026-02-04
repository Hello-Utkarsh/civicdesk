from typing import Optional
from sqlmodel import Field, SQLModel
from enum import Enum
import uuid

class Status(str, Enum):
    DISABLED = "disable"
    ACTIVE = "active"
    PENDING = "pending"


class Citizen(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str
    email: str | None = Field(default=None, unique=True)
    mobile: int | None = Field(default=None, unique=True)


class Admin(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str
    email: str = Field(unique=True)
    password: str
    status: Status = Field(default=Status.ACTIVE)


class Employee(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: Optional[str] = Field(default=None)
    email: str = Field(unique=True)
    password: Optional[str] = Field(default=None)
    role: str | None = Field(default=None)
    lvl: int | None = Field(default=None)
    status: Status = Field(default=Status.PENDING)

    # eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0MmZjZTJmLTM1ZTItNDY5OC04MTI2LTZjOWM4Nzk1YTVhMiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc3MDgzODgxMywiaWF0IjoxNzcwMjM0MDEzfQ.02YPqSboeHgiE6nPw52ij_EunO8viBgR0_FjYwVQMAQ
