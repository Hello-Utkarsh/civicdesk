import datetime
from hashlib import pbkdf2_hmac
from typing import Annotated
from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from db.database import engine
from sqlmodel import Session, select
from db.models import Admin, Employee, Status
from passlib.hash import pbkdf2_sha256
import os
from dotenv import load_dotenv
from jose import JWTError, jwt


router = APIRouter(prefix="/auth/admin")

security = HTTPBearer()


def get_session():
    with Session(engine) as session:
        yield session


class AdminCreate(BaseModel):
    password: str
    email: EmailStr
    admin_password: str
    name: str


class EmployeeCreate(BaseModel):
    email: EmailStr
    role: str
    lvl: int


async def verify_admin(
    session: Annotated[Session, Depends(get_session)],
    auth_token: HTTPAuthorizationCredentials = Depends(security),
):
    try:
        jwt_data = jwt.decode(
            auth_token.credentials, os.getenv("token_salt"), algorithms="HS256"
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Token"
        )
    if jwt_data["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not Authorized"
        )
    admin = session.exec(select(Admin).where(Admin.id == jwt_data["id"])).all()
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not Authorized"
        )


@router.post("/login")
async def login(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    password: str = Body(embed=True),
):
    admin_data = session.exec(select(Admin).where(Admin.email == email)).all()
    is_verified = pbkdf2_sha256.verify(password, admin_data[0].password)
    if not is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )
    payload = {
        "id": str(admin_data[0].id),
        "role": "admin",
        "exp": datetime.datetime.now() + datetime.timedelta(days=7),
        "iat": datetime.datetime.now(),
    }
    token = jwt.encode(payload, os.getenv("token_salt"), algorithm="HS256")

    return {
        "message": "logged in successfully",
        "auth-token": token,
        "name": admin_data[0].name,
        "status": admin_data[0].status,
    }


@router.post("/create-admin")
async def create_admin(
    admin_data: AdminCreate, session: Annotated[Session, Depends(get_session)]
):
    if admin_data.password != os.getenv("ADMIN_ONBOARD_PASSWORD"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid password"
        )

    all_admins = session.exec(select(Admin)).all()
    if len(all_admins) == 2:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot onboard more admins",
        )
    hashed_password = pbkdf2_sha256.hash(admin_data.admin_password)
    admin = Admin(
        email=admin_data.email,
        password=hashed_password,
        name=admin_data.name,
    )
    session.add(admin)
    session.commit()
    return {"message": "Admin created successfully"}


@router.put("/disable")
async def disable(
    session: Annotated[Session, Depends(get_session)],
    disable_admin_email: EmailStr,
    admin=Depends(verify_admin),
):
    disable_admin = session.exec(
        select(Admin).where(Admin.email == disable_admin_email)
    )
    if not disable_admin:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found"
        )
    session.delete(disable)
    session.commit()
    return {"message": "Admin disabled successfully"}


@router.post("/onboard-employee")
async def onboard_employee(
    session: Annotated[Session, Depends(get_session)],
    employee_data: EmployeeCreate,
    admin=Depends(verify_admin),
):
    employee = Employee(
        email=employee_data.email, role=employee_data.role, lvl=employee_data.lvl
    )
    session.add(employee)
    session.commit()
    return {"message": "Employee Onboarded successfully"}


@router.put("/toggle-employee-status")
async def disable_employee(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    admin=Depends(verify_admin),
):
    employee = session.exec(select(Employee).where(Employee.email == email)).one()
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found"
        )
    if employee.status == Status.ACTIVE or employee.status == Status.PENDING:
        employee.status = Status.DISABLED
    elif not employee.name:
        employee.status = Status.PENDING
    else:
        employee.status = Status.ACTIVE
    session.add(employee)
    session.commit()
    return {"message": "status updated successfully"}


@router.delete("/delete-employee")
async def delete_employee(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    admin=Depends(verify_admin),
):
    employee = session.exec(select(Employee).where(Employee.email == email))
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found"
        )
    session.delete(employee)
    session.commit()
    return {"message": "employee deleted successfully"}


@router.post("/manage-role")
async def create_role(role: str, lvl: int):
    if not role or not lvl:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing role or lvl"
        )
    # create the role if it does not alrwady exists in the db


@router.delete("/manage-role")
async def delete_role(role: str, lvl: int):
    if not role or not lvl:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing role or lvl"
        )
    # delete the role if it does not alrwady exists in the db


@router.put("/manage-role")
async def update_role(role: str, lvl: int):
    if not role or not lvl:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing role or lvl"
        )
    # update the role if it does not alrwady exists in the db


@router.get("/manage-role")
async def get_role():
    # gets all the roles
    return
