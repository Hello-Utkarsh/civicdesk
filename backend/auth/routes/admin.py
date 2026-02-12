import datetime
from hashlib import pbkdf2_hmac
from typing import Annotated
from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import true
from db.database import engine
from sqlmodel import Session, select
from db.models import Admin, Employee, Jurisdiction, Status
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
    department: str = Body(embed=True)
    jurisdiction_name: str = Body(embed=True)
    jurisdiction_type: str = Body(embed=True)


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
    admin = session.exec(select(Admin).where(Admin.id == jwt_data["id"])).first()
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not Authorized"
        )
    return admin


@router.post("/login")  # ✅
async def login(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    password: str = Body(embed=True),
):
    admin_data = session.exec(select(Admin).where(Admin.email == email)).first()
    is_verified = pbkdf2_sha256.verify(password, admin_data.password)
    if not is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )
    payload = {
        "id": str(admin_data.id),
        "role": "admin",
        "exp": datetime.datetime.now() + datetime.timedelta(days=7),
        "iat": datetime.datetime.now(),
    }
    token = jwt.encode(payload, os.getenv("token_salt"), algorithm="HS256")

    return {
        "message": "logged in successfully",
        "auth-token": token,
        "name": admin_data.name,
        "status": admin_data.status,
    }


@router.post("/create-admin")  # ✅
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
    jurisdiction = session.exec(
        select(Jurisdiction)
        .where(Jurisdiction.name == "india")
        .where(Jurisdiction.type == "country")
    ).first()
    if not jurisdiction:
        jurisdiction = Jurisdiction(name="india", type="country")
        session.add(jurisdiction)
        session.commit()
    hashed_password = pbkdf2_sha256.hash(admin_data.admin_password)
    admin = Admin(
        email=admin_data.email,
        password=hashed_password,
        name=admin_data.name,
        jurisdiction_id=jurisdiction.id,
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


@router.get("/get-direct-subordinates")  # ✅
async def get_direct_subordinates(
    session: Annotated[Session, Depends(get_session)], admin=Depends(verify_admin)
):
    results = session.exec(
        select(
            Employee.id,
            Employee.name,
            Employee.status,
            Employee.department,
            Employee.role,
            Jurisdiction.name,
            Jurisdiction.type,
        )
        .join(Jurisdiction)
        .where(Jurisdiction.parent_id == admin.jurisdiction_id)
    ).all()

    direct_subordinates = [
        {
            "id": id,
            "name": name,
            "status": status,
            "department": dept,
            "role": role,
            "jurisdiction_name": jur_name,
            "Jurisdiction_type": jur_type,
        }
        for id, name, status, dept, role, jur_name, jur_type in results
    ]
    return {"direct-subordinates": [direct_subordinates]}


@router.post("/onboard-employee")  # ✅
async def onboard_employee(
    session: Annotated[Session, Depends(get_session)],
    employee_data: EmployeeCreate,
    admin=Depends(verify_admin),
):
    jurisdiction_id = session.exec(
        select(Jurisdiction)
        .where(Jurisdiction.name == employee_data.jurisdiction_name.lower())
        .where(Jurisdiction.type == employee_data.jurisdiction_type.lower())
        .where(Jurisdiction.parent_id == admin.jurisdiction_id)
    ).first()
    if not jurisdiction_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no such jurisdiction not found",
        )
    employee = Employee(
        email=employee_data.email,
        role=employee_data.role,
        department=employee_data.department,
        jurisdiction_id=jurisdiction_id.id,
    )
    session.add(employee)
    session.commit()
    return {"message": "Employee Onboarded successfully"}


@router.put(
    "/toggle-employee-status"
)  # ✅
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
    if (
        employee.status == Status.ACTIVE.value
        or employee.status == Status.PENDING.value
    ):
        employee.status = Status.DISABLED.value
    elif not employee.name:
        employee.status = Status.PENDING.value
    else:
        employee.status = Status.ACTIVE.value
    session.add(employee)
    session.commit()
    return {"message": f"status updated successfully to {employee.status}"}


@router.delete("/delete-employee")  # ✅
async def delete_employee(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    admin=Depends(verify_admin),
):
    employee = session.exec(select(Employee).where(Employee.email == email)).first()
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found"
        )
    session.delete(employee)
    session.commit()
    return {"message": "employee deleted successfully"}


@router.get("/manage-jurisdiction")  # ✅
async def get_role(
    session: Annotated[Session, Depends(get_session)], admin=Depends(verify_admin)
):
    juris = session.exec(
        select(Jurisdiction).where(Jurisdiction.parent_id == admin.jurisdiction_id)
    ).all()
    return {"juris": juris}


@router.post("/manage-jurisdiction")  # ✅
async def create_juris(
    session: Annotated[Session, Depends(get_session)],
    name: str = Body(embed=True),
    juris_type: str = Body(embed=True),
    admin=Depends(verify_admin),
):
    juris = Jurisdiction(
        name=name.lower(), type=juris_type.lower(), parent_id=admin.jurisdiction_id
    )
    session.add(juris)
    session.commit()
    return {"message": "Jurisdiction created successfully"}


@router.put("/manage-jurisdiction") # ✅
async def update_role(
    session: Annotated[Session, Depends(get_session)],
    jurisdiction_id: str = Body(embed=True),
    name: str = Body(embed=True),
    juris_type: str = Body(embed=True),
    admin=Depends(verify_admin),
):
    juris = session.exec(
        select(Jurisdiction).where(Jurisdiction.id == jurisdiction_id)
    ).first()
    if not juris:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no such jurisdiction found"
        )
    juris.name = name
    juris.type = juris_type
    session.add(juris)
    session.commit()
    return {'message': 'jurisdiction updated successfully'}


@router.delete("/manage-jurisdiction") # ✅
async def delete_role(
    session: Annotated[Session, Depends(get_session)],
    jurisdiction_id: str = Body(embed=True),
    admin=Depends(verify_admin),
):
    juris = session.exec(
        select(Jurisdiction).where(Jurisdiction.id == jurisdiction_id)
    ).first()
    if not juris:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no such jurisdiction found"
        )
    session.delete(juris)
    session.commit()
    return {"message": "jurisdiction deleted successfully"}
