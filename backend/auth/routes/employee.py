import datetime
from typing import Annotated
from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from sqlmodel import Session, select
from jose import JWTError, jwt
from db.models import Department, Employee, Jurisdiction, Status
from .admin import get_session
import os
from dotenv import load_dotenv
from passlib.hash import pbkdf2_sha256

load_dotenv()

router = APIRouter(prefix="/auth/employee")
security = HTTPBearer()


class EmployeeCreate(BaseModel):
    email: EmailStr
    role: str
    department: Department = Body(embed=True)
    jurisdiction_name: str = Body(embed=True)
    jurisdiction_type: str = Body(embed=True)


async def verify_employee(
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
    if jwt_data["role"] != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not Authorized"
        )
    employee = session.exec(
        select(Employee).where(Employee.id == jwt_data["id"])
    ).first()
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not Authorized"
        )
    return employee


@router.post("/sign-in")  # ✅
async def signIn(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    password: str = Body(embed=True),
    name: str = Body(embed=True),
):
    get_employee = session.exec(select(Employee).where(Employee.email == email)).first()
    if not get_employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Employee id not found, please get yourself registered by the admin",
        )
    payload = {
        "id": str(get_employee.id),
        "role": "employee",
        "exp": datetime.datetime.now() + datetime.timedelta(days=1),
        "iat": datetime.datetime.now(),
    }
    auth_token = jwt.encode(payload, os.getenv("token_salt"), algorithm="HS256")
    get_employee.password = pbkdf2_sha256.hash(password)
    get_employee.name = name
    get_employee.status = Status.ACTIVE.value
    session.add(get_employee)
    session.commit()
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "on-boarded successfully", "auth-token": auth_token},
    )


@router.post("/login")  # ✅
async def logIn(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    password: str = Body(embed=True),
):
    get_employee = session.exec(select(Employee).where(Employee.email == email)).first()
    if not get_employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found"
        )
    if not get_employee.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="please signin first"
        )
    is_verified = pbkdf2_sha256.verify(password, get_employee.password)
    if not is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
        )
    payload = {
        "id": str(get_employee.id),
        "role": "employee",
        "exp": datetime.datetime.now() + datetime.timedelta(days=1),
        "iat": datetime.datetime.now(),
    }
    auth_token = jwt.encode(payload, os.getenv("token_salt"), algorithm="HS256")
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "logged-in successfully", "auth-token": auth_token},
    )


@router.get("/get-direct-subordinates")  # ✅
async def get_direct_subordinates(
    session: Annotated[Session, Depends(get_session)], employee=Depends(verify_employee)
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
        .where(Jurisdiction.parent_id == employee.jurisdiction_id)
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
    employee=Depends(verify_employee),
):
    jurisdiction = session.exec(
        select(Jurisdiction)
        .where(Jurisdiction.name == employee_data.jurisdiction_name)
        .where(Jurisdiction.type == employee_data.jurisdiction_type)
        .where(Jurisdiction.parent_id == employee.jurisdiction_id)
    ).first()
    if not jurisdiction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no such jurisdiction not found",
        )
    employee = Employee(
        email=employee_data.email,
        role=employee_data.role,
        department=employee_data.department,
        jurisdiction_id=jurisdiction.id,
    )
    session.add(employee)
    session.commit()
    return {"message": "Employee Onboarded successfully"}


@router.put("/toggle-employee-status")  # ✅
async def toggle_employee_status(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    head_employee=Depends(verify_employee),
):
    employee, _ = session.exec(
        select(Employee, Jurisdiction)
        .join(Jurisdiction)
        .where(Employee.email == email)
        .where(Jurisdiction.parent_id == head_employee.jurisdiction_id)
    ).first()
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
    id: str = Body(embed=True),
    employee=Depends(verify_employee),
):
    employee = session.exec(select(Employee).where(Employee.id == id)).first()
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found"
        )
    session.delete(employee)
    session.commit()
    return {"message": "employee deleted successfully"}


@router.get("/manage-jurisdiction")  # ✅
async def get_role(
    session: Annotated[Session, Depends(get_session)], employee=Depends(verify_employee)
):
    juris = session.exec(
        select(Jurisdiction).where(Jurisdiction.parent_id == employee.jurisdiction_id)
    ).all()
    return {"jurisdictons": juris}


@router.post("/manage-jurisdiction")  # ✅
async def create_juris(
    session: Annotated[Session, Depends(get_session)],
    name: str = Body(embed=True),
    juris_type: str = Body(embed=True),
    employee=Depends(verify_employee),
):
    juris = Jurisdiction(
        name=name.lower(), type=juris_type.lower(), parent_id=employee.jurisdiction_id
    )
    session.add(juris)
    session.commit()
    return {"message": "Jurisdiction created successfully"}


@router.put("/manage-jurisdiction")  # ✅
async def update_role(
    session: Annotated[Session, Depends(get_session)],
    id: str = Body(embed=True),
    name: str = Body(embed=True),
    juris_type: str = Body(embed=True),
    employee=Depends(verify_employee),
):
    juris = session.exec(select(Jurisdiction).where(Jurisdiction.id == id)).first()
    if not juris:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no such jurisdiction found"
        )
    juris.name = name
    juris.type = juris_type
    session.add(juris)
    session.commit()
    return {"message": "jurisdiction updated successfully"}


@router.delete("/manage-jurisdiction") # ✅
async def delete_role(
    session: Annotated[Session, Depends(get_session)],
    id: str = Body(embed=True),
    employee=Depends(verify_employee),
):
    juris = session.exec(select(Jurisdiction).where(Jurisdiction.id == id)).first()
    if not juris:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no such jurisdiction found"
        )
    session.delete(juris)
    session.commit()
    return {"message": "jurisdiction deleted successfully"}
