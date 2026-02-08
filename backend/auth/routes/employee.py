import datetime
import select
from typing import Annotated
from fastapi import APIRouter, Body, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import EmailStr
from sqlmodel import Session
from jose import jwt
from db.models import Employee
from .admin import get_session
import os
from dotenv import load_dotenv

load_dotenv()

router = APIRouter(prefix="/auth/employee")


@router.post("/sign-in")
async def signIn(
    session: Annotated[Session, Depends(get_session)],
    email: EmailStr = Body(embed=True),
    password: str = Body(embed=True),
    name: str = Body(embed=True),
):
    get_employee = session.exec(select(Employee).where(Employee.email == email)).all()
    if not get_employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Employee id not found, please get yourself registered by the admin",
        )
    payload = {
        "id": get_employee[0].id,
        "exp": datetime.datetime.now() + datetime.timedelta(days=1),
        "iat": datetime.datetime.now(),
    }
    auth_token = jwt.encode(payload, os.getenv("token_salt"), algorithm="HS256")
    get_employee.password = password
    get_employee.name = name
    session.add(get_employee)
    session.commit()
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "on-boarded successfully", "auth-token": auth_token},
    )


@router.post("/login")
async def logIn(
    session: Annotated[Session, Depends(get_session)],
    email: str = Body(embed=True),
    password: str = Body(embed=True),
):
    get_employee = session.exec(select(Employee).where(Employee.email == email)).all()
    if not get_employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found"
        )
    payload = {
        "id": get_employee[0].id,
        "exp": datetime.datetime.now() + datetime.timedelta(days=1),
        "iat": datetime.datetime.now(),
    }
    auth_token = jwt.encode(payload, os.getenv("token_salt"), algorithm="HS256")
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "logged-in successfully", "auth-token": auth_token},
    )
