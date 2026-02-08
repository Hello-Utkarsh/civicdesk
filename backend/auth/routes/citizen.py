import datetime
import select
from typing import Annotated
from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
from fastapi_mail import FastMail, MessageSchema, MessageType
from pydantic import EmailStr
import random
from sqlmodel import Session
from db.models import Citizen
from services.mail import conf
from services.redis import r
import os
from dotenv import load_dotenv
from jose import jwt
from .admin import get_session

load_dotenv()

router = APIRouter(prefix="/auth/citizen")


@router.post("/request-otp")
async def get_otp(email: EmailStr = Body(embed=True)):
    otp = random.randint(100000, 999999)
    message = MessageSchema(
        subject="OTP for email verification in CivicDesk",
        recipients=[email],
        body=f"{otp} is the OTP for your profile verification in CivicDesk",
        subtype=MessageType.plain,
    )
    fm = FastMail(conf)
    await fm.send_message(message)
    payload = {
        "id": str(otp),
        "exp": datetime.datetime.now() + datetime.timedelta(minutes=1),
        "iat": datetime.datetime.now(),
    }
    r.set(email, jwt.encode(payload, os.getenv("token_salt"), algorithm="HS256"))
    return {
        "message": "OTP sent to the provided email",
    }


@router.post("/verify-otp")
async def verify_otp(
    session: Annotated[Session, Depends(get_session)],
    name: str = Body(embed=True),
    otp: str = Body(min_length=6, max_length=6),
    email: EmailStr = Body(embed=True),
):
    otp_data = r.get(email)
    if not otp_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="please request an otp first",
        )
    verify = jwt.decode(otp_data, os.getenv("token_salt"), algorithms="HS256")
    if verify["id"] != otp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP"
        )
    find_cit = session.exec(select(Citizen).where(Citizen.email == email)).all()
    if not find_cit:
        find_cit = Citizen(name=name, email=email)
        session.add(find_cit)
        session.commit()
    payload = {
        "id": find_cit[0].id,
        "exp": datetime.datetime.now() + datetime.timedelta(hours=2),
        "iat": datetime.datetime.now(),
    }
    auth_token = jwt.encode(payload, os.getenv("token_salt"), algorithm="HS256")
    r.delete(email)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "verified successfully", "auth-token": auth_token},
    )
