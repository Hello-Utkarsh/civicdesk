from fastapi import APIRouter, HTTPException
from pydantic import EmailStr
import random

router = APIRouter(prefix="/auth/citizen")


@router.post("/request-otp")
async def get_otp(mob_no: str):
    if len(mob_no) < 10:
        raise HTTPException(status_code=400, detail="Invalid number")
    otp = random.randint(100000, 999999)
    # save the otp to a postgres db with the provided mob number
    print(otp)
    return {
        "message": "OTP sent to the provided mobile number",
    }

@router.get('/verify-otp')
async def verify_otp(otp: int):
    if len(otp) < 6:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    # fetch the otp using the mob number and delete both the mob number and otp if the provided otp is verified
    return

@router.post('/sign-in')
async def signIn(email: EmailStr, password: str):
    if not email or not password:
        raise HTTPException(status_code=400, detail='missing email or password')
    # set the employee password for future login and also login him and return a auth-token

@router.post('/login')
async def login(email: EmailStr, passowrd: str):
    if not email or not passowrd:
        raise HTTPException(status_code=400, detail='missing email or password')
    # verify and return auth token