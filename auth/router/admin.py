from fastapi import APIRouter, HTTPException
from pydantic import EmailStr

router = APIRouter(prefix="/auth/admin")


@router.post("/login")
async def login(email: EmailStr, password: str):
    if not email or not password:
        raise HTTPException(status_code=400, detail="Missing email or password")
    # verify the admin and return a auth token with 12hr of expiration time
    return {"message": "logged in successfully", "auth-token": ""}


@router.post("/create-admin")
async def create_admin(password: str, email: EmailStr, admin_password: str):
    if not password or not email or not admin_password:
        raise HTTPException(status_code=400, detail="Missing password or email")
    # register the admin in the db
    return {"message": "Admin created successfully"}


@router.put("/disable")
async def disable(admin_email: EmailStr, disable_admin_email: EmailStr, auth_token: str):
    if not auth_token:
        raise HTTPException(status_code=400, detail="missing auth-token")
    # verify auth token
    if not admin_email or not disable_admin_email:
        raise HTTPException(
            status_code=400, detail="Missing admin email or the email to be disabled"
        )
    # verify the admin email and then set the status of the provided email as disabled
    return {"message": "Admin disabled successfully"}


@router.post("/onboard-employee")
async def onboard_employee(email: EmailStr, role: str, lvl: int, auth_token: str):
    if not auth_token:
        raise HTTPException(status_code=400, detail="missing auth-token")
    # verify auth token
    if not email or not role or not lvl:
        raise HTTPException(status_code=400, detail="Missing email, role or lvl")
    # create the employee
    return {"message": "Employee Onboarded successfully"}


@router.put("/disbale-employee")
async def disable_employee(email: EmailStr, auth_token: str):
    if not auth_token:
        raise HTTPException(status_code=400, detail="missing auth-token")
    # verify auth token
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    # update the employee status to "disabled"
    return {"message": "status updated successfully"}


@router.delete("/delete-employee")
async def delete_employee(email: EmailStr, auth_token: str):
    if not auth_token:
        raise HTTPException(status_code=400, detail="missing auth-token")
    # verify auth token
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

@router.post("/manage-role")
async def create_role(role: str, lvl: int):
    if not role or not lvl:
        raise HTTPException(status_code=400, detail='Missing role or lvl')
    # create the role if it does not alrwady exists in the db

@router.delete("/manage-role")
async def delete_role(role: str, lvl: int):
    if not role or not lvl:
        raise HTTPException(status_code=400, detail='Missing role or lvl')
    # delete the role if it does not alrwady exists in the db

@router.put("/manage-role")
async def update_role(role: str, lvl: int):
    if not role or not lvl:
        raise HTTPException(status_code=400, detail='Missing role or lvl')
    # update the role if it does not alrwady exists in the db

@router.get("/manage-role")
async def get_role():
    # gets all the roles
    return