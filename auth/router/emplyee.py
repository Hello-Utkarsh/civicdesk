from fastapi import APIRouter, HTTPException

router = APIRouter(prefix='/auth/employee')


@router.post('/sign-in')
async def signIn(email: str, password: str):
    if not email or not password:
        raise HTTPException(status_code=400, detail='Missing email or password')
    
@router.post('/login')
async def logIn(email: str, password: str):
    if not email or not password:
        raise HTTPException(status_code=400, detail='Missing email or password')
    