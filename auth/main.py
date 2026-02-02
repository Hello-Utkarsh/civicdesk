from typing import Union

from fastapi import FastAPI
from router import citizen

app = FastAPI()

app.include_router(citizen.router)

@app.get("/")
async def root():
    return {"message": "Hello Bigger Applications!"}