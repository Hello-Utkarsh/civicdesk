from fastapi import FastAPI
from routes import citizen, admin, employee

app = FastAPI()

app.include_router(citizen.router)
app.include_router(employee.router)
app.include_router(admin.router)

@app.get("/")
async def root():
    return {"message": "Hello Bigger Applications!"}