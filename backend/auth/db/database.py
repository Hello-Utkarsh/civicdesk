from sqlmodel import SQLModel, create_engine
from dotenv import load_dotenv
from .models import Employee, Admin, Citizen, Department, Status
import os

load_dotenv()

db_url = os.getenv("DATABASE_URL")

engine = create_engine(db_url, echo=True)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)