import os
from dotenv import load_dotenv
from fastapi_mail import ConnectionConfig

load_dotenv()

conf = ConnectionConfig(
    MAIL_USERNAME="civicdesk0@gmail.com",
    MAIL_PASSWORD=os.getenv("mail_password"),
    MAIL_FROM="civicdesk0@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_FROM_NAME="CivicDesk",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)