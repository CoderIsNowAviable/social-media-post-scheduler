from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import mysql.connector
from fastapi.staticfiles import StaticFiles


load_dotenv()  # Load environment variables from .env

# Load secret key and database details from .env
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# FastAPI instance
app = FastAPI()



# Serve static files from the 'frontend' folder
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database connection
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

# Pydantic models
class User(BaseModel):
    username: str
    password: str

class UserInDB(User):
    hashed_password: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

from fastapi import FastAPI

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
def read_home():
    try:
        with open("frontend/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="404 Not Found", status_code=404)
    

@app.post("/signup")
async def signup(user: User):
    db = get_db()
    cursor = db.cursor()

    # Check if user exists
    cursor.execute("SELECT * FROM users WHERE username=%s", (user.username,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_password = get_password_hash(user.password)

    # Insert new user
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (user.username, hashed_password))
    db.commit()

    cursor.close()
    db.close()

    return {"message": "User created successfully!"}

@app.post("/token")
async def login_for_access_token(form_data: User):
    db = get_db()
    cursor = db.cursor()

    # Verify user
    cursor.execute("SELECT * FROM users WHERE username=%s", (form_data.username,))
    user = cursor.fetchone()
    
    if not user or not verify_password(form_data.password, user[1]):  # Check hashed password
        raise HTTPException(status_code=401, detail="Invalid credentials")

    cursor.close()
    db.close()

    return {"access_token": "JWT_TOKEN", "token_type": "bearer"}

@app.get("/dashboard")
async def dashboard(token: str = Depends(oauth2_scheme)):
    return {"message": "Welcome to the dashboard!"}
