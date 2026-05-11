# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

users_db = []

# --- Schemas ---
class User(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

# --- Register ---
@app.post("/register")
def register_user(user: User):
    for existing in users_db:
        if existing["email"] == user.email:
            raise HTTPException(status_code=400, detail="Email already registered")
    
    users_db.append(user.model_dump())
    return {"message": "User registered successfully", "username": user.username}

# --- Login ---
@app.post("/login")
def login_user(credentials: LoginRequest):
    for user in users_db:
        if user["email"] == credentials.email and user["password"] == credentials.password:
            return {"message": "Login successful", "username": user["username"]}
    
    raise HTTPException(status_code=401, detail="Invalid email or password")