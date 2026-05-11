# main.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta

app = FastAPI()

# --- Config ---
SECRET_KEY = "mysecretkey123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

users_db = []

# --- Schemas ---
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

# --- Helpers ---
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- 1. Register ---
@app.post("/register")
def register_user(user: RegisterRequest):
    for existing in users_db:
        if existing["email"] == user.email:
            raise HTTPException(status_code=400, detail="Email already registered")
    users_db.append({
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password)
    })
    return {
        "message": "User registered successfully",
        "username": user.username,
        "email": user.email
    }

# --- 2. Login ---
@app.post("/login")
def login_user(credentials: LoginRequest):
    for user in users_db:
        if user["email"] == credentials.email:
            if not verify_password(credentials.password, user["password"]):
                raise HTTPException(status_code=401, detail="Wrong password")
            token = create_access_token({"sub": user["email"]})
            return {
                "message": "Login successful",
                "username": user["username"],
                "access_token": token,
                "token_type": "bearer"
            }
    raise HTTPException(status_code=404, detail="User not found")

# --- 3. Authenticate ---
@app.get("/authenticate")
def authenticate(current_user: str = Depends(get_current_user)):
    for user in users_db:
        if user["email"] == current_user:
            return {
                "authenticated": True,
                "username": user["username"],
                "email": user["email"]
            }
    raise HTTPException(status_code=404, detail="User not found")