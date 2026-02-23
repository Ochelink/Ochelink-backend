from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr, constr
import os
import time
import psycopg2
import stripe

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
STRIPE_PRICE_ID = os.environ["STRIPE_PRICE_ID"]

stripe.api_key = STRIPE_SECRET_KEY

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def db():
    return psycopg2.connect(DATABASE_URL)

def make_token(email: str):
    return jwt.encode(
        {"sub": email, "exp": int(time.time()) + 3600},
        JWT_SECRET,
        algorithm="HS256",
    )

# bcrypt supports max 72 bytes (not characters). We'll enforce a safe max length.
class AuthIn(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=72)

def _ensure_bcrypt_len(password: str):
    # Byte-accurate check (covers emojis / multi-byte characters)
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 bytes or fewer")

@app.post("/auth/register")
def register(data: AuthIn):
    _ensure_bcrypt_len(data.password)

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (str(data.email),))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email already exists")

        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s,%s)",
            (str(data.email), bcrypt.hash(data.password)),
        )
        conn.commit()

    return {"ok": True}

@app.post("/auth/login")
def login(data: AuthIn):
    _ensure_bcrypt_len(data.password)

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE email=%s", (str(data.email),))
        row = cur.fetchone()
        if not row or not bcrypt.verify(data.password, row[0]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"access_token": make_token(str(data.email))}

@app.get("/me")
def me(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT license_active FROM users WHERE email=%s", (email,))
        row = cur.fetchone()

    return {"email": email, "license_active": row[0] if row else False}
