from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr, constr
import os
import time
import psycopg2
import stripe

# ==========================
# ENV
# ==========================
DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")

stripe.api_key = STRIPE_SECRET_KEY

# ==========================
# APP
# ==========================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten later when you have your website domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# DB
# ==========================
def db():
    return psycopg2.connect(DATABASE_URL)

# ==========================
# AUTH HELPERS
# ==========================
def make_token(email: str):
    return jwt.encode(
        {"sub": email, "exp": int(time.time()) + 3600},
        JWT_SECRET,
        algorithm="HS256",
    )

def _ensure_bcrypt_len(password: str):
    # bcrypt only supports max 72 BYTES
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 bytes or fewer")

class AuthIn(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=72)

# ==========================
# ROUTES
# ==========================
@app.post("/auth/register")
def register(data: AuthIn):
    _ensure_bcrypt_len(data.password)

    with db() as conn:
        cur = conn.cursor()

        # Check if user exists
        cur.execute("SELECT id FROM users WHERE email=%s", (str(data.email),))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email already exists")

        # Create user
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
            (str(data.email), bcrypt.hash(data.password)),
        )

        # Create license record (inactive until Stripe payment)
        # Safe to re-run due to ON CONFLICT.
        cur.execute(
            "INSERT INTO licenses (email, active, device_limit) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (email) DO NOTHING",
            (str(data.email), False, 2),
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
    """
    For now: token is passed as a query param (?token=...).
    Later we can switch to Authorization: Bearer <token>.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    with db() as conn:
        cur = conn.cursor()

        # Source of truth is licenses.active
        cur.execute("SELECT active, device_limit FROM licenses WHERE email=%s", (email,))
        lic = cur.fetchone()

        if not lic:
            return {"email": email, "license_active": False, "device_limit": 2}

        active, device_limit = lic
        return {"email": email, "license_active": bool(active), "device_limit": int(device_limit)}
