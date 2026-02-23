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
# DEBUG / PROOF ENDPOINT
# ==========================
@app.get("/version")
def version():
    return {"version": "main.py drop-in v3 (register creates public.licenses + returns license_id)"}

# ==========================
# ROUTES
# ==========================
@app.post("/auth/register")
def register(data: AuthIn):
    _ensure_bcrypt_len(data.password)

    with db() as conn:
        cur = conn.cursor()

        # 1) Check if user exists (schema-qualified)
        cur.execute("SELECT id FROM public.users WHERE email=%s", (str(data.email),))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email already exists")

        # 2) Insert user (schema-qualified)
        cur.execute(
            "INSERT INTO public.users (email, password_hash) VALUES (%s,%s) RETURNING id",
            (str(data.email), bcrypt.hash(data.password)),
        )
        user_id = cur.fetchone()[0]

        # 3) Insert license (schema-qualified) and RETURN the license row
        # Using DO UPDATE purely so we can always RETURN a row.
        cur.execute(
            "INSERT INTO public.licenses (email, active, device_limit) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email "
            "RETURNING id, active, device_limit",
            (str(data.email), False, 2),
        )
        lic = cur.fetchone()  # (license_id, active, device_limit)

        conn.commit()

    return {
        "ok": True,
        "user_id": str(user_id),
        "license_id": str(lic[0]) if lic else None,
        "license_active": bool(lic[1]) if lic else False,
        "device_limit": int(lic[2]) if lic else 2,
    }

@app.post("/auth/login")
def login(data: AuthIn):
    _ensure_bcrypt_len(data.password)

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM public.users WHERE email=%s", (str(data.email),))
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
        cur.execute("SELECT active, device_limit FROM public.licenses WHERE email=%s", (email,))
        lic = cur.fetchone()

    if not lic:
        return {"email": email, "license_active": False, "device_limit": 2}

    return {"email": email, "license_active": bool(lic[0]), "device_limit": int(lic[1])}
