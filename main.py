from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr
import psycopg2
import stripe
import os
import time

# ---------------- CONFIG ----------------

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
STRIPE_PRICE_ID = os.environ["STRIPE_PRICE_ID"]
STRIPE_WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]

stripe.api_key = STRIPE_SECRET_KEY

# ---------------- APP ----------------

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DB ----------------

def db():
    return psycopg2.connect(DATABASE_URL)

# ---------------- AUTH ----------------

class AuthIn(BaseModel):
    email: EmailStr
    password: str

def make_token(email: str):
    return jwt.encode(
        {"sub": email, "exp": int(time.time()) + 3600},
        JWT_SECRET,
        algorithm="HS256",
    )

@app.post("/auth/register")
def register(data: AuthIn):
    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (data.email,))
        if cur.fetchone():
            raise HTTPException(400, "Email already exists")

        cur.execute(
            "INSERT INTO users (email, password_hash, license_active) VALUES (%s,%s,false)",
            (data.email, bcrypt.hash(data.password)),
        )
        conn.commit()

    return {"ok": True}

@app.post("/auth/login")
def login(data: AuthIn):
    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash FROM users WHERE email=%s", (data.email,)
        )
        row = cur.fetchone()

    if not row or not bcrypt.verify(data.password, row[0]):
        raise HTTPException(401, "Invalid credentials")

    return {"access_token": make_token(data.email)}

@app.get("/me")
def me(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = payload["sub"]
    except JWTError:
        raise HTTPException(401)

    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT license_active FROM users WHERE email=%s", (email,)
        )
        row = cur.fetchone()

    return {"email": email, "license_active": row[0] if row else False}

# ---------------- STRIPE WEBHOOK ----------------

@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception:
        raise HTTPException(400, "Invalid webhook")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]

        email = session.get("customer_details", {}).get("email")
        customer_id = session.get("customer")
        payment_intent = session.get("payment_intent")

        if not email:
            return {"ignored": True}

        with db() as conn:
            cur = conn.cursor()

            # activate user
            cur.execute(
                "UPDATE users SET license_active=true WHERE email=%s",
                (email,),
            )

            # create or update license
            cur.execute("""
                INSERT INTO licenses (email, active, device_limit, stripe_customer_id, stripe_payment_intent_id)
                VALUES (%s, true, 2, %s, %s)
                ON CONFLICT (email)
                DO UPDATE SET active=true
            """, (email, customer_id, payment_intent))

            conn.commit()

    return {"ok": True}
