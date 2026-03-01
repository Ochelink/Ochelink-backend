from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr, constr
import os
import time
import psycopg2
import stripe
import logging

from email_verification import router as email_verification_router, send_verification_email
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from email_service import send_email
from email_templates import password_reset_email, license_activated_email

logging.basicConfig(level=logging.INFO)

# ==========================
# ENV
# ==========================
DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]

EMAIL_SECRET = os.environ.get("EMAIL_SECRET", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://ochelink.com").rstrip("/")
DOWNLOAD_URL = os.environ.get("DOWNLOAD_URL", f"{FRONTEND_URL}/download")

STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
STRIPE_PRICE_ID = os.environ["STRIPE_PRICE_ID"]
STRIPE_WEBHOOK_SECRET = os.environ["STRIPE_WEBHOOK_SECRET"]

CHECKOUT_SUCCESS_URL = os.environ.get(
    "CHECKOUT_SUCCESS_URL", "https://ochelink-backend.onrender.com/docs"
)
CHECKOUT_CANCEL_URL = os.environ.get(
    "CHECKOUT_CANCEL_URL", "https://ochelink-backend.onrender.com/docs"
)

stripe.api_key = STRIPE_SECRET_KEY

# ==========================
# APP
# ==========================
app = FastAPI()

# Email verification routes
app.include_router(email_verification_router)

# CORS (Website -> API)
# NOTE: Browsers send an OPTIONS "preflight" request before POSTing JSON with credentials.
# Using allow_origins=["*"] together with allow_credentials=True will cause the preflight to fail.
frontend_url = os.getenv("FRONTEND_URL", "").strip().rstrip("/")
allowed_origins = []
if frontend_url:
    allowed_origins.append(frontend_url)
    # If you set FRONTEND_URL to https://ochelink.com, also allow www.
    if frontend_url.startswith("https://") and "www." not in frontend_url:
        allowed_origins.append(frontend_url.replace("https://", "https://www.", 1))
    if frontend_url.startswith("http://") and "www." not in frontend_url:
        allowed_origins.append(frontend_url.replace("http://", "http://www.", 1))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or ["*"],
    allow_credentials=bool(allowed_origins),
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# DB HELPERS
# ==========================
def db():
    return psycopg2.connect(DATABASE_URL)

def _email_norm(email: str) -> str:
    return (email or "").strip().lower()

# ==========================
# MODELS
# ==========================
class RegisterIn(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class ResetRequestIn(BaseModel):
    email: EmailStr

class ResetConfirmIn(BaseModel):
    token: str
    new_password: constr(min_length=8)

# ==========================
# TOKEN SERIALIZER (password reset)
# ==========================
serializer = URLSafeTimedSerializer(EMAIL_SECRET or JWT_SECRET)

# ==========================
# AUTH UTILS
# ==========================
def make_jwt(email: str) -> str:
    payload = {"email": email, "iat": int(time.time())}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_jwt(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("email", "")
    except JWTError:
        return ""

# ==========================
# ROUTES
# ==========================
@app.get("/")
def root():
    return {"ok": True, "service": "ochelink-backend"}

@app.post("/auth/register")
def register(data: RegisterIn):
    email = _email_norm(data.email)
    password_hash = bcrypt.hash(data.password)

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM public.users WHERE email=%s", (email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Account already exists")

        cur.execute(
            """
            INSERT INTO public.users (email, password_hash, license, is_verified)
            VALUES (%s, %s, false, false)
            """,
            (email, password_hash),
        )
        conn.commit()

    # Send verification email (best-effort)
    try:
        send_verification_email(email)
    except Exception as e:
        logging.warning(f"Failed to send verification email: {e}")

    return {"ok": True, "email": email}

@app.post("/auth/login")
def login(data: LoginIn):
    email = _email_norm(data.email)

    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, license, is_verified FROM public.users WHERE email=%s",
            (email,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        password_hash, has_license, is_verified = row[0], bool(row[1]), bool(row[2])

        if not bcrypt.verify(data.password, password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")

    token = make_jwt(email)
    return {
        "ok": True,
        "token": token,
        "email": email,
        "license": bool(has_license),
        "is_verified": bool(is_verified),
    }

# ==========================
# PASSWORD RESET
# ==========================
@app.post("/auth/request-password-reset")
def request_password_reset(data: ResetRequestIn):
    email = _email_norm(data.email)

    # Generate token even if account doesn't exist (avoid user enumeration)
    token = serializer.dumps(email, salt="pwreset")
    reset_link = f"{FRONTEND_URL}/reset-password?token={token}"

    try:
        html = password_reset_email(reset_link)
        send_email(to_email=email, subject="Reset your OcheLink password", html=html)
    except Exception as e:
        logging.warning(f"Failed to send password reset email: {e}")

    return {"ok": True}

@app.post("/auth/confirm-password-reset")
def confirm_password_reset(data: ResetConfirmIn):
    try:
        email = serializer.loads(data.token, salt="pwreset", max_age=60 * 60)  # 1 hour
    except SignatureExpired:
        raise HTTPException(status_code=400, detail="Reset token expired")
    except BadSignature:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    email = _email_norm(email)
    new_hash = bcrypt.hash(data.new_password)

    with db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE public.users SET password_hash=%s WHERE email=%s", (new_hash, email))
        conn.commit()

    return {"ok": True}

# ==========================
# LICENSE STATUS
# ==========================
@app.get("/license/status")
def license_status(request: Request):
    auth = request.headers.get("authorization") or ""
    token = auth.replace("Bearer", "").strip()
    email = decode_jwt(token)
    if not email:
        raise HTTPException(status_code=401, detail="Unauthorized")

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT license, is_verified FROM public.users WHERE email=%s", (email,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

    return {
        "email": email,
        "license": bool(row[0]),
        "is_verified": bool(row[1]),
    }

# ==========================
# BILLING: CREATE CHECKOUT SESSION
# ==========================
class CheckoutIn(BaseModel):
    email: EmailStr

@app.post("/billing/create-checkout-session")
def create_checkout_session(data: CheckoutIn):
    if not STRIPE_PRICE_ID:
        raise HTTPException(status_code=500, detail="STRIPE_PRICE_ID not set")

    email = _email_norm(data.email)

    # Block checkout until email is verified (prevents typo-email purchases)
    with db() as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT is_verified FROM public.users WHERE email=%s", (email,))
            row = cur.fetchone()
            is_verified = bool(row[0]) if row and row[0] is not None else False
        except psycopg2.errors.UndefinedColumn:
            # If DB not migrated yet, allow (but you should migrate)
            is_verified = True

    if not is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    # Create a real Stripe Checkout Session
    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        customer_email=email,
        success_url=CHECKOUT_SUCCESS_URL,
        cancel_url=CHECKOUT_CANCEL_URL,
        allow_promotion_codes=True,  # ✅ Enables discount codes on Stripe Checkout
    )

    return {"url": session.url, "id": session.id}

# ==========================
# STRIPE WEBHOOK
# ==========================
@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    if not sig_header:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")

    # Handle successful Checkout
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        email = _email_norm(session.get("customer_email") or "")

        if email:
            with db() as conn:
                cur = conn.cursor()
                cur.execute("UPDATE public.users SET license=true WHERE email=%s", (email,))
                conn.commit()

            # Send license activated email (best-effort)
            try:
                html = license_activated_email(DOWNLOAD_URL)
                send_email(to_email=email, subject="Your OcheLink license is active", html=html)
            except Exception as e:
                logging.warning(f"Failed to send license activated email: {e}")

    return {"ok": True}
