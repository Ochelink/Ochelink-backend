from fastapi import FastAPI, HTTPException, Request
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later
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
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 bytes or fewer")

def _email_norm(email: str) -> str:
    return str(email).strip().lower()

def _email_from_bearer(request: Request) -> str:
    """
    Reads Authorization: Bearer <token>
    Returns the email from JWT "sub".
    """
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization must be Bearer <token>")

    token = parts[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        return _email_norm(email)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

class AuthIn(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=72)

@app.get("/version")
def version():
    return {"version": "main.py v7 (v6 + device licensing /license/check)"}

# ==========================
# AUTH ROUTES
# ==========================
@app.post("/auth/register")
def register(data: AuthIn):
    _ensure_bcrypt_len(data.password)
    email = _email_norm(data.email)

    with db() as conn:
        cur = conn.cursor()

        cur.execute("SELECT id FROM public.users WHERE email=%s", (email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email already exists")

        cur.execute(
            "INSERT INTO public.users (email, password_hash) VALUES (%s,%s) RETURNING id",
            (email, bcrypt.hash(data.password)),
        )
        user_id = cur.fetchone()[0]

        # Ensure a licenses row exists for the email
        cur.execute(
            """
            INSERT INTO public.licenses (email, active, device_limit)
            VALUES (%s, %s, %s)
            ON CONFLICT (email) DO NOTHING
            RETURNING id, active, device_limit
            """,
            (email, False, 2),
        )
        lic = cur.fetchone()
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
    email = _email_norm(data.email)

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM public.users WHERE email=%s", (email,))
        row = cur.fetchone()

    if not row or not bcrypt.verify(data.password, row[0]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"access_token": make_token(email)}

@app.get("/me")
def me(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = _email_norm(payload["sub"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    with db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT active, device_limit FROM public.licenses WHERE email=%s", (email,))
        lic = cur.fetchone()

    if not lic:
        return {"email": email, "license_active": False, "device_limit": 2}

    return {"email": email, "license_active": bool(lic[0]), "device_limit": int(lic[1])}

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

    # Create a real Stripe Checkout Session
    session = stripe.checkout.Session.create(
        mode="payment",
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        customer_email=email,
        success_url=CHECKOUT_SUCCESS_URL,
        cancel_url=CHECKOUT_CANCEL_URL,
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
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {str(e)}")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]

        # Only activate if actually paid
        if session.get("payment_status") != "paid":
            return {"ok": True}

        customer_id = session.get("customer")
        checkout_session_id = session.get("id")
        payment_intent_id = session.get("payment_intent")

        customer_details = session.get("customer_details") or {}
        email = customer_details.get("email") or session.get("customer_email")
        if email:
            email = _email_norm(email)

        if not email:
            return {"ok": True, "license_updated": False, "reason": "no_email"}

        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO public.licenses (email, active, device_limit,
                                            stripe_customer_id, stripe_checkout_session_id, stripe_payment_intent_id)
                VALUES (%s, TRUE, 2, %s, %s, %s)
                ON CONFLICT (email)
                DO UPDATE SET active = TRUE,
                              stripe_customer_id = EXCLUDED.stripe_customer_id,
                              stripe_checkout_session_id = EXCLUDED.stripe_checkout_session_id,
                              stripe_payment_intent_id = EXCLUDED.stripe_payment_intent_id,
                              updated_at = now()
                """,
                (email, customer_id, checkout_session_id, payment_intent_id),
            )
            conn.commit()

        return {"ok": True, "email": email, "activated": True}

    return {"ok": True}

# ==========================
# STEP 3: DEVICE LICENSE CHECK
# ==========================
class LicenseCheckIn(BaseModel):
    device_fingerprint: str

@app.post("/license/check")
def license_check(data: LicenseCheckIn, request: Request):
    """
    Desktop app sends:
      - Authorization: Bearer <JWT from /auth/login>
      - JSON: { "device_fingerprint": "..." }

    Returns:
      - allowed (bool)
      - reason (string)
      - devices_used (int)
      - device_limit (int)
    """
    email = _email_from_bearer(request)
    fp = (data.device_fingerprint or "").strip()

    if not fp:
        raise HTTPException(status_code=400, detail="device_fingerprint required")

    with db() as conn:
        cur = conn.cursor()

        # Transaction (default) + FOR UPDATE prevents two concurrent logins
        cur.execute(
            """
            SELECT id, active, device_limit
            FROM public.licenses
            WHERE email=%s
            FOR UPDATE
            """,
            (email,),
        )
        lic = cur.fetchone()

        if not lic:
            conn.commit()
            return {
                "allowed": False,
                "reason": "no_license_row",
                "devices_used": 0,
                "device_limit": 0,
            }

        license_id, active, device_limit = lic[0], bool(lic[1]), int(lic[2] or 0)

        # Count active devices helper
        def count_active_devices() -> int:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM public.devices
                WHERE license_id=%s AND revoked=FALSE
                """,
                (license_id,),
            )
            return int(cur.fetchone()[0])

        if not active:
            used = count_active_devices()
            conn.commit()
            return {
                "allowed": False,
                "reason": "license_inactive",
                "devices_used": used,
                "device_limit": device_limit,
            }

        # If already registered (and not revoked), allow
        cur.execute(
            """
            SELECT 1
            FROM public.devices
            WHERE license_id=%s AND device_fingerprint=%s AND revoked=FALSE
            """,
            (license_id, fp),
        )
        if cur.fetchone():
            used = count_active_devices()
            conn.commit()
            return {
                "allowed": True,
                "reason": "device_already_registered",
                "devices_used": used,
                "device_limit": device_limit,
            }

        # Not registered -> check limit
        used = count_active_devices()
        if used >= device_limit:
            conn.commit()
            return {
                "allowed": False,
                "reason": "device_limit_exceeded",
                "devices_used": used,
                "device_limit": device_limit,
            }

        # Under limit -> register new device (Option 1: reinstall counts as a new device)
        cur.execute(
            """
            INSERT INTO public.devices (license_id, device_fingerprint, revoked)
            VALUES (%s, %s, FALSE)
            """,
            (license_id, fp),
        )

        used_after = count_active_devices()
        conn.commit()

        return {
            "allowed": True,
            "reason": "device_registered",
            "devices_used": used_after,
            "device_limit": device_limit,
        }
