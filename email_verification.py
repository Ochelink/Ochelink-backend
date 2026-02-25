from __future__ import annotations

import os
import logging
import psycopg2

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, EmailStr
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

logger = logging.getLogger("uvicorn.error")
def _log(msg: str, *args):
    try:
        logger.info(msg, *args)
    except Exception:
        pass
    try:
        print("[email_verification]", msg % args if args else msg, flush=True)
    except Exception:
        print("[email_verification]", msg, flush=True)

# Log env presence (masked) at import time for quick diagnosis
try:
    _log("Loaded. FRONTEND_URL=%s EMAIL_FROM=%s RESEND_API_KEY_set=%s EMAIL_SECRET_set=%s",
         os.environ.get("FRONTEND_URL"), os.environ.get("EMAIL_FROM"),
         bool(os.environ.get("RESEND_API_KEY")), bool(os.environ.get("EMAIL_SECRET")))
except Exception:
    pass

# -------------------------
# ENV
# -------------------------
DATABASE_URL = os.environ["DATABASE_URL"]

EMAIL_SECRET = os.environ.get("EMAIL_SECRET", "")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://ochelink.com").rstrip("/")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "Ochelink@outlook.com")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")

VERIFY_SALT = "email-verify"
VERIFY_TOKEN_MAX_AGE_SECONDS = 60 * 60 * 24  # 24 hours


def _email_norm(email: str) -> str:
    return str(email).strip().lower()


def db():
    return psycopg2.connect(DATABASE_URL)


def _serializer() -> URLSafeTimedSerializer:
    if not EMAIL_SECRET:
        raise RuntimeError("EMAIL_SECRET is missing. Set it in Render env vars.")
    return URLSafeTimedSerializer(EMAIL_SECRET)


def make_verification_token(email: str) -> str:
    return _serializer().dumps(_email_norm(email), salt=VERIFY_SALT)


def read_verification_token(token: str) -> str:
    try:
        email = _serializer().loads(
            token,
            salt=VERIFY_SALT,
            max_age=VERIFY_TOKEN_MAX_AGE_SECONDS,
        )
        return _email_norm(email)
    except SignatureExpired:
        raise HTTPException(status_code=400, detail="Verification link expired")
    except BadSignature:
        raise HTTPException(status_code=400, detail="Invalid verification token")


def build_verify_link(token: str) -> str:
    # Recommended UX: website page handles this and calls backend.
    return f"{FRONTEND_URL}/verify-email?token={token}"


def _send_email_resend(to_email: str, subject: str, html: str) -> None:
    """Send an email via Resend API."""
    import requests

    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "from": EMAIL_FROM,
            "to": [to_email],
            "subject": subject,
            "html": html,
        },
        timeout=15,
    )

    _log('Resend response %s for %s', resp.status_code, to_email)

    if resp.status_code >= 400:
        raise RuntimeError(f"Resend error {resp.status_code}: {resp.text}")



def send_verification_email(email: str) -> str:
    _log('Sending verification email to %s', _email_norm(email))
    """
    Sends (or logs) the verification email.
    Returns the verify link (useful for testing).
    """
    token = make_verification_token(email)
    link = build_verify_link(token)

    subject = "Verify your OcheLink email"
    html = f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.5;">
      <h2>Verify your email</h2>
      <p>Please verify your email address to finish setting up your OcheLink account.</p>
      <p><a href="{link}">Verify email</a></p>
      <p>This link expires in 24 hours.</p>
      <p>If you didn’t create an account, you can ignore this email.</p>
    </div>
    """.strip()

    if RESEND_API_KEY and RESEND_API_KEY.strip():
        try:
            _send_email_resend(_email_norm(email), subject, html)
        except Exception:
            _log('Resend send failed; logging verify link instead.')
            logger.exception('Resend send failed')
            _log('VERIFY LINK for %s: %s', _email_norm(email), link)
    else:
        # Safe fallback — doesn't break your backend while email is not configured.
        _log('RESEND_API_KEY not set. VERIFY LINK for %s: %s', _email_norm(email), link)

    return link


router = APIRouter(prefix="/auth", tags=["auth"])


class SendVerificationBody(BaseModel):
    email: EmailStr


@router.post("/send-verification")
def send_verification(body: SendVerificationBody):
    """
    Resend verification email. Always returns ok to prevent user enumeration.
    """
    email = _email_norm(body.email)

    with db() as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT is_verified FROM public.users WHERE email=%s", (email,))
            row = cur.fetchone()
        except psycopg2.errors.UndefinedColumn:
            # If column not yet migrated, treat as verified to avoid breaking auth.
            return {"ok": True}

    if not row:
        _log('send-verification: no user for %s (returning ok)', email)
        return {"ok": True}

    is_verified = bool(row[0]) if row[0] is not None else False
    if is_verified:
        _log('send-verification: already verified for %s (returning ok)', email)
        return {"ok": True}

    send_verification_email(email)
    return {"ok": True}


@router.get("/verify-email")
def verify_email(token: str = Query(..., description="Email verification token")):
    email = read_verification_token(token)

    with db() as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT id, is_verified FROM public.users WHERE email=%s", (email,))
        except psycopg2.errors.UndefinedColumn:
            raise HTTPException(
                status_code=500,
                detail="Email verification not enabled on DB (missing users.is_verified column)",
            )

        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        user_id, is_verified = row[0], bool(row[1]) if row[1] is not None else False
        if is_verified:
            return {"ok": True, "message": "Already verified"}

        cur.execute("UPDATE public.users SET is_verified=TRUE WHERE id=%s", (user_id,))
        conn.commit()

    return {"ok": True, "message": "Email verified"}
