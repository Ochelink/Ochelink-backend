from __future__ import annotations

import os
import logging

logger = logging.getLogger("uvicorn.error")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "support@ochelink.com")


def resend_send(to_email: str, subject: str, html: str) -> tuple[int, str]:
    """Send email via Resend. Returns (status_code, response_text)."""
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
    return resp.status_code, resp.text


def send_email(to_email: str, subject: str, html: str, *, fallback_log: str | None = None) -> None:
    """Best-effort email send. Never raises unless explicitly asked."""
    if not RESEND_API_KEY:
        logger.info("RESEND_API_KEY not set. %s", fallback_log or f"Email to {to_email} not sent")
        try:
            print("[email] RESEND_API_KEY not set.", fallback_log or "", flush=True)
        except Exception:
            pass
        return

    try:
        status, text = resend_send(to_email, subject, html)
        logger.info("Resend response %s for %s", status, to_email)
        try:
            print("[email] resend status", status, "to", to_email, flush=True)
        except Exception:
            pass
        if status >= 400:
            logger.error("Resend error %s: %s", status, text)
            try:
                print("[email] resend error", status, text[:500], flush=True)
            except Exception:
                pass
    except Exception as e:
        logger.exception("Resend send failed: %s", e)
        try:
            print("[email] resend exception", e, flush=True)
        except Exception:
            pass
