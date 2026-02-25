OcheLink Backend (Render + FastAPI)

This zip contains your working backend plus Email Verification (v10 - Resend).

Changes in v10 (Resend email sender)
- Added email_verification.py
- Added routes:
  - POST /auth/send-verification
  - GET  /auth/verify-email?token=...
- /auth/register now sends a verification email (non-blocking; failures never break signup)
- /auth/login blocks unverified users (403) once DB column exists
- requirements.txt includes itsdangerous + requests (Resend)

Supabase migration (run once)
- Add column to public.users:

  ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;

Render environment variables to add
- EMAIL_SECRET   = long random string (keep private)
- FRONTEND_URL   = https://ochelink.com
- EMAIL_FROM     = Ochelink@outlook.com   (display/from address)
- RESEND_API_KEY  = (required to actually send emails)

Notes
- If RESEND_API_KEY is not set, the backend will log the verification link instead of sending email.
- This is intentional so you can deploy safely before configuring email delivery.


## Verification-gated purchase flow (added)
- /me now supports Authorization: Bearer <JWT> and returns is_verified.
- /billing/create-checkout-session returns 403 if the user's email is not verified.
- /auth/login returns access_token plus is_verified.
