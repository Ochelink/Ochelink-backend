from __future__ import annotations

import html


def _base(title: str, preheader: str, body_html: str) -> str:
    # Simple, brandable, inbox-friendly HTML (no external assets)
    # Keeps styling conservative to avoid spam triggers.
    title_esc = html.escape(title)
    preheader_esc = html.escape(preheader)

    return f"""
<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>{title_esc}</title>
  </head>
  <body style=\"margin:0;padding:0;background:#0b0f14;\">
    <div style=\"display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;\">{preheader_esc}</div>
    <table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"background:#0b0f14;padding:24px 0;\">
      <tr>
        <td align=\"center\">
          <table role=\"presentation\" width=\"600\" cellspacing=\"0\" cellpadding=\"0\" style=\"width:600px;max-width:92vw;background:#111826;border-radius:16px;overflow:hidden;\">
            <tr>
              <td style=\"padding:22px 24px;background:#0f1724;\">
                <div style=\"font-family:Arial,Helvetica,sans-serif;font-size:14px;letter-spacing:0.2px;color:#cbd5e1;\">OCHELINK</div>
                <div style=\"font-family:Arial,Helvetica,sans-serif;font-size:22px;font-weight:700;color:#ffffff;margin-top:6px;\">{title_esc}</div>
              </td>
            </tr>
            <tr>
              <td style=\"padding:22px 24px;font-family:Arial,Helvetica,sans-serif;color:#e5e7eb;font-size:15px;line-height:1.6;\">
                {body_html}
                <div style=\"margin-top:18px;font-size:12px;color:#94a3b8;\">
                  If you didn’t request this, you can safely ignore this email.
                </div>
              </td>
            </tr>
            <tr>
              <td style=\"padding:16px 24px;background:#0f1724;font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#94a3b8;\">
                © OcheLink • Support: reply to this email
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
""".strip()


def _button(url: str, label: str) -> str:
    url_esc = html.escape(url, quote=True)
    label_esc = html.escape(label)
    return (
        f"<div style=\"margin:18px 0 10px;\">"
        f"<a href=\"{url_esc}\" style=\"display:inline-block;background:#3b82f6;color:#ffffff;"
        f"text-decoration:none;padding:12px 16px;border-radius:10px;font-weight:700;\">{label_esc}</a>"
        f"</div>"
        f"<div style=\"font-size:12px;color:#94a3b8;word-break:break-all;\">Or paste this link into your browser:<br/>{url_esc}</div>"
    )


def verification_email(verify_url: str) -> tuple[str, str]:
    subject = "Verify your OcheLink email"
    body = (
        "<div style=\"font-size:15px;\">"
        "Please verify your email address to continue to purchase and activate your license."
        "</div>"
        + _button(verify_url, "Verify email")
        + "<div style=\"margin-top:12px;font-size:13px;color:#cbd5e1;\">This link expires in 24 hours.</div>"
    )
    html_doc = _base("Verify your email", "Verify your email to continue", body)
    return subject, html_doc


def password_reset_email(reset_url: str) -> tuple[str, str]:
    subject = "Reset your OcheLink password"
    body = (
        "<div style=\"font-size:15px;\">"
        "We received a request to reset your OcheLink password."
        "</div>"
        + _button(reset_url, "Reset password")
        + "<div style=\"margin-top:12px;font-size:13px;color:#cbd5e1;\">This link expires in 60 minutes.</div>"
    )
    html_doc = _base("Reset your password", "Reset your OcheLink password", body)
    return subject, html_doc


def license_activated_email(download_url: str) -> tuple[str, str]:
    subject = "Your OcheLink license is activated"
    body = (
        "<div style=\"font-size:15px;\">"
        "Thanks for your purchase — your lifetime license is now activated."
        "</div>"
        + _button(download_url, "Download OcheLink")
        + "<div style=\"margin-top:12px;font-size:13px;color:#cbd5e1;\">"
        "Remember: 1 license = 2 devices. Reinstall counts as a new device (as designed)."
        "</div>"
    )
    html_doc = _base("License activated", "Your license is activated", body)
    return subject, html_doc
