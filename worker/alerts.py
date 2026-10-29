import smtplib
from email.message import EmailMessage

from app.core.config import (
    ALERT_EMAIL,
    ALERT_FROM_EMAIL,
    SMTP_HOST,
    SMTP_PASS,
    SMTP_PORT,
    SMTP_USE_TLS,
    SMTP_USER,
)


def send_alert_if_critical(target, scan_id: int) -> None:
    """Envía alerta por email cuando se detecta un hallazgo crítico.

    Soporta cualquier servidor SMTP (SendGrid, AWS SES, Mailgun, etc.)
    configurado mediante variables de entorno. En desarrollo falla en silencio.
    """
    msg = EmailMessage()
    msg["Subject"] = f"[Cybersec SaaS] Critical finding on {target.name}"
    msg["From"] = ALERT_FROM_EMAIL
    msg["To"] = ALERT_EMAIL
    msg.set_content(
        f"A new critical finding was detected on {target.name} ({target.url}) "
        f"during scan {scan_id}. Check the dashboard.\n\n"
        f"Severity: critical\n"
        f"Target: {target.url}\n"
        f"Scan ID: {scan_id}\n"
    )
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
            if SMTP_USE_TLS:
                smtp.starttls()
            if SMTP_USER and SMTP_PASS:
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
    except Exception:  # noqa: BLE001 - dev SMTP may be unavailable; alert is best-effort
        pass
