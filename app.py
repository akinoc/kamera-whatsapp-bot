from __future__ import annotations

import email
import hashlib
import hmac
import imaplib
import json
import logging
import os
import re
import tempfile
from datetime import datetime
from email.header import decode_header
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)

# ============================================================
# RENDER ENVIRONMENT VARIABLES
# ============================================================

GMAIL_USER = os.getenv("GMAIL_USER", "").strip()

GMAIL_APP_PASSWORD = (
    os.getenv("GMAIL_APP_PASSWORD", "")
    .replace(" ", "")
    .strip()
)

GMAIL_FOLDER = os.getenv("GMAIL_FOLDER", "INBOX").strip() or "INBOX"

ALARM_SUBJECT_FILTER = (
    os.getenv("ALARM_SUBJECT_FILTER", "Alarm Message")
    .strip()
    .lower()
)

DESK360_API_KEY = os.getenv("DESK360_API_KEY", "").strip()

DESK360_WEBHOOK_TOKEN = os.getenv(
    "DESK360_WEBHOOK_TOKEN",
    "",
).strip()

CONTROL_TOKEN = os.getenv(
    "CONTROL_TOKEN",
    "",
).strip()

ADMIN_PHONE = os.getenv(
    "ADMIN_PHONE",
    "",
).strip()

SECONDARY_PHONE = os.getenv(
    "SECONDARY_PHONE",
    "",
).strip()

TIMEZONE_NAME = os.getenv(
    "TIMEZONE",
    "Europe/Istanbul",
).strip()

SECONDARY_START_HOUR = int(
    os.getenv("SECONDARY_START_HOUR", "9")
)

SECONDARY_END_HOUR = int(
    os.getenv("SECONDARY_END_HOUR", "18")
)

MAX_UNREAD_MESSAGES = max(
    1,
    int(os.getenv("MAX_UNREAD_MESSAGES", "20")),
)

# Render yeniden başlatılırsa /tmp içindeki kayıt silinebilir.
LAST_WEBHOOK_FILE = "/tmp/desk360_last_webhook.json"


# ============================================================
# GENEL YARDIMCI FONKSİYONLAR
# ============================================================

def local_now() -> datetime:
    return datetime.now(ZoneInfo(TIMEZONE_NAME))


def decode_text(value: str | None) -> str:
    if not value:
        return ""

    result: list[str] = []

    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            result.append(
                part.decode(
                    encoding or "utf-8",
                    errors="replace",
                )
            )
        else:
            result.append(part)

    return "".join(result)


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")

    if not digits:
        raise ValueError("Telefon numarası boş.")

    return f"+{digits}"


def secondary_is_active(
    at: datetime | None = None,
) -> bool:
    """
    Secondary numara:
    - Pazartesi-Cuma
    - 09:00 dahil
    - 18:00 hariç
    """
    now = at or local_now()

    is_weekday = now.weekday() < 5

    is_working_hours = (
        SECONDARY_START_HOUR
        <= now.hour
        < SECONDARY_END_HOUR
    )

    return is_weekday and is_working_hours


def get_recipients(
    at: datetime | None = None,
) -> list[str]:
    recipients: list[str] = []

    if ADMIN_PHONE:
        recipients.append(normalize_phone(ADMIN_PHONE))

    if SECONDARY_PHONE and secondary_is_active(at):
        recipients.append(
            normalize_phone(SECONDARY_PHONE)
        )

    # Aynı numara iki kez tanımlanmışsa tekilleştirir.
    return list(dict.fromkeys(recipients))


def require_control_token() -> tuple[dict[str, Any], int] | None:
    """
    /last-webhook ve /check-mail gibi yönetim adreslerini korur.
    """
    if not CONTROL_TOKEN:
        return (
            {
                "success": False,
                "error": (
                    "CONTROL_TOKEN Render'da "
                    "tanımlı değil."
                ),
            },
            503,
        )

    provided = (
        request.args.get("token", "")
        or request.headers.get("X-Control-Token", "")
    )

    if not hmac.compare_digest(
        provided,
        CONTROL_TOKEN,
    ):
        return (
            {
                "success": False,
                "error": "Yetkisiz istek.",
            },
            401,
        )

    return None


# ============================================================
# DESK360 WEBHOOK ANALİZİ
# ============================================================

def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Hassas olabilecek HTTP başlıklarını gizler.
    """
    hidden_names = {
        "authorization",
        "token",
        "x-token",
        "x-webhook-token",
        "x-api-key",
        "api-key",
        "cookie",
    }

    result: dict[str, str] = {}

    for name, value in headers.items():
        if name.lower() in hidden_names:
            result[name] = "***GİZLENDİ***"
        else:
            result[name] = value

    return result


def find_possible_ids(
    value: Any,
    path: str = "root",
) -> list[dict[str, Any]]:
    """
    Desk360 webhook içindeki olası entegrasyon ve Meta
    kimliklerini otomatik olarak bulmaya çalışır.
    """
    results: list[dict[str, Any]] = []

    exact_target_names = {
        "integrationid",
        "integration_id",
        "integration",
        "phone_number_id",
        "phonenumberid",
        "waba_id",
        "wabaid",
        "business_account_id",
        "businessaccountid",
        "whatsapp_business_account_id",
        "whatsappbusinessaccountid",
    }

    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            normalized_key = key.lower().replace("-", "_")

            if (
                normalized_key in exact_target_names
                or "integration" in normalized_key
                or normalized_key.endswith("_id")
                or normalized_key.endswith("id")
            ):
                results.append(
                    {
                        "path": child_path,
                        "field": key,
                        "value": child,
                    }
                )

            results.extend(
                find_possible_ids(
                    child,
                    child_path,
                )
            )

    elif isinstance(value, list):
        for index, child in enumerate(value):
            results.extend(
                find_possible_ids(
                    child,
                    f"{path}[{index}]",
                )
            )

    return results


def verify_optional_webhook_token() -> bool:
    """
    Desk360 token'ı hangi başlıkla gönderirse göndersin,
    yaygın alanlarda kontrol etmeye çalışır.

    Token hiç gönderilmezse webhook'u reddetmez; yalnızca
    kaydı alır. Böylece ilk test sırasında veri kaybolmaz.
    """
    if not DESK360_WEBHOOK_TOKEN:
        return True

    candidates = [
        request.headers.get("Authorization", ""),
        request.headers.get("Token", ""),
        request.headers.get("X-Token", ""),
        request.headers.get("X-Webhook-Token", ""),
        request.args.get("token", ""),
    ]

    for candidate in candidates:
        clean_candidate = candidate.strip()

        if clean_candidate.lower().startswith("bearer "):
            clean_candidate = clean_candidate[7:].strip()

        if clean_candidate and hmac.compare_digest(
            clean_candidate,
            DESK360_WEBHOOK_TOKEN,
        ):
            return True

    # İlk kurulumda Desk360'ın token'ı farklı yerde gönderme
    # ihtimaline karşı veri kaybını önlemek için engellemiyoruz.
    return False


# ============================================================
# GMAIL / JPG KONTROLÜ
# ============================================================

def message_matches(
    message: email.message.Message,
) -> bool:
    subject = decode_text(
        message.get("Subject")
    ).lower()

    if (
        ALARM_SUBJECT_FILTER
        and ALARM_SUBJECT_FILTER not in subject
    ):
        return False

    return True


def find_jpg_attachments() -> dict[str, Any]:
    """
    Okunmamış alarm e-postalarını kontrol eder.

    Bu test fonksiyonu:
    - Fotoğrafı WhatsApp'a göndermez.
    - E-postayı okundu yapmaz.
    """
    if not GMAIL_USER:
        raise RuntimeError(
            "GMAIL_USER Render'da eksik."
        )

    if not GMAIL_APP_PASSWORD:
        raise RuntimeError(
            "GMAIL_APP_PASSWORD Render'da eksik."
        )

    result: dict[str, Any] = {
        "checked_unread": 0,
        "matched_messages": 0,
        "images_found": 0,
        "messages": [],
    }

    mailbox = imaplib.IMAP4_SSL(
        "imap.gmail.com",
        993,
    )

    temporary_paths: list[str] = []

    try:
        mailbox.login(
            GMAIL_USER,
            GMAIL_APP_PASSWORD,
        )

        status, _ = mailbox.select(GMAIL_FOLDER)

        if status != "OK":
            raise RuntimeError(
                f"Gmail klasörü açılamadı: {GMAIL_FOLDER}"
            )

        status, data = mailbox.uid(
            "search",
            None,
            "UNSEEN",
        )

        if status != "OK":
            raise RuntimeError(
                "Gmail UNSEEN araması başarısız."
            )

        uids = data[0].split()[-MAX_UNREAD_MESSAGES:]

        result["checked_unread"] = len(uids)

        for uid_bytes in reversed(uids):
            uid = uid_bytes.decode()

            status, fetched = mailbox.uid(
                "fetch",
                uid_bytes,
                "(RFC822)",
            )

            if (
                status != "OK"
                or not fetched
                or not isinstance(fetched[0], tuple)
            ):
                continue

            message = email.message_from_bytes(
                fetched[0][1]
            )

            if not message_matches(message):
                continue

            result["matched_messages"] += 1

            attachments: list[dict[str, Any]] = []

            for part in message.walk():
                filename = decode_text(
                    part.get_filename()
                )

                content_type = (
                    part.get_content_type() or ""
                ).lower()

                extension = (
                    Path(filename).suffix.lower()
                    if filename
                    else ""
                )

                is_jpg = (
                    extension in {".jpg", ".jpeg"}
                    or content_type == "image/jpeg"
                )

                if not is_jpg:
                    continue

                payload = part.get_payload(decode=True)

                if not payload:
                    continue

                suffix = (
                    extension
                    if extension in {".jpg", ".jpeg"}
                    else ".jpg"
                )

                with tempfile.NamedTemporaryFile(
                    prefix="besta_",
                    suffix=suffix,
                    delete=False,
                ) as temp_file:
                    temp_file.write(payload)
                    temp_path = temp_file.name

                temporary_paths.append(temp_path)

                attachments.append(
                    {
                        "filename": (
                            filename
                            or Path(temp_path).name
                        ),
                        "size_bytes": len(payload),
                        "sha256": hashlib.sha256(
                            payload
                        ).hexdigest(),
                    }
                )

            if attachments:
                result["images_found"] += len(
                    attachments
                )

                result["messages"].append(
                    {
                        "uid": uid,
                        "subject": decode_text(
                            message.get("Subject")
                        ),
                        "sender": decode_text(
                            message.get("From")
                        ),
                        "date": decode_text(
                            message.get("Date")
                        ),
                        "attachments": attachments,
                    }
                )

        return result

    finally:
        try:
            mailbox.logout()
        except Exception:
            pass

        for path in temporary_paths:
            try:
                os.remove(path)
            except OSError:
                pass


# ============================================================
# FLASK ENDPOINTLERİ
# ============================================================

@app.get("/")
@app.get("/health")
def health() -> Any:
    return jsonify(
        {
            "status": "ok",
            "service": "kamera-whatsapp-bot",
            "local_time": local_now().isoformat(),
            "secondary_active": secondary_is_active(),
            "recipients_defined": {
                "admin": bool(ADMIN_PHONE),
                "secondary": bool(SECONDARY_PHONE),
            },
            "desk360_api_key_defined": bool(
                DESK360_API_KEY
            ),
            "desk360_webhook_token_defined": bool(
                DESK360_WEBHOOK_TOKEN
            ),
            "gmail_defined": bool(
                GMAIL_USER and GMAIL_APP_PASSWORD
            ),
        }
    )


@app.route(
    "/desk360-webhook",
    methods=["GET", "POST"],
)
def desk360_webhook() -> Any:
    """
    Desk360 Public API kayıt ekranına yazılacak adres:

    https://kamera-whatsapp-bot.onrender.com/desk360-webhook
    """
    if request.method == "GET":
        return jsonify(
            {
                "success": True,
                "message": "Desk360 webhook aktif.",
            }
        ), 200

    token_verified = verify_optional_webhook_token()

    payload = request.get_json(silent=True)

    if payload is None:
        form_data = request.form.to_dict(flat=False)
        raw_body = request.get_data(
            as_text=True
        )

        payload = {
            "form_data": form_data,
            "raw_body": raw_body,
        }

    record = {
        "received_at": local_now().isoformat(),
        "token_verified": token_verified,
        "method": request.method,
        "content_type": request.content_type,
        "headers": sanitize_headers(
            dict(request.headers)
        ),
        "query_parameters": (
            request.args.to_dict(flat=False)
        ),
        "payload": payload,
        "possible_ids": find_possible_ids(payload),
    }

    with open(
        LAST_WEBHOOK_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            record,
            file,
            ensure_ascii=False,
            indent=2,
            default=str,
        )

    logging.info(
        "Desk360 webhook kaydedildi. "
        "Token doğrulandı: %s, olası ID sayısı: %s",
        token_verified,
        len(record["possible_ids"]),
    )

    return jsonify(
        {
            "success": True,
            "message": "Desk360 webhook alındı.",
            "possible_id_count": len(
                record["possible_ids"]
            ),
        }
    ), 200


@app.get("/last-webhook")
def last_webhook() -> Any:
    """
    Son Desk360 webhook içeriğini gösterir.

    Örnek:
    /last-webhook?token=GERCEK_CONTROL_TOKEN
    """
    denied = require_control_token()

    if denied:
        return jsonify(denied[0]), denied[1]

    if not os.path.exists(LAST_WEBHOOK_FILE):
        return jsonify(
            {
                "success": False,
                "error": (
                    "Henüz Desk360 webhook isteği gelmedi."
                ),
            }
        ), 404

    with open(
        LAST_WEBHOOK_FILE,
        "r",
        encoding="utf-8",
    ) as file:
        record = json.load(file)

    return jsonify(
        {
            "success": True,
            **record,
        }
    )


@app.get("/recipients")
def recipients_endpoint() -> Any:
    denied = require_control_token()

    if denied:
        return jsonify(denied[0]), denied[1]

    now = local_now()

    return jsonify(
        {
            "success": True,
            "local_time": now.isoformat(),
            "secondary_active": secondary_is_active(
                now
            ),
            "secondary_schedule": {
                "days": "Monday-Friday",
                "start_hour": SECONDARY_START_HOUR,
                "end_hour": SECONDARY_END_HOUR,
            },
            "recipients": get_recipients(now),
        }
    )


@app.get("/check-mail")
def check_mail_endpoint() -> Any:
    denied = require_control_token()

    if denied:
        return jsonify(denied[0]), denied[1]

    try:
        result = find_jpg_attachments()

        return jsonify(
            {
                "success": True,
                "local_time": local_now().isoformat(),
                "secondary_active": (
                    secondary_is_active()
                ),
                "current_recipients": (
                    get_recipients()
                ),
                **result,
            }
        )

    except Exception as exc:
        logging.exception(
            "Gmail kontrolü başarısız."
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 500
