from __future__ import annotations

import email
import hashlib
import hmac
import imaplib
import logging
import os
import re
import tempfile
from datetime import datetime
from email.header import decode_header
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import requests
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

DESK360_BASE_URL = (
    os.getenv(
        "DESK360_BASE_URL",
        "https://public-api.desk360.com/v1",
    )
    .strip()
    .rstrip("/")
)

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

REQUEST_TIMEOUT_SECONDS = max(
    10,
    int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
)


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
    Pazartesi-Cuma, 09:00 dahil, 18:00 hariç.
    """
    now = at or local_now()

    is_weekday = now.weekday() < 5

    is_working_hour = (
        SECONDARY_START_HOUR
        <= now.hour
        < SECONDARY_END_HOUR
    )

    return is_weekday and is_working_hour


def get_recipients(
    at: datetime | None = None,
) -> list[str]:
    recipients: list[str] = []

    if ADMIN_PHONE:
        recipients.append(
            normalize_phone(ADMIN_PHONE)
        )

    if (
        SECONDARY_PHONE
        and secondary_is_active(at)
    ):
        recipients.append(
            normalize_phone(SECONDARY_PHONE)
        )

    # Aynı numara iki kez girildiyse tekilleştirir.
    return list(dict.fromkeys(recipients))


def require_control_token() -> tuple[dict[str, Any], int] | None:
    """
    Yönetim/test adreslerini dış erişime karşı korur.
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
        or request.headers.get(
            "X-Control-Token",
            "",
        )
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


def safe_response_body(
    response: requests.Response,
) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text[:4000]


# ============================================================
# DESK360 API
# ============================================================

def desk360_headers() -> dict[str, str]:
    if not DESK360_API_KEY:
        raise RuntimeError(
            "DESK360_API_KEY Render'da eksik."
        )

    return {
        "Authorization": (
            f"Bearer {DESK360_API_KEY}"
        ),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def desk360_get(path: str) -> Any:
    """
    Desk360 Public API'ye GET isteği gönderir.
    """
    url = f"{DESK360_BASE_URL}{path}"

    response = requests.get(
        url,
        headers=desk360_headers(),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    body = safe_response_body(response)

    if not response.ok:
        raise RuntimeError(
            f"Desk360 GET {path} başarısız: "
            f"HTTP {response.status_code} - {body}"
        )

    return body


def extract_possible_integration_ids(
    value: Any,
) -> list[dict[str, Any]]:
    """
    /integrations cevabındaki olası entegrasyon
    kimliklerini gösterir. Otomatik seçim yapmaz.
    """
    results: list[dict[str, Any]] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            possible_id = (
                item.get("integration_id")
                or item.get("integrationId")
                or item.get("id")
            )

            if possible_id is not None:
                results.append(
                    {
                        "possible_integration_id": (
                            possible_id
                        ),
                        "name": (
                            item.get("name")
                            or item.get("title")
                        ),
                        "phone": (
                            item.get("phone")
                            or item.get("phone_number")
                            or item.get("phoneNumber")
                        ),
                        "status": item.get("status"),
                        "type": item.get("type"),
                        "raw": item,
                    }
                )

            for child in item.values():
                walk(child)

        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)

    return results


# ============================================================
# GMAIL / JPG TESTİ
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
    Dosyaları WhatsApp'a göndermez ve e-postaları
    okundu olarak işaretlemez.
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

        status, _ = mailbox.select(
            GMAIL_FOLDER
        )

        if status != "OK":
            raise RuntimeError(
                f"Gmail klasörü açılamadı: "
                f"{GMAIL_FOLDER}"
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

        uids = data[0].split()[
            -MAX_UNREAD_MESSAGES:
        ]

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
                or not isinstance(
                    fetched[0],
                    tuple,
                )
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

                payload = part.get_payload(
                    decode=True
                )

                if not payload:
                    continue

                suffix = (
                    extension
                    if extension in {
                        ".jpg",
                        ".jpeg",
                    }
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
# FLASK ADRESLERİ
# ============================================================

@app.get("/")
@app.get("/health")
def health() -> Any:
    return jsonify(
        {
            "status": "ok",
            "service": "kamera-whatsapp-bot",
            "local_time": local_now().isoformat(),
            "secondary_active": (
                secondary_is_active()
            ),
            "recipients_defined": {
                "admin": bool(ADMIN_PHONE),
                "secondary": bool(
                    SECONDARY_PHONE
                ),
            },
            "desk360_api_key_defined": bool(
                DESK360_API_KEY
            ),
            "gmail_defined": bool(
                GMAIL_USER
                and GMAIL_APP_PASSWORD
            ),
        }
    )


@app.route(
    "/desk360-webhook",
    methods=["GET", "POST"],
)
def desk360_webhook() -> Any:
    """
    Desk360 Public API kayıt ekranının zorunlu
    tuttuğu webhook adresidir.
    """
    if request.method == "POST":
        logging.info(
            "Desk360 webhook isteği alındı."
        )

    return jsonify(
        {
            "success": True,
            "message": (
                "Desk360 webhook aktif."
            ),
        }
    ), 200


@app.get("/recipients")
def recipients_endpoint() -> Any:
    denied = require_control_token()

    if denied:
        return jsonify(
            denied[0]
        ), denied[1]

    now = local_now()

    return jsonify(
        {
            "success": True,
            "local_time": now.isoformat(),
            "secondary_active": (
                secondary_is_active(now)
            ),
            "secondary_schedule": {
                "days": "Monday-Friday",
                "start_hour": (
                    SECONDARY_START_HOUR
                ),
                "end_hour": (
                    SECONDARY_END_HOUR
                ),
            },
            "recipients": get_recipients(now),
        }
    )


@app.get("/desk360-info")
def desk360_info() -> Any:
    """
    Şablon endpoint'ine kesinlikle gitmez.

    Sadece /integrations cevabını alarak gerçek
    integration ID'nin bulunmasını sağlar.
    """
    denied = require_control_token()

    if denied:
        return jsonify(
            denied[0]
        ), denied[1]

    try:
        integrations_response = desk360_get(
            "/integrations"
        )

        possible_integrations = (
            extract_possible_integration_ids(
                integrations_response
            )
        )

        return jsonify(
            {
                "success": True,
                "possible_integrations": (
                    possible_integrations
                ),
                "raw_integrations_response": (
                    integrations_response
                ),
            }
        )

    except Exception as exc:
        logging.exception(
            "Desk360 entegrasyon bilgisi "
            "alınamadı."
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 502


@app.get("/check-mail")
def check_mail_endpoint() -> Any:
    denied = require_control_token()

    if denied:
        return jsonify(
            denied[0]
        ), denied[1]

    try:
        result = find_jpg_attachments()

        return jsonify(
            {
                "success": True,
                "local_time": (
                    local_now().isoformat()
                ),
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
