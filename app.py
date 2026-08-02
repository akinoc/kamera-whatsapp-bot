from __future__ import annotations

import email
import hashlib
import imaplib
import json
import logging
import os
import re
import sqlite3
import tempfile
import threading
import time
from datetime import datetime
from email.header import decode_header
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterator
from zoneinfo import ZoneInfo

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)

# -----------------------------------------------------------------------------
# Environment variables
# -----------------------------------------------------------------------------
GMAIL_USER = os.getenv("GMAIL_USER", "").strip()
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "").replace(" ", "").strip()
GMAIL_FOLDER = os.getenv("GMAIL_FOLDER", "INBOX").strip() or "INBOX"
ALARM_FROM_FILTER = os.getenv("ALARM_FROM_FILTER", "").strip().lower()
ALARM_SUBJECT_FILTER = os.getenv("ALARM_SUBJECT_FILTER", "Alarm Message").strip().lower()

DESK360_API_KEY = os.getenv("DESK360_API_KEY", "").strip()
DESK360_BASE_URL = os.getenv(
    "DESK360_BASE_URL", "https://public-api.desk360.com/v1"
).rstrip("/")
DESK360_INTEGRATION_ID = os.getenv("DESK360_INTEGRATION_ID", "").strip()
DESK360_TEMPLATE_NAME = os.getenv(
    "DESK360_TEMPLATE_NAME", "kamera_alarm_bildirimi"
).strip()
DESK360_TEMPLATE_ID = os.getenv("DESK360_TEMPLATE_ID", "").strip()
DESK360_LANGUAGE_ID = os.getenv("DESK360_LANGUAGE_ID", "").strip()
DESK360_TEMPLATE_LANGUAGE = os.getenv("DESK360_TEMPLATE_LANGUAGE", "tr").strip().lower()
DESK360_PARAM_KEY_CAMERA = os.getenv("DESK360_PARAM_KEY_CAMERA", "").strip()
DESK360_PARAM_KEY_DATETIME = os.getenv("DESK360_PARAM_KEY_DATETIME", "").strip()
DESK360_WEBHOOK_TOKEN = os.getenv("DESK360_WEBHOOK_TOKEN", "").strip()

ADMIN_PHONE = os.getenv("ADMIN_PHONE", "").strip()
SECONDARY_PHONE = os.getenv("SECONDARY_PHONE", "").strip()
CAMERA_NAME = os.getenv("CAMERA_NAME", "Kapı Kamerası").strip()

TIMEZONE_NAME = os.getenv("TIMEZONE", "Europe/Istanbul").strip()
SECONDARY_START_HOUR = int(os.getenv("SECONDARY_START_HOUR", "9"))
SECONDARY_END_HOUR = int(os.getenv("SECONDARY_END_HOUR", "18"))
CHECK_INTERVAL_SECONDS = max(30, int(os.getenv("CHECK_INTERVAL_SECONDS", "60")))
MAX_UNREAD_MESSAGES = max(1, int(os.getenv("MAX_UNREAD_MESSAGES", "20")))
REQUEST_TIMEOUT_SECONDS = max(10, int(os.getenv("REQUEST_TIMEOUT_SECONDS", "45")))
ENABLE_BACKGROUND_WORKER = os.getenv("ENABLE_BACKGROUND_WORKER", "true").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
CONTROL_TOKEN = os.getenv("CONTROL_TOKEN", "").strip()
DATABASE_PATH = os.getenv("DATABASE_PATH", "/tmp/kamera_bot.sqlite3").strip()

mail_lock = threading.Lock()
cache_lock = threading.Lock()
worker_started = False

_cache: dict[str, Any] = {
    "integration_id": None,
    "template": None,
    "cached_at": 0.0,
}
CACHE_SECONDS = 900


# -----------------------------------------------------------------------------
# Generic helpers
# -----------------------------------------------------------------------------
def local_now() -> datetime:
    return datetime.now(ZoneInfo(TIMEZONE_NAME))


def decode_text(value: str | None) -> str:
    if not value:
        return ""
    result: list[str] = []
    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            result.append(part.decode(encoding or "utf-8", errors="replace"))
        else:
            result.append(part)
    return "".join(result)


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    if not digits:
        raise ValueError("Telefon numarası boş.")
    return f"+{digits}"


def secondary_is_active(at: datetime | None = None) -> bool:
    now = at or local_now()
    return now.weekday() < 5 and SECONDARY_START_HOUR <= now.hour < SECONDARY_END_HOUR


def get_recipients(at: datetime | None = None) -> list[str]:
    recipients: list[str] = []
    if ADMIN_PHONE:
        recipients.append(normalize_phone(ADMIN_PHONE))
    if SECONDARY_PHONE and secondary_is_active(at):
        recipients.append(normalize_phone(SECONDARY_PHONE))
    return list(dict.fromkeys(recipients))


def require_control_token() -> tuple[dict[str, Any], int] | None:
    if not CONTROL_TOKEN:
        return {"success": False, "error": "CONTROL_TOKEN Render'da tanımlı değil."}, 503
    provided = request.args.get("token", "") or request.headers.get("X-Control-Token", "")
    if not hashlib.sha256(provided.encode()).digest() == hashlib.sha256(
        CONTROL_TOKEN.encode()
    ).digest():
        return {"success": False, "error": "Yetkisiz istek."}, 401
    return None


def response_body(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text[:4000]


def iter_dicts(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_dicts(child)


def first_int(obj: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = obj.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


# -----------------------------------------------------------------------------
# SQLite duplicate protection
# -----------------------------------------------------------------------------
def init_database() -> None:
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS delivered (
                message_uid TEXT NOT NULL,
                attachment_sha256 TEXT NOT NULL,
                recipient TEXT NOT NULL,
                delivered_at TEXT NOT NULL,
                PRIMARY KEY (message_uid, attachment_sha256, recipient)
            )
            """
        )
        conn.commit()


def already_delivered(message_uid: str, file_hash: str, recipient: str) -> bool:
    with sqlite3.connect(DATABASE_PATH) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM delivered
            WHERE message_uid = ? AND attachment_sha256 = ? AND recipient = ?
            """,
            (message_uid, file_hash, recipient),
        ).fetchone()
        return row is not None


def record_delivered(message_uid: str, file_hash: str, recipient: str) -> None:
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO delivered
            (message_uid, attachment_sha256, recipient, delivered_at)
            VALUES (?, ?, ?, ?)
            """,
            (message_uid, file_hash, recipient, local_now().isoformat()),
        )
        conn.commit()


# -----------------------------------------------------------------------------
# Desk360 API discovery
# -----------------------------------------------------------------------------
def desk360_headers() -> dict[str, str]:
    if not DESK360_API_KEY:
        raise RuntimeError("DESK360_API_KEY eksik.")
    return {
        "Authorization": f"Bearer {DESK360_API_KEY}",
        "Accept": "application/json",
    }


def desk360_get(path: str) -> Any:
    response = requests.get(
        f"{DESK360_BASE_URL}{path}",
        headers=desk360_headers(),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    if not response.ok:
        raise RuntimeError(
            f"Desk360 GET {path} başarısız: HTTP {response.status_code} - "
            f"{response_body(response)}"
        )
    return response.json()


def discover_integration_id(force_refresh: bool = False) -> int:
    if DESK360_INTEGRATION_ID:
        if not DESK360_INTEGRATION_ID.isdigit():
            raise RuntimeError("DESK360_INTEGRATION_ID sayısal olmalı.")
        return int(DESK360_INTEGRATION_ID)

    with cache_lock:
        if (
            not force_refresh
            and _cache["integration_id"]
            and time.time() - _cache["cached_at"] < CACHE_SECONDS
        ):
            return int(_cache["integration_id"])

    payload = desk360_get("/integrations")
    candidates: list[tuple[int, dict[str, Any]]] = []
    for obj in iter_dicts(payload):
        integration_id = first_int(obj, ("integration_id", "integrationId", "id"))
        if integration_id is None:
            continue
        keys = {str(k).lower() for k in obj.keys()}
        if keys.intersection({"name", "title", "phone", "phone_number", "status", "type"}):
            candidates.append((integration_id, obj))

    if not candidates:
        raise RuntimeError(
            "Desk360 integration ID otomatik bulunamadı. /desk360-info çıktısına bakın "
            "ve DESK360_INTEGRATION_ID değişkenini tanımlayın."
        )

    integration_id = candidates[0][0]
    with cache_lock:
        _cache["integration_id"] = integration_id
        _cache["cached_at"] = time.time()
    return integration_id


def object_name(obj: dict[str, Any]) -> str:
    for key in ("name", "template_name", "templateName", "title"):
        value = obj.get(key)
        if isinstance(value, str):
            return value.strip()
    return ""


def language_matches(obj: dict[str, Any]) -> bool:
    wanted = DESK360_TEMPLATE_LANGUAGE.lower()
    values: list[str] = []
    for key in ("language", "language_code", "languageCode", "code", "locale", "name"):
        value = obj.get(key)
        if isinstance(value, str):
            values.append(value.lower())
    aliases = {wanted}
    if wanted in {"tr", "tr_tr", "tr-tr", "turkish", "türkçe"}:
        aliases.update({"tr", "tr_tr", "tr-tr", "turkish", "türkçe", "turkce"})
    return any(value in aliases or value.startswith("tr") for value in values)


def extract_parameter_keys(candidate: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    pattern = re.compile(r"^(?:body|header|button)[._-]?\d+$", re.IGNORECASE)

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if pattern.match(str(key)):
                    found.add(str(key))
                if isinstance(child, str) and pattern.match(child):
                    found.add(child)
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str) and pattern.match(value):
            found.add(value)

    visit(candidate)

    def sort_key(text: str) -> tuple[int, int, str]:
        lower = text.lower()
        group = 0 if lower.startswith("body") else 1
        match = re.search(r"(\d+)$", lower)
        return group, int(match.group(1)) if match else 999, lower

    return sorted(found, key=sort_key)


def discover_template(force_refresh: bool = False) -> dict[str, Any]:
    if DESK360_TEMPLATE_ID and DESK360_LANGUAGE_ID:
        keys = [
            key
            for key in (DESK360_PARAM_KEY_CAMERA, DESK360_PARAM_KEY_DATETIME)
            if key
        ]
        if len(keys) < 2:
            keys = ["body_1", "body_2"]
        return {
            "template_id": int(DESK360_TEMPLATE_ID),
            "language_id": int(DESK360_LANGUAGE_ID),
            "parameter_keys": keys,
            "source": "environment",
        }

    with cache_lock:
        if (
            not force_refresh
            and _cache["template"]
            and time.time() - _cache["cached_at"] < CACHE_SECONDS
        ):
            return dict(_cache["template"])

    integration_id = discover_integration_id(force_refresh=force_refresh)
    payload = desk360_get(f"/integrations/{integration_id}/conversations/templates")
    wanted_name = DESK360_TEMPLATE_NAME.casefold()

    template_candidates = [
        obj
        for obj in iter_dicts(payload)
        if object_name(obj).casefold() == wanted_name
    ]
    if not template_candidates:
        raise RuntimeError(
            f"'{DESK360_TEMPLATE_NAME}' şablonu Desk360 template listesinde bulunamadı. "
            "Şablonun Meta onayının tamamlandığını kontrol edin."
        )

    candidate = template_candidates[0]
    template_id = first_int(candidate, ("template_id", "templateId", "id"))
    if template_id is None:
        raise RuntimeError("Şablon bulundu ancak template_id okunamadı.")

    language_id: int | None = None
    for obj in iter_dicts(candidate):
        if language_matches(obj):
            language_id = first_int(obj, ("language_id", "languageId", "id"))
            if language_id is not None:
                break

    if language_id is None:
        language_id = first_int(candidate, ("language_id", "languageId"))

    if language_id is None:
        raise RuntimeError(
            "Şablon bulundu ancak language_id okunamadı. /desk360-info çıktısına bakın "
            "ve DESK360_LANGUAGE_ID değişkenini tanımlayın."
        )

    keys = extract_parameter_keys(candidate)
    body_keys = [key for key in keys if key.lower().startswith("body")]
    camera_key = DESK360_PARAM_KEY_CAMERA or (body_keys[0] if len(body_keys) >= 1 else "body_1")
    datetime_key = DESK360_PARAM_KEY_DATETIME or (
        body_keys[1] if len(body_keys) >= 2 else "body_2"
    )

    result = {
        "template_id": template_id,
        "language_id": language_id,
        "parameter_keys": [camera_key, datetime_key],
        "source": "auto-discovery",
    }
    with cache_lock:
        _cache["template"] = result
        _cache["cached_at"] = time.time()
    return result


def send_template_with_image(
    recipient: str,
    image_path: str,
    camera_name: str,
    event_time: str,
) -> dict[str, Any]:
    integration_id = discover_integration_id()
    template = discover_template()
    camera_key, datetime_key = template["parameter_keys"][:2]
    url = (
        f"{DESK360_BASE_URL}/integrations/{integration_id}"
        "/conversations/templates/send"
    )

    destination = {
        "phone": normalize_phone(recipient),
        "parameters": {
            camera_key: camera_name,
            datetime_key: event_time,
        },
    }

    # Desk360 dokümanı attachment içeren şablonlarda multipart/form-data ister.
    # API sürümleri nested alanları farklı şekilde yorumlayabildiği için yalnızca
    # validation (400/422) hatasında üç uyumlu form kodlamasını sırayla deneriz.
    variants: list[list[tuple[str, str]]] = [
        [
            ("template_id", str(template["template_id"])),
            ("language_id", str(template["language_id"])),
            ("destinations[0][phone]", destination["phone"]),
            (
                f"destinations[0][parameters][{camera_key}]",
                camera_name,
            ),
            (
                f"destinations[0][parameters][{datetime_key}]",
                event_time,
            ),
        ],
        [
            ("template_id", str(template["template_id"])),
            ("language_id", str(template["language_id"])),
            ("destinations", json.dumps([destination], ensure_ascii=False)),
        ],
        [
            ("template_id", str(template["template_id"])),
            ("language_id", str(template["language_id"])),
            ("destinations[]", json.dumps(destination, ensure_ascii=False)),
        ],
    ]

    last_response: requests.Response | None = None
    mime = "image/jpeg"
    for data in variants:
        with open(image_path, "rb") as image_file:
            files = {
                "attachment": (
                    Path(image_path).name,
                    image_file,
                    mime,
                )
            }
            response = requests.post(
                url,
                headers=desk360_headers(),
                data=data,
                files=files,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        last_response = response
        if response.ok:
            return {
                "success": True,
                "status_code": response.status_code,
                "response": response_body(response),
            }
        if response.status_code not in {400, 422}:
            break

    assert last_response is not None
    raise RuntimeError(
        "Desk360 şablon gönderimi başarısız: "
        f"HTTP {last_response.status_code} - {response_body(last_response)}"
    )


# -----------------------------------------------------------------------------
# Gmail processing
# -----------------------------------------------------------------------------
def message_matches(message: email.message.Message) -> bool:
    sender = decode_text(message.get("From")).lower()
    subject = decode_text(message.get("Subject")).lower()
    if ALARM_FROM_FILTER and ALARM_FROM_FILTER not in sender:
        return False
    if ALARM_SUBJECT_FILTER and ALARM_SUBJECT_FILTER not in subject:
        return False
    return True


def event_time_from_message(message: email.message.Message) -> str:
    raw_date = message.get("Date")
    if raw_date:
        try:
            parsed = parsedate_to_datetime(raw_date)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=ZoneInfo("UTC"))
            return parsed.astimezone(ZoneInfo(TIMEZONE_NAME)).strftime("%d.%m.%Y %H:%M:%S")
        except (TypeError, ValueError, OverflowError):
            pass
    return local_now().strftime("%d.%m.%Y %H:%M:%S")


def extract_jpg_attachments(message: email.message.Message) -> list[dict[str, str]]:
    attachments: list[dict[str, str]] = []
    for part in message.walk():
        filename = decode_text(part.get_filename())
        content_type = (part.get_content_type() or "").lower()
        extension = Path(filename).suffix.lower() if filename else ""
        if extension not in {".jpg", ".jpeg"} and content_type != "image/jpeg":
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        suffix = extension if extension in {".jpg", ".jpeg"} else ".jpg"
        with tempfile.NamedTemporaryFile(
            prefix="besta_", suffix=suffix, delete=False
        ) as temp_file:
            temp_file.write(payload)
            path = temp_file.name
        attachments.append(
            {
                "filename": filename or Path(path).name,
                "path": path,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return attachments


def process_mailbox(send_messages: bool = True) -> dict[str, Any]:
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise RuntimeError("GMAIL_USER veya GMAIL_APP_PASSWORD eksik.")

    summary: dict[str, Any] = {
        "checked_unread": 0,
        "matched_messages": 0,
        "images_found": 0,
        "sent": 0,
        "skipped_duplicate": 0,
        "errors": [],
        "recipients": get_recipients(),
    }

    mailbox = imaplib.IMAP4_SSL("imap.gmail.com", 993)
    try:
        mailbox.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        status, _ = mailbox.select(GMAIL_FOLDER)
        if status != "OK":
            raise RuntimeError(f"Gmail klasörü açılamadı: {GMAIL_FOLDER}")

        status, data = mailbox.uid("search", None, "UNSEEN")
        if status != "OK":
            raise RuntimeError("Gmail UNSEEN araması başarısız.")

        uids = data[0].split()[-MAX_UNREAD_MESSAGES:]
        summary["checked_unread"] = len(uids)

        for uid_bytes in uids:
            uid = uid_bytes.decode()
            status, fetched = mailbox.uid("fetch", uid_bytes, "(RFC822)")
            if status != "OK" or not fetched or not isinstance(fetched[0], tuple):
                continue

            message = email.message_from_bytes(fetched[0][1])
            if not message_matches(message):
                continue

            summary["matched_messages"] += 1
            attachments = extract_jpg_attachments(message)
            summary["images_found"] += len(attachments)
            if not attachments:
                continue

            recipients = get_recipients()
            if not recipients:
                summary["errors"].append(f"UID {uid}: alıcı numarası tanımlı değil.")
                continue

            all_successful = True
            event_time = event_time_from_message(message)

            try:
                for attachment in attachments:
                    for recipient in recipients:
                        if already_delivered(uid, attachment["sha256"], recipient):
                            summary["skipped_duplicate"] += 1
                            continue

                        if not send_messages:
                            continue

                        result = send_template_with_image(
                            recipient=recipient,
                            image_path=attachment["path"],
                            camera_name=CAMERA_NAME,
                            event_time=event_time,
                        )
                        logging.info(
                            "Desk360 gönderildi. UID=%s, recipient=%s, result=%s",
                            uid,
                            recipient,
                            result,
                        )
                        record_delivered(uid, attachment["sha256"], recipient)
                        summary["sent"] += 1
            except Exception as exc:
                all_successful = False
                logging.exception("UID %s gönderimi başarısız.", uid)
                summary["errors"].append(f"UID {uid}: {exc}")
            finally:
                for attachment in attachments:
                    try:
                        os.remove(attachment["path"])
                    except OSError:
                        pass

            if send_messages and all_successful:
                mailbox.uid("store", uid_bytes, "+FLAGS", r"(\Seen)")

        return summary
    finally:
        try:
            mailbox.logout()
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Background worker
# -----------------------------------------------------------------------------
def background_worker() -> None:
    logging.info("Gmail alarm worker başladı. Kontrol aralığı=%s sn", CHECK_INTERVAL_SECONDS)
    while True:
        try:
            with mail_lock:
                result = process_mailbox(send_messages=True)
            if result["matched_messages"] or result["errors"]:
                logging.info("Gmail kontrol sonucu: %s", result)
        except Exception:
            logging.exception("Arka plan Gmail kontrolünde hata oluştu.")
        time.sleep(CHECK_INTERVAL_SECONDS)


def start_worker_once() -> None:
    global worker_started
    if not ENABLE_BACKGROUND_WORKER or worker_started:
        return
    worker_started = True
    thread = threading.Thread(
        target=background_worker,
        daemon=True,
        name="gmail-camera-worker",
    )
    thread.start()


# -----------------------------------------------------------------------------
# Flask endpoints
# -----------------------------------------------------------------------------
@app.get("/")
@app.get("/health")
def health() -> Any:
    return jsonify(
        {
            "status": "ok",
            "service": "kamera-whatsapp-bot",
            "local_time": local_now().isoformat(),
            "secondary_active": secondary_is_active(),
            "background_worker": ENABLE_BACKGROUND_WORKER,
        }
    )


@app.route("/desk360-webhook", methods=["GET", "POST"])
def desk360_webhook() -> Any:
    # Bu projede gelen mesajı işlemek zorunda değiliz. Desk360 Public API kaydının
    # tamamlanabilmesi için güvenli bir HTTPS webhook endpoint'i sağlıyoruz.
    if request.method == "POST":
        payload = request.get_json(silent=True)
        logging.info(
            "Desk360 webhook alındı. JSON=%s, içerik kaydedilmedi.",
            isinstance(payload, dict),
        )
    return jsonify({"success": True, "message": "Desk360 webhook aktif."}), 200


@app.get("/recipients")
def recipients_endpoint() -> Any:
    denied = require_control_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    return jsonify(
        {
            "local_time": local_now().isoformat(),
            "secondary_active": secondary_is_active(),
            "recipients": get_recipients(),
        }
    )


@app.get("/desk360-info")
def desk360_info() -> Any:
    denied = require_control_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    try:
        integration_id = discover_integration_id(force_refresh=True)
        templates = desk360_get(
            f"/integrations/{integration_id}/conversations/templates"
        )
        selected = discover_template(force_refresh=True)
        return jsonify(
            {
                "success": True,
                "integration_id": integration_id,
                "selected_template": selected,
                "templates_response": templates,
            }
        )
    except Exception as exc:
        logging.exception("Desk360 info alınamadı.")
        return jsonify({"success": False, "error": str(exc)}), 502


@app.get("/check-mail")
def check_mail_endpoint() -> Any:
    denied = require_control_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    try:
        with mail_lock:
            result = process_mailbox(send_messages=False)
        return jsonify({"success": True, **result})
    except Exception as exc:
        logging.exception("Gmail test kontrolü başarısız.")
        return jsonify({"success": False, "error": str(exc)}), 500


@app.post("/run-now")
@app.get("/run-now")
def run_now_endpoint() -> Any:
    denied = require_control_token()
    if denied:
        return jsonify(denied[0]), denied[1]
    try:
        with mail_lock:
            result = process_mailbox(send_messages=True)
        return jsonify({"success": True, **result})
    except Exception as exc:
        logging.exception("Manuel alarm çalıştırma başarısız.")
        return jsonify({"success": False, "error": str(exc)}), 500


init_database()
start_worker_once()
