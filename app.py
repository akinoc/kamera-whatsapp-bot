import email
import imaplib
import logging
import os
import tempfile
import threading
import time
from datetime import datetime
from email.header import decode_header
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import Flask, jsonify

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
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

DESK360_API_KEY = os.getenv("DESK360_API_KEY", "").strip()

ADMIN_PHONE = os.getenv("ADMIN_PHONE", "").strip()
SECONDARY_PHONE = os.getenv("SECONDARY_PHONE", "").strip()

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

CHECK_INTERVAL_SECONDS = int(
    os.getenv("CHECK_INTERVAL_SECONDS", "60")
)

# Aynı anda iki Gmail kontrolü yapılmasını engeller.
check_lock = threading.Lock()


# ============================================================
# YARDIMCI FONKSİYONLAR
# ============================================================

def decode_text(value: str | None) -> str:
    """
    E-posta başlıklarındaki Türkçe karakterleri ve farklı
    kodlamaları okunabilir metne dönüştürür.
    """
    if not value:
        return ""

    decoded_parts = decode_header(value)
    result: list[str] = []

    for part, encoding in decoded_parts:
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


def get_local_time() -> datetime:
    """
    Ayarlanan zaman dilimine göre güncel zamanı verir.
    Varsayılan: Europe/Istanbul
    """
    return datetime.now(
        ZoneInfo(TIMEZONE_NAME)
    )


def secondary_is_active(
    current_time: datetime | None = None,
) -> bool:
    """
    Secondary numaranın mesaj alıp alamayacağını belirler.

    Kurallar:
    - Pazartesi–Cuma
    - 09:00 dahil
    - 18:00 hariç
    """
    now = current_time or get_local_time()

    is_weekday = now.weekday() < 5

    is_working_hours = (
        SECONDARY_START_HOUR
        <= now.hour
        < SECONDARY_END_HOUR
    )

    return is_weekday and is_working_hours


def get_alarm_recipients(
    current_time: datetime | None = None,
) -> list[str]:
    """
    Alarm fotoğrafının gönderileceği telefon numaralarını döndürür.

    Admin:
    - Her gün
    - Her saat

    Secondary:
    - Sadece hafta içi
    - 09:00–18:00
    """
    recipients: list[str] = []

    if ADMIN_PHONE:
        recipients.append(ADMIN_PHONE)

    if (
        SECONDARY_PHONE
        and secondary_is_active(current_time)
    ):
        recipients.append(SECONDARY_PHONE)

    # Aynı telefon iki alana da yazıldıysa
    # yalnızca bir kez gönderilmesini sağlar.
    return list(dict.fromkeys(recipients))


# ============================================================
# GMAIL / IMAP
# ============================================================

def find_jpg_attachments(
    mark_as_read: bool = False,
) -> list[dict]:
    """
    Gmail gelen kutusundaki okunmamış e-postaları kontrol eder.

    JPG veya JPEG eki bulunan e-postaları ve dosya bilgilerini
    döndürür.
    """
    if not GMAIL_USER:
        raise RuntimeError(
            "GMAIL_USER Render Environment bölümünde eksik."
        )

    if not GMAIL_APP_PASSWORD:
        raise RuntimeError(
            "GMAIL_APP_PASSWORD Render Environment bölümünde eksik."
        )

    results: list[dict] = []

    mail = imaplib.IMAP4_SSL(
        "imap.gmail.com",
        993,
    )

    try:
        mail.login(
            GMAIL_USER,
            GMAIL_APP_PASSWORD,
        )

        status, _ = mail.select(
            "INBOX"
        )

        if status != "OK":
            raise RuntimeError(
                "Gmail gelen kutusu açılamadı."
            )

        status, data = mail.uid(
            "search",
            None,
            "UNSEEN",
        )

        if status != "OK":
            raise RuntimeError(
                "Gmail okunmamış e-posta araması başarısız."
            )

        message_uids = data[0].split()

        logging.info(
            "Okunmamış e-posta sayısı: %s",
            len(message_uids),
        )

        # En yeni 20 okunmamış e-posta kontrol edilir.
        for uid in reversed(
            message_uids[-20:]
        ):
            status, message_data = mail.uid(
                "fetch",
                uid,
                "(RFC822)",
            )

            if status != "OK":
                continue

            if not message_data:
                continue

            if not isinstance(
                message_data[0],
                tuple,
            ):
                continue

            raw_email = message_data[0][1]

            message = email.message_from_bytes(
                raw_email
            )

            subject = decode_text(
                message.get("Subject")
            )

            sender = decode_text(
                message.get("From")
            )

            date_value = decode_text(
                message.get("Date")
            )

            attachments: list[dict] = []

            for part in message.walk():
                filename = decode_text(
                    part.get_filename()
                )

                if not filename:
                    continue

                extension = (
                    Path(filename)
                    .suffix
                    .lower()
                )

                if extension not in {
                    ".jpg",
                    ".jpeg",
                }:
                    continue

                payload = part.get_payload(
                    decode=True
                )

                if not payload:
                    continue

                with tempfile.NamedTemporaryFile(
                    prefix="besta_",
                    suffix=extension,
                    delete=False,
                ) as temporary_file:
                    temporary_file.write(payload)
                    saved_path = temporary_file.name

                attachment = {
                    "filename": filename,
                    "path": saved_path,
                    "size_bytes": len(payload),
                }

                attachments.append(
                    attachment
                )

                logging.info(
                    "JPG bulundu: %s — %s byte",
                    filename,
                    len(payload),
                )

            if not attachments:
                continue

            result = {
                "uid": uid.decode(),
                "subject": subject,
                "sender": sender,
                "date": date_value,
                "attachments": attachments,
            }

            results.append(result)

            if mark_as_read:
                mail.uid(
                    "store",
                    uid,
                    "+FLAGS",
                    r"(\Seen)",
                )

        return results

    finally:
        try:
            mail.logout()
        except Exception:
            pass


# ============================================================
# DESK360 GÖNDERİMİ
# ============================================================

def send_alarm_to_recipients(
    message: dict,
) -> None:
    """
    Bu fonksiyona sonraki aşamada Desk360 fotoğraf gönderme
    API çağrısını ekleyeceğiz.

    Şu anda yalnızca hangi numaralara gönderileceğini loglar.
    """
    recipients = get_alarm_recipients()

    if not recipients:
        logging.warning(
            "Alarm bulundu ancak gönderilecek numara tanımlı değil."
        )
        return

    attachments = message.get(
        "attachments",
        [],
    )

    for attachment in attachments:
        image_path = attachment.get(
            "path",
            "",
        )

        filename = attachment.get(
            "filename",
            "",
        )

        for recipient in recipients:
            logging.info(
                "Hazır gönderim: Telefon=%s, Dosya=%s, Yol=%s",
                recipient,
                filename,
                image_path,
            )

            # Desk360 API hazır olduğunda burası şöyle olacak:
            #
            # send_desk360_image(
            #     recipient_phone=recipient,
            #     image_path=image_path,
            #     caption="Kapıda hareket algılandı.",
            # )


# ============================================================
# ARKA PLAN GMAIL KONTROLÜ
# ============================================================

def background_mail_checker() -> None:
    """
    Belirlenen aralıklarla Gmail'i kontrol eder.
    """
    while True:
        try:
            with check_lock:
                messages = find_jpg_attachments(
                    mark_as_read=False
                )

            if messages:
                total_images = sum(
                    len(
                        message.get(
                            "attachments",
                            [],
                        )
                    )
                    for message in messages
                )

                logging.info(
                    "%s alarm e-postasında toplam %s JPG bulundu.",
                    len(messages),
                    total_images,
                )

                for message in messages:
                    send_alarm_to_recipients(
                        message
                    )

        except Exception:
            logging.exception(
                "Gmail kontrolü sırasında hata oluştu."
            )

        time.sleep(
            CHECK_INTERVAL_SECONDS
        )


# ============================================================
# WEB ENDPOINTLERİ
# ============================================================

@app.route("/")
def home():
    now = get_local_time()

    return jsonify(
        {
            "status": "ok",
            "service": "Kamera WhatsApp Bot",
            "local_time": now.isoformat(),
            "timezone": TIMEZONE_NAME,
            "secondary_active": secondary_is_active(
                now
            ),
        }
    )


@app.route("/recipients")
def recipients():
    """
    Şu anda alarmın hangi numaralara gönderileceğini gösterir.
    """
    now = get_local_time()

    return jsonify(
        {
            "success": True,
            "local_time": now.isoformat(),
            "weekday_number": now.weekday(),
            "secondary_start_hour": (
                SECONDARY_START_HOUR
            ),
            "secondary_end_hour": (
                SECONDARY_END_HOUR
            ),
            "secondary_active": secondary_is_active(
                now
            ),
            "recipients": get_alarm_recipients(
                now
            ),
        }
    )


@app.route("/check-mail")
def check_mail():
    """
    Gmail'i manuel kontrol eder.

    E-postaları okundu olarak işaretlemez.
    """
    try:
        with check_lock:
            messages = find_jpg_attachments(
                mark_as_read=False
            )

        safe_results: list[dict] = []

        for message in messages:
            safe_results.append(
                {
                    "uid": message["uid"],
                    "subject": message["subject"],
                    "sender": message["sender"],
                    "date": message["date"],
                    "attachments": [
                        {
                            "filename": item[
                                "filename"
                            ],
                            "size_bytes": item[
                                "size_bytes"
                            ],
                        }
                        for item in message[
                            "attachments"
                        ]
                    ],
                }
            )

        now = get_local_time()

        return jsonify(
            {
                "success": True,
                "local_time": now.isoformat(),
                "secondary_active": (
                    secondary_is_active(now)
                ),
                "recipients": (
                    get_alarm_recipients(now)
                ),
                "email_count": len(
                    safe_results
                ),
                "messages": safe_results,
            }
        )

    except Exception as exc:
        logging.exception(
            "Manuel Gmail kontrolü başarısız."
        )

        return jsonify(
            {
                "success": False,
                "error": str(exc),
            }
        ), 500


# ============================================================
# THREAD BAŞLATMA
# ============================================================

def start_background_thread() -> None:
    thread = threading.Thread(
        target=background_mail_checker,
        daemon=True,
        name="gmail-alarm-checker",
    )

    thread.start()

    logging.info(
        "Gmail alarm kontrol thread'i başlatıldı."
    )


start_background_thread()
