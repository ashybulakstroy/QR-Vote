"""Этап 0: минимальный стенд eGov Mobile QR (FastAPI + SIGEX).

Один файл, как в ТЗ:
- авторизация через eGov Mobile QR;
- подписание тестового голоса (CMS/PKCS#7);
- криптографическая проверка ЭЦП;
- сохранение результатов в data/vote и логов в data/logs.

HOST и PORT читаются из .env в корне проекта.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlparse

import httpx
from asn1crypto import cms, core, pem, x509
from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Настройки из .env
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise RuntimeError(f"Переменная {name} в {ENV_FILE} должна быть целым числом") from exc
    if not 1 <= value <= 65535:
        raise RuntimeError(f"Переменная {name} должна быть в диапазоне 1..65535")
    return value


HOST = os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"
PORT = _env_int("PORT", 8020)
SIGEX_BASE_URL = (os.getenv("SIGEX_BASE_URL", "https://sigex.kz").strip() or "https://sigex.kz").rstrip("/")

DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
VOTES_DIR = DATA_DIR / "vote"
STATIC_DIR = BASE_DIR / "App" / "static"

REQUEST_TIMEOUT = 30.0
LONG_POLL_TIMEOUT = 300.0
SIGEX_RETRIES = 25

POLL_NAME = "Тестовое голосование № 1"
POLL_QUESTION = "Согласны ли вы с предложенным решением?"
POLL_ANSWER = "За"

STATUS_PENDING = "pending"
STATUS_DATA_SENT = "data_sent"
STATUS_COMPLETED = "completed"
STATUS_CANCELED = "canceled"
STATUS_ERROR = "error"
STATUS_EXPIRED = "expired"
TERMINAL_STATUSES = {STATUS_COMPLETED, STATUS_CANCELED, STATUS_ERROR, STATUS_EXPIRED}


def _configure_logging() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    VOTES_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    if getattr(root, "_qr_vote_configured", False):
        return
    root.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)
    file_handler = RotatingFileHandler(
        LOGS_DIR / "app.log", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    root._qr_vote_configured = True  # type: ignore[attr-defined]


_configure_logging()
logger = logging.getLogger("App.main")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# CMS / ЭЦП
# ---------------------------------------------------------------------------

DIGEST_ALGORITHMS: dict[str, tuple[str, Any, str]] = {
    "1.3.14.3.2.26": ("sha1", SHA1, "SHA-1"),
    "2.16.840.1.101.3.4.2.4": ("sha224", SHA224, "SHA-224"),
    "2.16.840.1.101.3.4.2.1": ("sha256", SHA256, "SHA-256"),
    "2.16.840.1.101.3.4.2.2": ("sha384", SHA384, "SHA-384"),
    "2.16.840.1.101.3.4.2.3": ("sha512", SHA512, "SHA-512"),
}

RSA_PKCS1_OIDS = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
}
RSA_PSS_OID = "1.2.840.113549.1.1.10"
GOST_PREFIXES = ("1.2.643.", "1.2.398.3.10.1.1.1", "1.2.398.3.10.1.1.2")
IIN_RE = re.compile(r"(?i)\b(?:IIN|BIN)\s*[:=]?\s*(\d{12})\b")
TWELVE_DIGITS_RE = re.compile(r"\b(\d{12})\b")


class CmsError(ValueError):
    pass


def decode_signature(signature: str | bytes) -> bytes:
    raw = signature.encode("ascii") if isinstance(signature, str) else signature
    raw = raw.strip()
    if b"-----BEGIN" in raw:
        _type_name, _headers, der_bytes = pem.unarmor(raw)
        return der_bytes
    try:
        return base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise CmsError(f"Подпись не является корректным base64: {exc}") from exc


def _iter_certificates(signed_data: cms.SignedData) -> list[x509.Certificate]:
    certificates = signed_data["certificates"]
    if isinstance(certificates, core.Void):
        return []
    result: list[x509.Certificate] = []
    for choice in certificates:
        if isinstance(choice, x509.Certificate):
            result.append(choice)
        elif getattr(choice, "name", None) == "certificate":
            result.append(choice.chosen)
    return result


def _find_signer_certificate(
    signer_info: cms.SignerInfo, certificates: list[x509.Certificate]
) -> x509.Certificate | None:
    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        chosen = sid.chosen
        issuer_der = chosen["issuer"].dump()
        serial = chosen["serial_number"].native
        for certificate in certificates:
            if certificate.serial_number == serial and certificate.issuer.dump() == issuer_der:
                return certificate
    return certificates[0] if len(certificates) == 1 else None


def _subject_values(certificate: x509.Certificate) -> list[str]:
    values: list[str] = []
    try:
        for rdn in certificate.subject.chosen:
            for attribute in rdn:
                value = attribute["value"].native
                if isinstance(value, str):
                    values.append(value)
    except Exception:
        pass
    return values


def _extract_iin_bin(values: list[str]) -> tuple[str | None, str | None]:
    for value in values:
        match = IIN_RE.search(value)
        if match:
            identifier = match.group(1)
            return (None, identifier) if value.upper().startswith("BIN") else (identifier, None)
    for value in values:
        match = TWELVE_DIGITS_RE.search(value)
        if match:
            return match.group(1), None
    return None, None


def _certificate_details(certificate: x509.Certificate) -> dict[str, Any]:
    values = _subject_values(certificate)
    subject = certificate.subject.native
    serial_number_value = str(subject.get("serial_number") or "")
    iin, bin_ = _extract_iin_bin(([serial_number_value] if serial_number_value else []) + values)

    common_name = subject.get("common_name") or next(
        (value for value in values if not TWELVE_DIGITS_RE.fullmatch(value)), None
    )
    not_before = certificate["tbs_certificate"]["validity"]["not_before"].native
    not_after = certificate["tbs_certificate"]["validity"]["not_after"].native
    now = utcnow()
    valid_now = bool(not_before <= now <= not_after) if not_before and not_after else False

    return {
        "common_name": common_name,
        "iin": iin,
        "bin": bin_,
        "organization": subject.get("organization_name"),
        "organizational_unit": subject.get("organizational_unit_name"),
        "issuer": certificate.issuer.human_friendly,
        "serial_number": format(certificate.serial_number, "x"),
        "not_before": isoformat(not_before) if not_before else None,
        "not_after": isoformat(not_after) if not_after else None,
        "valid_now": valid_now,
        "subject": certificate.subject.human_friendly,
    }


def _get_signed_attrs_der(signed_attrs: cms.CMSAttributes) -> bytes:
    try:
        return signed_attrs.untag().dump()
    except Exception:
        der = signed_attrs.dump()
        if der and der[0] == 0xA0:
            return b"\x31" + der[1:]
        return der


def _message_digest(signed_attrs: cms.CMSAttributes) -> bytes | None:
    for attribute in signed_attrs:
        if attribute["type"].native == "message_digest":
            return attribute["values"][0].native
    return None


def verify_cms(content: bytes, signature: str | bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "checked": False,
        "supported": False,
        "valid": None,
        "signature_algorithm": None,
        "signature_algorithm_name": None,
        "digest_algorithm": None,
        "checks": {
            "digest_matches": None,
            "signature_valid": None,
            "certificate_valid_now": None,
            "certificate_matches_signer": None,
        },
        "signer": None,
        "certificate": None,
        "details": "",
        "error": None,
    }

    try:
        der = decode_signature(signature)
        content_info = cms.ContentInfo.load(der, strict=False)
        if content_info["content_type"].native != "signed_data":
            raise CmsError(f"Ожидался CMS SignedData, получено: {content_info['content_type'].native}")

        signed_data = content_info["content"]
        signer_infos = signed_data["signer_infos"]
        if len(signer_infos) != 1:
            raise CmsError(f"Ожидалась одна подпись, найдено: {len(signer_infos)}")

        signer_info = signer_infos[0]
        certificates = _iter_certificates(signed_data)
        certificate = _find_signer_certificate(signer_info, certificates)

        result["checked"] = True
        if certificate is not None:
            result["certificate"] = _certificate_details(certificate)
            result["signer"] = {
                "common_name": result["certificate"]["common_name"],
                "iin": result["certificate"]["iin"],
                "bin": result["certificate"]["bin"],
                "organization": result["certificate"]["organization"],
            }
            result["checks"]["certificate_valid_now"] = result["certificate"]["valid_now"]
            result["checks"]["certificate_matches_signer"] = True

        signature_oid = signer_info["signature_algorithm"]["algorithm"].dotted
        digest_oid = signer_info["digest_algorithm"]["algorithm"].dotted
        digest_entry = DIGEST_ALGORITHMS.get(digest_oid)
        digest_label = digest_entry[2] if digest_entry else digest_oid
        hash_name = digest_entry[0] if digest_entry else None

        result["signature_algorithm"] = signature_oid
        result["signature_algorithm_name"] = (
            RSA_PKCS1_OIDS.get(signature_oid)
            or ("RSA-PSS" if signature_oid == RSA_PSS_OID else None)
            or f"OID {signature_oid}"
        )
        result["digest_algorithm"] = digest_label

        if certificate is None:
            raise CmsError("Не удалось найти сертификат подписанта в CMS.")

        signed_attrs = signer_info["signed_attrs"]
        if isinstance(signed_attrs, core.Void):
            signed_bytes = content
            result["checks"]["digest_matches"] = True
        else:
            embedded_digest = _message_digest(signed_attrs)
            if embedded_digest is None:
                raise CmsError("В signedAttrs отсутствует messageDigest.")
            if hash_name is None:
                raise CmsError(f"Неподдерживаемый алгоритм хеширования: {digest_oid}")
            if hashlib.new(hash_name, content).digest() != embedded_digest:
                result["supported"] = True
                result["valid"] = False
                result["details"] = (
                    "ЭЦП не соответствует документу: хеш подписанных данных не совпадает "
                    "с переданным документом."
                )
                return result
            result["checks"]["digest_matches"] = True
            signed_bytes = _get_signed_attrs_der(signed_attrs)

        signature_bytes = signer_info["signature"].native

        if signature_oid in RSA_PKCS1_OIDS or signature_oid == RSA_PSS_OID:
            if signature_oid not in ("1.2.840.113549.1.1.1", RSA_PSS_OID):
                expected_digest = {
                    "1.2.840.113549.1.1.5": "1.3.14.3.2.26",
                    "1.2.840.113549.1.1.14": "2.16.840.1.101.3.4.2.4",
                    "1.2.840.113549.1.1.11": "2.16.840.1.101.3.4.2.1",
                    "1.2.840.113549.1.1.12": "2.16.840.1.101.3.4.2.2",
                    "1.2.840.113549.1.1.13": "2.16.840.1.101.3.4.2.3",
                }.get(signature_oid)
                if expected_digest and expected_digest != digest_oid:
                    raise CmsError("Алгоритм подписи не соответствует алгоритму хеширования.")

            if digest_entry is None:
                raise CmsError(f"Неподдерживаемый алгоритм хеширования: {digest_oid}")
            public_key = RSA.import_key(certificate.public_key.dump())
            digest = digest_entry[1].new(signed_bytes)
            if signature_oid == RSA_PSS_OID:
                pss.new(public_key).verify(digest, signature_bytes)
            else:
                pkcs1_15.new(public_key).verify(digest, signature_bytes)

            result["supported"] = True
            result["valid"] = True
            result["checks"]["signature_valid"] = True

        elif signature_oid.startswith(GOST_PREFIXES):
            result["supported"] = False
            result["valid"] = None
            result["details"] = (
                "Подпись сформирована по алгоритму ГОСТ (НУЦ РК). Сертификат и подписант "
                "разобраны, однако локальная проверка ГОСТ в Этапе 0 не поддерживается — "
                "требуется проверка через SIGEX/НУЦ РК."
            )
            return result
        else:
            result["supported"] = False
            result["valid"] = None
            result["details"] = (
                f"Алгоритм подписи {signature_oid} не поддерживается локальной проверкой Этапа 0."
            )
            return result

        if result["checks"]["certificate_valid_now"] is False:
            result["valid"] = False
            result["details"] = (
                "Подпись математически верна, но срок действия сертификата подписанта истёк "
                "или ещё не наступил."
            )
        else:
            signer_name = (result["signer"] or {}).get("common_name") or "подписант"
            result["details"] = (
                "ЭЦП действительна: подпись соответствует документу, сертификат подписанта "
                f"действует ({signer_name})."
            )
        return result

    except CmsError as exc:
        result["supported"] = True
        result["valid"] = False
        result["details"] = f"Ошибка разбора CMS: {exc}"
        result["error"] = str(exc)
        return result
    except Exception as exc:  # noqa: BLE001
        result["supported"] = True
        result["valid"] = False
        result["details"] = f"Криптографическая проверка не пройдена: {exc}"
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result


# ---------------------------------------------------------------------------
# SIGEX API
# ---------------------------------------------------------------------------

class SigexError(RuntimeError):
    pass


def _ensure_trusted_url(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    base_host = (urlparse(SIGEX_BASE_URL).hostname or "").lower()
    if parsed.scheme != "https" or not host:
        raise SigexError(f"SIGEX вернул некорректный URL: {url!r}")
    if base_host and not (host == base_host or host.endswith("." + base_host)):
        raise SigexError(f"SIGEX вернул URL чужого домена: {host!r}")
    return url


def _json_or_error(response: httpx.Response) -> dict[str, Any]:
    if response.status_code != 200:
        message = response.text
        try:
            payload = response.json()
            message = payload.get("message") or payload.get("error") or message
        except ValueError:
            pass
        raise SigexError(f"SIGEX вернул HTTP {response.status_code}: {message}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise SigexError(f"SIGEX вернул не-JSON ответ: {response.text[:300]!r}") from exc

    if isinstance(payload, dict) and payload.get("message"):
        raise SigexError(f"Ошибка SIGEX: {payload['message']}")
    if not isinstance(payload, dict):
        raise SigexError(f"Неожиданный ответ SIGEX: {payload!r}")
    return payload


async def sigex_register_qr(description: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=15.0)) as client:
            response = await client.post(f"{SIGEX_BASE_URL}/api/egovQr", json={"description": description})
    except httpx.HTTPError as exc:
        raise SigexError(f"Не удалось зарегистрировать QR в SIGEX: {exc}") from exc

    payload = _json_or_error(response)
    for field in ("qrCode", "dataURL", "signURL"):
        if not payload.get(field):
            raise SigexError(f"SIGEX не вернул обязательное поле {field!r}.")
    payload["dataURL"] = _ensure_trusted_url(str(payload["dataURL"]))
    payload["signURL"] = _ensure_trusted_url(str(payload["signURL"]))
    return payload


async def sigex_send_documents(data_url: str, documents: list[dict[str, Any]]) -> None:
    data_url = _ensure_trusted_url(data_url)
    payload = {"signMethod": "CMS_SIGN_ONLY", "version": 1, "documentsToSign": documents}
    timeout = httpx.Timeout(connect=15.0, read=LONG_POLL_TIMEOUT, write=REQUEST_TIMEOUT, pool=15.0)

    last_error: Exception | None = None
    for attempt in range(1, SIGEX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(data_url, json=payload)
            _json_or_error(response)
            logger.info("SIGEX: данные переданы в eGov Mobile (попытка %s)", attempt)
            return
        except httpx.TransportError as exc:
            last_error = exc
            logger.warning("SIGEX: обрыв при передаче данных (%s/%s): %s", attempt, SIGEX_RETRIES, exc)
            await asyncio.sleep(min(attempt, 5))
    raise SigexError(f"Не удалось передать данные в SIGEX: {last_error}")


async def sigex_get_signatures(sign_url: str) -> dict[str, Any]:
    sign_url = _ensure_trusted_url(sign_url)
    timeout = httpx.Timeout(connect=15.0, read=LONG_POLL_TIMEOUT, write=REQUEST_TIMEOUT, pool=15.0)

    last_error: Exception | None = None
    for attempt in range(1, SIGEX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(sign_url)
            payload = _json_or_error(response)
            logger.info("SIGEX: получен ответ с подписями (попытка %s)", attempt)
            return payload
        except httpx.TransportError as exc:
            last_error = exc
            logger.warning("SIGEX: обрыв при ожидании подписи (%s/%s): %s", attempt, SIGEX_RETRIES, exc)
            await asyncio.sleep(min(attempt, 5))
    raise SigexError(f"Не удалось получить подписи из SIGEX: {last_error}")


def extract_signature(response: dict[str, Any]) -> str:
    documents = response.get("documentsToSign")
    if not isinstance(documents, list) or not documents:
        raise SigexError("В ответе SIGEX отсутствует documentsToSign.")
    try:
        signature = documents[0]["document"]["file"]["data"]
    except (KeyError, TypeError) as exc:
        raise SigexError("В ответе SIGEX отсутствует подпись документа.") from exc
    if not isinstance(signature, str) or not signature:
        raise SigexError("SIGEX вернул пустую подпись.")
    return signature


# ---------------------------------------------------------------------------
# Сессии
# ---------------------------------------------------------------------------

@dataclass
class Session:
    session_id: str
    kind: str
    status: str
    created_at: datetime
    updated_at: datetime
    expire_at: datetime
    qr_code: str
    launch_link: str | None
    business_link: str | None
    data_url: str
    sign_url: str
    document: dict[str, Any] | None = None
    raw_document_b64: str | None = None
    signature: str | None = None
    verification: dict[str, Any] | None = None
    user: dict[str, Any] | None = None
    saved_file: str | None = None
    error: str | None = None
    _raw_content: bytes | None = field(default=None, repr=False)

    def public(self) -> dict[str, Any]:
        saved_file = None
        if self.saved_file:
            try:
                saved_file = str(Path(self.saved_file).relative_to(BASE_DIR))
            except ValueError:
                saved_file = self.saved_file
        return {
            "session_id": self.session_id,
            "type": self.kind,
            "status": self.status,
            "created_at": isoformat(self.created_at),
            "updated_at": isoformat(self.updated_at),
            "expire_at": isoformat(self.expire_at),
            "qr_code": self.qr_code,
            "launch_link": self.launch_link,
            "business_link": self.business_link,
            "document": self.document,
            "signature": self.signature,
            "verification": self.verification,
            "user": self.user,
            "saved_file": saved_file,
            "error": self.error,
        }


sessions: dict[str, Session] = {}
_tasks: set[asyncio.Task[None]] = set()


def _expire_at(sigex_data: dict[str, Any], now: datetime) -> datetime:
    raw_expire = sigex_data.get("expireAt")
    if isinstance(raw_expire, (int, float)) and raw_expire > 0:
        try:
            return datetime.fromtimestamp(raw_expire / 1000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            pass
    return now + timedelta(minutes=15)


def _document_to_sign(name: str, meta: list[dict[str, str]], raw: bytes) -> dict[str, Any]:
    return {
        "id": 1,
        "nameRu": name,
        "nameKz": name,
        "nameEn": name,
        "meta": meta,
        "document": {"file": {"mime": "application/json", "data": base64.b64encode(raw).decode("ascii")}},
    }


def _build_session(session_id: str, kind: str, sigex_data: dict[str, Any], document: dict, raw: bytes) -> Session:
    now = utcnow()
    session = Session(
        session_id=session_id,
        kind=kind,
        status=STATUS_PENDING,
        created_at=now,
        updated_at=now,
        expire_at=_expire_at(sigex_data, now),
        qr_code=str(sigex_data["qrCode"]),
        launch_link=sigex_data.get("eGovMobileLaunchLink"),
        business_link=sigex_data.get("eGovBusinessLaunchLink"),
        data_url=str(sigex_data["dataURL"]),
        sign_url=str(sigex_data["signURL"]),
        document=document,
        raw_document_b64=base64.b64encode(raw).decode("ascii"),
        _raw_content=raw,
    )
    sessions[session_id] = session
    _prune_sessions()
    logger.info("Создана сессия %s (%s)", session_id, kind)
    return session


async def start_auth() -> Session:
    session_id = str(uuid.uuid4())
    document = {
        "action": "auth",
        "session_id": session_id,
        "nonce": base64.b64encode(os.urandom(32)).decode("ascii"),
        "created_at": isoformat(utcnow()),
    }
    raw = json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
    sigex_data = await sigex_register_qr("Авторизация через eGov Mobile (Этап 0)")
    session = _build_session(session_id, "auth", sigex_data, document, raw)
    documents = [
        _document_to_sign(
            "Подтверждение входа",
            [
                {"name": "Действие", "value": "Авторизация в системе голосования"},
                {"name": "Сессия", "value": session_id},
            ],
            raw,
        )
    ]
    _schedule(session, documents)
    return session


async def start_sign(user_fullname: str, iin: str | None = None) -> Session:
    session_id = str(uuid.uuid4())
    document = {
        "poll_name": POLL_NAME,
        "question": POLL_QUESTION,
        "answer": POLL_ANSWER,
        "user_fullname": user_fullname,
        "doc_id": str(uuid.uuid4()),
        "created_at": isoformat(utcnow()),
    }
    raw = json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
    sigex_data = await sigex_register_qr("Подписание тестового голоса № 1")
    session = _build_session(session_id, "sign", sigex_data, document, raw)
    session.user = {"common_name": user_fullname, "iin": iin, "bin": None}
    documents = [
        _document_to_sign(
            "Тестовый бюллетень № 1",
            [
                {"name": "Вопрос", "value": POLL_QUESTION},
                {"name": "Выбор", "value": POLL_ANSWER},
                {"name": "ФИО", "value": user_fullname},
            ],
            raw,
        )
    ]
    _schedule(session, documents)
    return session


def _schedule(session: Session, documents: list[dict[str, Any]]) -> None:
    task = asyncio.create_task(_drive(session, documents))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def _drive(session: Session, documents: list[dict[str, Any]]) -> None:
    try:
        timeout_seconds = max(30.0, (session.expire_at - utcnow()).total_seconds() + 120.0)
        async with asyncio.timeout(timeout_seconds):
            await sigex_send_documents(session.data_url, documents)
            _touch(session, STATUS_DATA_SENT)
            logger.info("Сессия %s: данные переданы, ждём подпись", session.session_id)

            response = await sigex_get_signatures(session.sign_url)
            if response.get("status") == "CANCELED":
                _touch(session, STATUS_CANCELED, error="Пользователь отменил подписание.")
                return

            signature = extract_signature(response)
            session.signature = signature
            if session._raw_content is None:
                raise SigexError("Отсутствует исходный документ сессии.")
            verification = verify_cms(session._raw_content, signature)
            session.verification = verification

            if session.kind == "auth":
                _complete_auth(session, verification)
            else:
                _complete_sign(session, verification)

            session.status = STATUS_COMPLETED
            session.updated_at = utcnow()
            logger.info("Сессия %s завершена, ЭЦП valid=%s", session.session_id, verification.get("valid"))

    except TimeoutError:
        _touch(session, STATUS_EXPIRED, error="Срок действия QR-кода истёк. Создайте новый QR-код.")
    except asyncio.CancelledError:
        _touch(session, STATUS_ERROR, error="Обработка прервана.")
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("Сессия %s завершилась ошибкой", session.session_id)
        _touch(session, STATUS_ERROR, error=str(exc))


def _complete_auth(session: Session, verification: dict[str, Any]) -> None:
    if verification.get("valid") is False:
        raise SigexError("Подпись не подтверждена: " + (verification.get("details") or "ошибка"))
    signer = verification.get("signer") or {}
    session.user = {
        "common_name": signer.get("common_name") or "Подтверждённый гражданин РК",
        "iin": signer.get("iin"),
        "bin": signer.get("bin"),
        "organization": signer.get("organization"),
        "verified": verification.get("valid") is True,
    }


def _complete_sign(session: Session, _verification: dict[str, Any]) -> None:
    session.saved_file = str(_save_vote(session))


def _save_vote(session: Session) -> Path:
    if session.document is None or session.signature is None:
        raise SigexError("Нечего сохранять: отсутствует документ или подпись.")
    created_at = utcnow()
    doc_id = str(session.document.get("doc_id") or session.session_id)
    stem = f"{created_at.strftime('%Y%m%dT%H%M%S')}_{doc_id}"
    payload = {
        "session_id": session.session_id,
        "saved_at": isoformat(created_at),
        "document": session.document,
        "document_b64": session.raw_document_b64,
        "signature_b64": session.signature,
        "verification": session.verification,
        "user": session.user,
    }
    json_path = VOTES_DIR / f"{stem}.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (VOTES_DIR / f"{stem}.cms").write_bytes(decode_signature(session.signature))
    logger.info("Бюллетень сохранён: %s", json_path)
    return json_path


def _touch(session: Session, status: str, *, error: str | None = None) -> None:
    session.status = status
    session.updated_at = utcnow()
    if error is not None:
        session.error = error


def _mark_expired(session: Session) -> None:
    if session.status in TERMINAL_STATUSES:
        return
    if utcnow() > session.expire_at + timedelta(seconds=60):
        _touch(session, STATUS_EXPIRED, error="Срок действия QR-кода истёк.")


def _prune_sessions() -> None:
    if len(sessions) < 200:
        return
    cutoff = utcnow() - timedelta(hours=2)
    stale = [
        session_id
        for session_id, session in sessions.items()
        if session.updated_at < cutoff and session.status in TERMINAL_STATUSES
    ]
    for session_id in stale:
        sessions.pop(session_id, None)
    logger.info("Очистка сессий: удалено %s", len(stale))


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    logger.info("Запуск стенда Этапа 0: http://%s:%s (SIGEX: %s)", HOST, PORT, SIGEX_BASE_URL)
    yield
    logger.info("Остановка стенда Этапа 0")


app = FastAPI(
    title="Этап 0 — eGov Mobile QR Vote",
    description="Авторизация и подписание голоса через eGov Mobile QR (SIGEX).",
    version="0.1.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class SignInitRequest(BaseModel):
    user_fullname: str = Field(min_length=1, max_length=200)
    iin: str | None = Field(default=None, pattern=r"^\d{12}$")

    @field_validator("user_fullname")
    @classmethod
    def validate_fullname(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value:
            raise ValueError("ФИО не может быть пустым")
        return value


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "egov-qr-vote-stage0",
        "host": HOST,
        "port": PORT,
        "sigex": SIGEX_BASE_URL,
    }


@app.post("/api/auth/init")
async def auth_init() -> JSONResponse:
    try:
        return JSONResponse((await start_auth()).public())
    except SigexError as exc:
        logger.warning("Ошибка авторизации: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/sign/init")
async def sign_init(payload: SignInitRequest) -> JSONResponse:
    try:
        return JSONResponse((await start_sign(payload.user_fullname, payload.iin)).public())
    except SigexError as exc:
        logger.warning("Ошибка инициализации подписи: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/sessions/{session_id}")
async def session_status(session_id: str) -> JSONResponse:
    session = sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Сессия не найдена")
    _mark_expired(session)
    return JSONResponse(session.public())


@app.exception_handler(SigexError)
async def sigex_error_handler(_: Request, exc: SigexError) -> JSONResponse:
    logger.warning("Необработанная ошибка SIGEX: %s", exc)
    return JSONResponse(status_code=502, content={"detail": str(exc)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
