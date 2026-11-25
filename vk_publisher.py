# -*- coding: utf-8 -*-
"""
Модуль формирования раздельных .docx документов (1 — БС, 2 — ЧС)
и отправки их в личные сообщения ВКонтакте от имени сообщества.
"""

import json
import logging
import os
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

import docx
import requests

logger = logging.getLogger("harvester.vk")
BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "vk_config.json"

VK_API_BASE = "https://api.vk.com/method"
VK_API_VERSION = "5.199"
_NON_RETRYABLE_VK_ERRORS = {5, 7, 15, 27, 100, 113, 900, 901, 902, 917}


def _now_msk() -> datetime:
    try:
        return datetime.now(ZoneInfo("Europe/Moscow"))
    except Exception:
        return datetime.now(timezone(timedelta(hours=3)))


def _parse_peer_ids(raw) -> List[int]:
    if raw is None or raw == "":
        return []
    items = raw if isinstance(raw, list) else str(raw).split(",")
    result: List[int] = []
    for item in items:
        s = str(item).strip()
        if not s:
            continue
        if s.lower().startswith("id") and s[2:].lstrip("-").isdigit():
            s = s[2:]
        try:
            pid = int(s)
            if pid not in result:
                result.append(pid)
        except ValueError:
            logger.warning(f"Пропущен некорректный peer_id: {item!r}")
    return result


def load_vk_config() -> Optional[dict]:
    env_token = os.environ.get("VK_ACCESS_TOKEN", "").strip()
    env_group = os.environ.get("VK_GROUP_ID", "").strip()
    env_suffix = os.environ.get("VK_SUFFIX", "").strip()
    env_peer = os.environ.get("VK_PEER_ID", "").strip()
    if env_token and env_group:
        cfg = {
            "enabled": True,
            "access_token": env_token,
            "group_id": env_group,
            "suffix": env_suffix,
        }
        if env_peer:
            cfg["peer_id"] = env_peer
        return cfg

    if not CONFIG_PATH.exists():
        return None
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            if env_suffix and not cfg.get("suffix"):
                cfg["suffix"] = env_suffix
            if env_peer and not cfg.get("peer_id") and not cfg.get("peer_ids"):
                cfg["peer_id"] = env_peer
            return cfg
    except Exception as e:
        logger.warning(f"Не удалось прочитать vk_config.json: {e}")
        return None


def _strip_uri_fragment(uri: str) -> str:
    """Убирает текстовую метку и тайминги после '#', оставляя только чистую ссылку."""
    return uri.strip().partition("#")[0]


def _read_links_from_file(path: Path) -> List[str]:
    if not path.exists():
        return []
    lines = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "://" in line:
            lines.append(line)
    return lines


def _build_single_docx(doc_path: Path, links: List[str]) -> Optional[Path]:
    """Создаёт .docx файл, содержащий только чистые ссылки без заголовков, слов и таймингов."""
    if not links:
        return None

    doc_path.parent.mkdir(parents=True, exist_ok=True)
    doc = docx.Document()
    doc.core_properties.title = ""
    doc.core_properties.subject = ""
    doc.core_properties.comments = ""
    doc.core_properties.author = ""

    for uri in links:
        doc.add_paragraph(_strip_uri_fragment(uri))

    doc.save(str(doc_path))
    return doc_path


def _format_vk_error(err: dict) -> str:
    code = err.get("error_code")
    msg = err.get("error_msg", "")
    if code in (5, 7, 15, 27):
        return (
            f"VK error {code} ({msg}). Проверьте права ключа группы («Сообщения сообщества» и «Документы») "
            "и включите сообщения в настройках группы ВК."
        )
    if code in (901, 902):
        return (
            f"VK error {code} ({msg}). Отправьте любое первое сообщение (например «привет») "
            "в ЛС вашей группы ВК, чтобы она могла присылать файлы."
        )
    return f"VK error {code}: {msg}"


def _vk_api_call(
    method: str,
    params: Dict[str, object],
    token: str,
    http_method: str = "POST",
    timeout: Tuple[int, int] = (10, 15),
    attempts: int = 3,
) -> dict:
    """Выполняет запрос к VK API с автоповтором только при временных сбоях."""
    url = f"{VK_API_BASE}/{method}"
    payload = {**params, "access_token": token, "v": VK_API_VERSION}
    last_resp: dict = {}

    for attempt in range(attempts):
        if attempt > 0:
            time.sleep(1.5)
        try:
            if http_method.upper() == "GET":
                resp = requests.get(url, params=payload, timeout=timeout)
            else:
                resp = requests.post(url, data=payload, timeout=timeout)
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning(f"Попытка {attempt + 1}/{attempts} {method}: сетевой/JSON сбой: {exc}")
            last_resp = {}
            continue

        if "response" in data:
            return data

        last_resp = data
        err = data.get("error", {})
        if err.get("error_code") in _NON_RETRYABLE_VK_ERRORS:
            return data
        logger.warning(f"Попытка {attempt + 1}/{attempts} {method}: {data}")

    return last_resp


def _upload_bytes_to_server(upload_url: str, upload_filename: str, doc_bytes: bytes) -> Optional[str]:
    """Загружает байты .docx на upload_url VK с автоповтором."""
    mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    for attempt in range(3):
        if attempt > 0:
            time.sleep(1.5)
        try:
            up_resp = requests.post(
                upload_url,
                files={"file": (upload_filename, doc_bytes, mime)},
                timeout=(10, 20),
            )
            if not up_resp.text or not up_resp.text.strip():
                logger.warning(f"Попытка {attempt + 1}/3 пустой ответ upload ({upload_filename})")
                continue
            up = up_resp.json()
            if "file" in up:
                return up["file"]
            logger.warning(f"Попытка {attempt + 1}/3 ошибка upload ({upload_filename}): {up}")
        except (requests.RequestException, ValueError) as exc:
            logger.warning(f"Попытка {attempt + 1}/3 сбой upload ({upload_filename}): {exc}")
    return None


def _upload_message_docx(doc_path: Path, upload_filename: str, peer_id: int, token: str) -> Optional[str]:
    """Загружает .docx на сервер документов для личных сообщений VK и возвращает doc{owner_id}_{id}."""
    srv = _vk_api_call(
        "docs.getMessagesUploadServer",
        {"peer_id": peer_id, "type": "doc"},
        token=token,
        http_method="GET",
    )
    if "response" not in srv or "upload_url" not in srv["response"]:
        err = srv.get("error")
        detail = _format_vk_error(err) if err else str(srv)
        logger.error(f"getMessagesUploadServer ({upload_filename}): {detail}")
        return None

    uploaded_file = _upload_bytes_to_server(srv["response"]["upload_url"], upload_filename, doc_path.read_bytes())
    if not uploaded_file:
        logger.error(f"Не удалось загрузить файл {upload_filename} на сервер VK.")
        return None

    save = _vk_api_call(
        "docs.save",
        {"file": uploaded_file, "title": upload_filename},
        token=token,
        http_method="POST",
    )
    resp_data = save.get("response")
    doc_info = resp_data.get("doc") if isinstance(resp_data, dict) else (resp_data[0] if isinstance(resp_data, list) and resp_data else None)
    if not doc_info or "owner_id" not in doc_info or "id" not in doc_info:
        err = save.get("error")
        detail = _format_vk_error(err) if err else str(save)
        logger.error(f"docs.save ({upload_filename}): {detail}")
        return None

    return f"doc{doc_info['owner_id']}_{doc_info['id']}"


def _resolve_peer_ids(cfg: dict, group_id: int, token: str) -> List[int]:
    """Возвращает peer_id получателей: из конфига/env или автоопределением (создатель/диалог группы)."""
    explicit = _parse_peer_ids(cfg.get("peer_ids") or cfg.get("peer_id"))
    if explicit:
        return explicit

    mgr_res = _vk_api_call(
        "groups.getMembers",
        {"group_id": group_id, "filter": "managers"},
        token=token,
        http_method="GET",
        attempts=2,
    )
    manager_items = mgr_res.get("response", {}).get("items", [])
    manager_items.sort(key=lambda item: 0 if item.get("role") == "creator" else 1)
    manager_ids = [int(item["id"]) for item in manager_items if item.get("id")]

    conv_res = _vk_api_call(
        "messages.getConversations",
        {"count": 20},
        token=token,
        http_method="GET",
        attempts=2,
    )
    if "error" in conv_res:
        logger.error(_format_vk_error(conv_res["error"]))
        return manager_ids[:1]

    allowed_peers: List[int] = []
    for item in conv_res.get("response", {}).get("items", []):
        conv = item.get("conversation", {})
        pid = conv.get("peer", {}).get("id")
        if pid and conv.get("can_write", {}).get("allowed"):
            allowed_peers.append(int(pid))

    mgr_allowed = [pid for pid in manager_ids if pid in allowed_peers]
    if mgr_allowed:
        return [mgr_allowed[0]]
    if len(allowed_peers) == 1:
        return allowed_peers
    if manager_ids:
        return [manager_ids[0]]

    logger.error(
        "Не удалось определить peer_id получателя. Напишите «привет» своей группе ВК или укажите peer_id в vk_config.json."
    )
    return []


def _send_vk_message(peer_id: int, message: str, attachments: List[str], token: str) -> bool:
    """Отправляет сообщение с .docx вложениями в ЛС от имени сообщества."""
    res = _vk_api_call(
        "messages.send",
        {
            "peer_id": peer_id,
            "random_id": random.SystemRandom().randint(1, 2_147_483_647),
            "message": message,
            "attachment": ",".join(attachments),
        },
        token=token,
        http_method="POST",
        timeout=(10, 20),
    )
    if "response" in res:
        logger.info(f"Отправлено в ЛС VK (peer_id={peer_id}, msg_id={res['response']}): {', '.join(attachments)}")
        return True

    err = res.get("error")
    detail = _format_vk_error(err) if err else str(res)
    logger.error(f"Ошибка messages.send (peer_id={peer_id}): {detail}")
    return False


def publish_to_vk(whitelist_links: Optional[List[str]] = None) -> bool:
    cfg = load_vk_config()
    if not cfg or not cfg.get("enabled", True):
        return False

    token = str(cfg.get("access_token", "")).strip()
    group_id = str(cfg.get("group_id", "")).strip()
    suffix = str(cfg.get("suffix", "")).strip()
    if not token or not group_id:
        logger.info("VK secrets не заданы, отправка в VK пропущена.")
        return False

    out_dir = BASE_DIR / "output"
    (out_dir / "notes.docx").unlink(missing_ok=True)

    list_1 = list(whitelist_links) if whitelist_links else _read_links_from_file(out_dir / "whitelist.txt")
    if not list_1:
        list_1 = _read_links_from_file(out_dir / "whitelist.txt")
    list_2 = _read_links_from_file(out_dir / "blacklist.txt")

    now = _now_msk()
    now_str = now.strftime("%d.%m.%Y %H:%M")
    stamp = now.strftime("%Y%m%d_%H%M")

    targets = [
        (out_dir / f"notes_1{suffix}.docx", f"notes_1_{stamp}{suffix}.docx", f"1{suffix} БС ({len(list_1)})", list_1),
        (out_dir / f"notes_2{suffix}.docx", f"notes_2_{stamp}{suffix}.docx", f"2{suffix} ЧС ({len(list_2)})", list_2),
    ]

    built_items: List[Tuple[Path, str, str]] = []
    for local_path, upload_name, label, links in targets:
        built = _build_single_docx(local_path, links)
        if built:
            built_items.append((built, upload_name, label))

    if not built_items:
        logger.info("Нет ссылок для отправки .docx в VK.")
        return False

    try:
        peer_ids = _resolve_peer_ids(cfg, int(group_id), token)
        if not peer_ids:
            return False

        all_sent = True
        for peer_id in peer_ids:
            attachments: List[str] = []
            labels: List[str] = []
            for built_path, upload_name, label in built_items:
                att = _upload_message_docx(built_path, upload_name, peer_id, token)
                if att:
                    attachments.append(att)
                    labels.append(label)
                else:
                    all_sent = False

            if not attachments:
                all_sent = False
                continue

            msg_text = f"{' · '.join(labels)} | {now_str}"
            if not _send_vk_message(peer_id, msg_text, attachments, token):
                all_sent = False

        return all_sent

    except Exception as e:
        logger.error(f"Исключение при отправке .docx в ЛС VK: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    publish_to_vk()
