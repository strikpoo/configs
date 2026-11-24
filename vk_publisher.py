# -*- coding: utf-8 -*-
"""
Модуль формирования двух раздельных .docx документов и отправки в закрытое сообщество ВКонтакте.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
from zoneinfo import ZoneInfo

import docx
import requests

logger = logging.getLogger("harvester.vk")
BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "vk_config.json"


def _now_msk() -> datetime:
    try:
        return datetime.now(ZoneInfo("Europe/Moscow"))
    except Exception:
        return datetime.now(timezone(timedelta(hours=3)))


def load_vk_config():
    env_token = os.environ.get("VK_ACCESS_TOKEN", "").strip()
    env_group = os.environ.get("VK_GROUP_ID", "").strip()
    env_suffix = os.environ.get("VK_SUFFIX", "").strip()
    if env_token and env_group:
        return {
            "enabled": True,
            "access_token": env_token,
            "group_id": env_group,
            "suffix": env_suffix,
        }

    if not CONFIG_PATH.exists():
        return None
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            if env_suffix and not cfg.get("suffix"):
                cfg["suffix"] = env_suffix
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
        if line and "://" in line:
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


def _upload_docx(doc_path: Path, upload_filename: str, group_id: int, token: str) -> Optional[str]:
    """Загружает .docx файл на сервер документов VK (с автоповтором при временном сбое сервера) и возвращает attachment-строку."""
    doc_bytes = doc_path.read_bytes()
    for attempt in range(3):
        if attempt > 0:
            time.sleep(1.0)
        srv = requests.get(
            "https://api.vk.com/method/docs.getWallUploadServer",
            params={
                "group_id": group_id,
                "access_token": token,
                "v": "5.199",
            },
            timeout=15,
        ).json()

        if "response" not in srv:
            logger.warning(f"Попытка {attempt + 1}/3 getWallUploadServer ({upload_filename}): {srv}")
            continue

        upload_url = srv["response"]["upload_url"]
        up_resp = requests.post(
            upload_url,
            files={
                "file": (
                    upload_filename,
                    doc_bytes,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
            timeout=30,
        )
        if not up_resp.text or not up_resp.text.strip():
            logger.warning(f"Попытка {attempt + 1}/3 пустой ответ upload ({upload_filename})")
            continue

        try:
            up = up_resp.json()
        except ValueError:
            logger.warning(f"Попытка {attempt + 1}/3 не-JSON ответ upload ({upload_filename}): {up_resp.text[:120]}")
            continue

        if "file" not in up:
            logger.warning(f"Попытка {attempt + 1}/3 ошибка upload ({upload_filename}): {up}")
            continue

        save = requests.post(
            "https://api.vk.com/method/docs.save",
            data={
                "file": up["file"],
                "title": upload_filename,
                "access_token": token,
                "v": "5.199",
            },
            timeout=15,
        ).json()

        if "response" not in save or "doc" not in save["response"]:
            logger.warning(f"Попытка {attempt + 1}/3 ошибка docs.save ({upload_filename}): {save}")
            continue

        doc_info = save["response"]["doc"]
        return f"doc{doc_info['owner_id']}_{doc_info['id']}"

    logger.error(f"Не удалось загрузить {upload_filename} в VK после 3 попыток.")
    return None


def publish_to_vk(whitelist_links: Optional[List[str]] = None) -> bool:
    cfg = load_vk_config()
    if not cfg or not cfg.get("enabled", True):
        return False

    token = str(cfg.get("access_token", "")).strip()
    group_id = str(cfg.get("group_id", "")).strip()
    suffix = str(cfg.get("suffix", "")).strip()
    if not token or not group_id:
        logger.info("VK secrets не заданы, публикация в VK пропущена.")
        return False

    out_dir = BASE_DIR / "output"
    old_single = out_dir / "notes.docx"
    old_single.unlink(missing_ok=True)

    list_1 = list(whitelist_links) if whitelist_links else _read_links_from_file(out_dir / "whitelist.txt")
    if not list_1:
        list_1 = _read_links_from_file(out_dir / "whitelist.txt")
    list_2 = _read_links_from_file(out_dir / "blacklist.txt")

    now = _now_msk()
    now_str = now.strftime("%d.%m.%Y %H:%M")
    stamp = now.strftime("%Y%m%d_%H%M")

    # Публикуем от обратного порядка: сперва 2, затем 1 — чтобы Файл 1 (основной) был самым верхним постом на стене
    targets = [
        (out_dir / f"notes_2{suffix}.docx", f"notes_2_{stamp}{suffix}.docx", f"2{suffix} · {now_str}", list_2),
        (out_dir / f"notes_1{suffix}.docx", f"notes_1_{stamp}{suffix}.docx", f"1{suffix} · {now_str}", list_1),
    ]

    published_posts: List[int] = []
    try:
        for idx, (local_path, upload_name, wall_msg, links) in enumerate(targets):
            built = _build_single_docx(local_path, links)
            if not built:
                continue
            att = _upload_docx(built, upload_name, int(group_id), token)
            if not att:
                continue
            if idx > 0 and published_posts:
                time.sleep(0.5)
            res = requests.post(
                "https://api.vk.com/method/wall.post",
                data={
                    "owner_id": -int(group_id),
                    "from_group": 1,
                    "message": wall_msg,
                    "attachments": att,
                    "access_token": token,
                    "v": "5.199",
                },
                timeout=15,
            ).json()

            if "response" in res:
                pid = res["response"].get("post_id")
                published_posts.append(pid)
                logger.info(f"Опубликован {upload_name} в VK (post_id: {pid})")
            else:
                logger.error(f"Ошибка публикации {upload_name} в VK: {res}")

        return len(published_posts) == sum(1 for t in targets if t[3])

    except Exception as e:
        logger.error(f"Исключение при отправке .docx в VK: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    publish_to_vk()
