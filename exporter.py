# -*- coding: utf-8 -*-
"""
Экспортер готовых подписок (.txt) и доставка на подключенное устройство через ADB.
"""

import base64
import logging
import subprocess
from pathlib import Path
from typing import List
from config import OUTPUT_DIR, ADB_PATH, DEVICE_TARGET_DIR

logger = logging.getLogger("harvester.exporter")


def _format_subscription_text(nodes_list: List[str], title: str) -> str:
    """Формирует текст подписки с мета-заголовками названия профиля (#profile-title) для клиентов (INCY / Happ / v2rayNG)."""
    title_b64 = base64.b64encode(title.encode("utf-8")).decode("ascii")
    header = f"#profile-title: base64:{title_b64}\n#profile-update-interval: 1\n"
    return header + "\n".join(nodes_list) + "\n"


def save_subscriptions(whitelist: List[str], blacklist: List[str]) -> Path:
    """Сохранение подписок в директорию output/ (только .txt форматы)."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Удаляем устаревшие non-.txt форматы подписок, если остались на диске
    for legacy_name in ("happ_whitelist.json", "happ_blacklist.json", "happ_config.json", "happ_config.zip", "happ.html"):
        (OUTPUT_DIR / legacy_name).unlink(missing_ok=True)

    wl_file = OUTPUT_DIR / "whitelist.txt"
    bl_file = OUTPUT_DIR / "blacklist.txt"
    wl_b64_file = OUTPUT_DIR / "whitelist_base64.txt"
    bl_b64_file = OUTPUT_DIR / "blacklist_base64.txt"
    happ_txt_file = OUTPUT_DIR / "happ_whitelist.txt"
    happ_b64_file = OUTPUT_DIR / "happ_whitelist_base64.txt"

    wl_text = _format_subscription_text(whitelist, "🏳️ БС")
    bl_text = _format_subscription_text(blacklist, "🏴 ЧС")

    # Сохранение White-List (.txt)
    with open(wl_file, "w", encoding="utf-8") as f:
        f.write(wl_text)

    with open(happ_txt_file, "w", encoding="utf-8") as f:
        f.write(wl_text)

    wl_b64 = base64.b64encode(wl_text.encode("utf-8")).decode("utf-8")
    with open(wl_b64_file, "w", encoding="utf-8") as f:
        f.write(wl_b64 + "\n")

    with open(happ_b64_file, "w", encoding="utf-8") as f:
        f.write(wl_b64 + "\n")

    # Сохранение Black-List (.txt)
    with open(bl_file, "w", encoding="utf-8") as f:
        f.write(bl_text)

    bl_b64 = base64.b64encode(bl_text.encode("utf-8")).decode("utf-8")
    with open(bl_b64_file, "w", encoding="utf-8") as f:
        f.write(bl_b64 + "\n")

    logger.info(f"Файлы успешно сохранены в папку: {OUTPUT_DIR}")
    logger.info(f" -> {wl_file.name} ({len(whitelist)} узлов)")
    logger.info(f" -> {bl_file.name} ({len(blacklist)} узлов)")
    logger.info(f" -> {wl_b64_file.name}, {bl_b64_file.name}, {happ_txt_file.name}, {happ_b64_file.name} (.txt)")

    return OUTPUT_DIR


def push_to_android_adb(filename: str = "whitelist.txt") -> bool:
    """Отправка сгенерированного файла на подключенный телефон через ADB с уведомлением MediaScanner."""
    source_file = OUTPUT_DIR / filename
    if not source_file.exists():
        logger.error(f"Файл {source_file} не существует для отправки!")
        return False

    adb = Path(ADB_PATH)
    if not adb.exists():
        logger.warning(f"ADB не найден по пути {ADB_PATH}. Пропускаем отправку.")
        return False

    try:
        # Проверяем наличие подключенных устройств
        check_dev = subprocess.run([str(adb), "devices"], capture_output=True, text=True, timeout=15)
        lines = [l.strip() for l in check_dev.stdout.splitlines() if l.strip() and not l.startswith("*")]
        devices = [l for l in lines if "device" in l and not l.startswith("List")]

        if not devices:
            logger.warning("Устройство не подключено по ADB. Файл сохранен локально.")
            return False

        target_path = f"{DEVICE_TARGET_DIR}/{filename}"
        res = subprocess.run([str(adb), "push", str(source_file), target_path], capture_output=True, text=True, timeout=15)
        if res.returncode == 0:
            logger.info(f"Файл успешно передан на телефон: {target_path}")
            # Оповещаем MediaScanner Android, чтобы файл мгновенно отображался в проводнике/загрузках
            subprocess.run([str(adb), "shell", f"am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file://{target_path}"], capture_output=True, text=True, timeout=5)
            return True
        else:
            logger.error(f"Ошибка передачи через ADB: {res.stderr}")
            return False
    except Exception as e:
        logger.error(f"Ошибка при работе с ADB: {e}")
        return False
