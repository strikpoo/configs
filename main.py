# -*- coding: utf-8 -*-
"""
Главная точка входа комбайна: сбор, очистка, проверка и экспорт VPN-подписок.
"""

import sys
import asyncio
import logging
import argparse
from pathlib import Path

# Добавляем текущую директорию в PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from fetcher import fetch_all_sources
from filter import deduplicate_nodes, classify_nodes
from checker import check_nodes_pool
from exporter import save_subscriptions, push_to_android_adb

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

async def run_pipeline(skip_check: bool = False, auto_push: bool = True, limit: int = 0):
    logger = logging.getLogger("harvester")
    logger.info("=" * 60)
    logger.info("   VPN HARVESTER & WHITE-LIST FILTER (RUSSIAN TSPO BYPASS)")
    logger.info("=" * 60)

    # 1. Загрузка сырых конфигураций из всех источников
    raw_nodes = await fetch_all_sources()
    if not raw_nodes:
        logger.error("Не удалось получить ни одного узла. Завершение работы.")
        return

    # 2. Дедупликация (удаление повторяющихся серверов)
    unique_nodes = deduplicate_nodes(raw_nodes)

    # 3. Валидация доступности (проверка пинга и отсев мертвых серверов)
    if not skip_check:
        alive_nodes, tcp_nodes = await check_nodes_pool(unique_nodes)
    else:
        logger.info("Проверка доступности пропущена по флагу --no-check.")
        alive_nodes = [(node, 0.0) for node in unique_nodes]
        tcp_nodes = unique_nodes

    if not alive_nodes and not tcp_nodes:
        logger.warning("Живых узлов не обнаружено после проверки!")
        return

    # 4. Классификация на White-List и Black-List
    whitelist, blacklist = classify_nodes(alive_nodes, tcp_nodes, unique_nodes)

    # Применение лимита, если указан
    if limit > 0:
        whitelist = whitelist[:limit]
        blacklist = blacklist[:limit]

    # 5. Экспорт в файлы
    out_dir = save_subscriptions(whitelist, blacklist)

    # 6. Отправка на телефон через ADB
    if auto_push:
        logger.info("Попытка отправки списков на подключенный телефон через ADB...")
        push_to_android_adb("whitelist.txt")
        push_to_android_adb("blacklist.txt")
        push_to_android_adb("whitelist_base64.txt")
        push_to_android_adb("blacklist_base64.txt")
        push_to_android_adb("happ_whitelist.txt")
        push_to_android_adb("happ_whitelist_base64.txt")

    # 7. Автоматическая публикация White-List в закрытую группу VK
    try:
        from vk_publisher import publish_to_vk
        publish_to_vk(whitelist)
    except Exception as e:
        logger.warning(f"Пропуск публикации в VK: {e}")

    logger.info("=" * 60)
    logger.info(f" ГОТОВО! Сгенерировано:")
    logger.info(f" -> White-List (чистый список под шатдауны): {len(whitelist)} серверов")
    logger.info(f" -> Black-List (серверы под обход блокировок): {len(blacklist)} серверов")
    logger.info(f" Папка: {out_dir}")
    logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="VPN Harvester & White/Black List Generator")
    parser.add_argument("--no-check", action="store_true", help="Пропустить проверку пинга (быстрый экспорт)")
    parser.add_argument("--no-push", action="store_true", help="Не отправлять файл на телефон по ADB")
    parser.add_argument("--limit", type=int, default=0, help="Ограничить количество серверов в списках")
    args = parser.parse_args()

    setup_logging()
    asyncio.run(run_pipeline(
        skip_check=args.no_check,
        auto_push=not args.no_push,
        limit=args.limit
    ))


if __name__ == "__main__":
    main()
