# -*- coding: utf-8 -*-
"""
Конфигурация параметров фильтрации, белых доменов (RU-SNI) и сетевых тайм-аутов.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = BASE_DIR / "output"
SOURCES_FILE = BASE_DIR / "sources.json"

# Белый список российских доменов и SNI (разрешенные Минцифры и не блокируемые при шатдаунах)
RU_WHITE_SNI = {
    # Яндекс
    "ya.ru",
    "yandex.ru",
    "yandex.net",
    "storage.yandex.net",
    "avatars.mds.yandex.net",
    "mc.yandex.ru",
    "disk.yandex.ru",
    "music.yandex.ru",
    "dzen.ru",
    # VK / Mail.ru
    "vk.com",
    "vk.ru",
    "userapi.com",
    "sun6-21.userapi.com",
    "mail.ru",
    "ok.ru",
    "my.mail.ru",
    "cloud.mail.ru",
    # Государственные и финансовые сервисы
    "gosuslugi.ru",
    "esia.gosuslugi.ru",
    "sberbank.ru",
    "sber.ru",
    "tinkoff.ru",
    "tbank.ru",
    "vtb.ru",
    "cbr.ru",
    "nalog.gov.ru",
    "mos.ru",
    "pfr.gov.ru",
    # Маркетплейсы и крупные RU-платформы
    "ozon.ru",
    "wildberries.ru",
    "avito.ru",
    "rutube.ru",
    "megamarket.ru",
    "kinopoisk.ru",
    "max.ru",
    # CDN, инфраструктура и глобальные белые списки
    "selectel.ru",
    "yandexcloud.net",
    "cloud.mts.ru",
    "rt.ru",
    "maps.apple.com",
    "x5.ru",
    "ads.x5.ru",
    "kommersant.ru"
}

# Сетевые настройки валидатора
CHECKER_CONCURRENCY = 256     # Количество одновременных сокет-проверок (TCP Ping)
TCP_CHECK_TIMEOUT = 1.2       # Тайм-аут сокет-проверки доступности порта в секундах
FETCHER_TIMEOUT = 30.0        # Тайм-аут скачивания подписки из интернета

# Настройки реального URL-теста (через Sing-Box core)
SINGBOX_PATH = str(BASE_DIR.parent / "tools" / "sing-box.exe")
URL_TEST_ENDPOINT = "https://www.google.com/generate_204"
URL_TEST_TIMEOUT = 5.0        # Тайм-аут рукопожатия VLESS Reality + HTTP 204 в секундах
URL_TEST_CONCURRENCY = 64     # Потоков одновременного URL-теста через Clash API
SINGBOX_API_PORT = 19095

# Настройки экспорта
ADB_PATH = str(BASE_DIR.parent / "tools" / "scrcpy-win64-v4.1" / "adb.exe")
DEVICE_TARGET_DIR = "/sdcard/Download"
