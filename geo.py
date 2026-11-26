# -*- coding: utf-8 -*-
"""
Определение страны реального подключения (Exit IP через Xray или Entry IP GeoIP),
кэширование результатов и форматирование флага с названием страны на русском языке.
"""

import ipaddress
import json
import logging
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("harvester.geo")
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_GEO_CACHE_PATH = Path(tempfile.gettempdir()) / "vpn_harvester_geo_cache.json"
_GEO_CACHE_TTL_SEC = 7 * 24 * 3600
_CACHE_LOCK = threading.Lock()
_MEMORY_CACHE: Dict[str, Tuple[str, float]] = {}
_CACHE_LOADED = False

_RATE_LOCK = threading.Lock()
_IPINFO_COOLDOWN_UNTIL = 0.0
_IPWHO_COOLDOWN_UNTIL = 0.0

_EXIT_IP_URLS = (
    "http://api.ipify.org",
    "http://checkip.amazonaws.com",
    "http://icanhazip.com",
    "http://ifconfig.me/ip",
)

COUNTRY_NAMES_RU: Dict[str, str] = {
    "AD": "Андорра",
    "AE": "ОАЭ",
    "AF": "Афганистан",
    "AL": "Албания",
    "AM": "Армения",
    "AO": "Ангола",
    "AR": "Аргентина",
    "AT": "Австрия",
    "AU": "Австралия",
    "AZ": "Азербайджан",
    "BA": "Босния и Герцеговина",
    "BD": "Бангладеш",
    "BE": "Бельгия",
    "BG": "Болгария",
    "BH": "Бахрейн",
    "BM": "Бермуды",
    "BN": "Бруней",
    "BO": "Боливия",
    "BR": "Бразилия",
    "BS": "Багамы",
    "BY": "Беларусь",
    "BZ": "Белиз",
    "CA": "Канада",
    "CH": "Швейцария",
    "CL": "Чили",
    "CN": "Китай",
    "CO": "Колумбия",
    "CR": "Коста-Рика",
    "CU": "Куба",
    "CY": "Кипр",
    "CZ": "Чехия",
    "DE": "Германия",
    "DK": "Дания",
    "DO": "Доминикана",
    "DZ": "Алжир",
    "EC": "Эквадор",
    "EE": "Эстония",
    "EG": "Египет",
    "ES": "Испания",
    "ET": "Эфиопия",
    "FI": "Финляндия",
    "FO": "Фарерские о-ва",
    "FR": "Франция",
    "GB": "Великобритания",
    "GE": "Грузия",
    "GG": "Гернси",
    "GH": "Гана",
    "GI": "Гибралтар",
    "GL": "Гренландия",
    "GR": "Греция",
    "GT": "Гватемала",
    "HK": "Гонконг",
    "HN": "Гондурас",
    "HR": "Хорватия",
    "HU": "Венгрия",
    "ID": "Индонезия",
    "IE": "Ирландия",
    "IL": "Израиль",
    "IM": "Остров Мэн",
    "IN": "Индия",
    "IQ": "Ирак",
    "IR": "Иран",
    "IS": "Исландия",
    "IT": "Италия",
    "JE": "Джерси",
    "JM": "Ямайка",
    "JO": "Иордания",
    "JP": "Япония",
    "KE": "Кения",
    "KG": "Кыргызстан",
    "KH": "Камбоджа",
    "KR": "Южная Корея",
    "KW": "Кувейт",
    "KY": "Каймановы о-ва",
    "KZ": "Казахстан",
    "LA": "Лаос",
    "LB": "Ливан",
    "LI": "Лихтенштейн",
    "LK": "Шри-Ланка",
    "LT": "Литва",
    "LU": "Люксембург",
    "LV": "Латвия",
    "MA": "Марокко",
    "MC": "Монако",
    "MD": "Молдова",
    "ME": "Черногория",
    "MK": "Северная Македония",
    "MM": "Мьянма",
    "MN": "Монголия",
    "MO": "Макао",
    "MT": "Мальта",
    "MU": "Маврикий",
    "MX": "Мексика",
    "MY": "Малайзия",
    "NG": "Нигерия",
    "NL": "Нидерланды",
    "NO": "Норвегия",
    "NP": "Непал",
    "NZ": "Новая Зеландия",
    "OM": "Оман",
    "PA": "Панама",
    "PE": "Перу",
    "PH": "Филиппины",
    "PK": "Пакистан",
    "PL": "Польша",
    "PR": "Пуэрто-Рико",
    "PS": "Палестина",
    "PT": "Португалия",
    "PY": "Парагвай",
    "QA": "Катар",
    "RO": "Румыния",
    "RS": "Сербия",
    "RU": "Россия",
    "SA": "Саудовская Аравия",
    "SC": "Сейшелы",
    "SE": "Швеция",
    "SG": "Сингапур",
    "SI": "Словения",
    "SK": "Словакия",
    "SM": "Сан-Марино",
    "TH": "Таиланд",
    "TJ": "Таджикистан",
    "TM": "Туркменистан",
    "TN": "Тунис",
    "TR": "Турция",
    "TW": "Тайвань",
    "TZ": "Танзания",
    "UA": "Украина",
    "UG": "Уганда",
    "US": "США",
    "UY": "Уругвай",
    "UZ": "Узбекистан",
    "VE": "Венесуэла",
    "VG": "Виргинские о-ва",
    "VN": "Вьетнам",
    "ZA": "ЮАР",
}


def normalize_country_code(code: Optional[str]) -> str:
    """Нормализует двухбуквенный ISO-код страны (UK -> GB, отсекает мусор)."""
    if not code:
        return ""
    c = str(code).strip().upper()
    if c == "UK":
        c = "GB"
    if c in ("XX", "ZZ", "T1", "A1", "A2", "EU", "AP"):
        return ""
    if len(c) == 2 and c.isascii() and c.isalpha():
        return c
    return ""


def country_code_to_flag(code: Optional[str]) -> str:
    """Преобразует ISO 3166-1 alpha-2 код в emoji-флаг (напр. DE -> 🇩🇪)."""
    c = normalize_country_code(code)
    if not c:
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in c)


def format_country_label(code: Optional[str]) -> Tuple[str, str]:
    """Возвращает (emoji_flag, russian_country_name) для кода страны или 'CF'."""
    raw = (code or "").strip().upper()
    if raw == "CF":
        return ("🌐", "Cloudflare")
    norm = normalize_country_code(raw)
    if not norm:
        return ("🌐", "Неизвестно")
    return (country_code_to_flag(norm), COUNTRY_NAMES_RU.get(norm, norm))


def _is_public_ip(value: str) -> Optional[str]:
    """Проверяет, что строка является публичным IPv4/IPv6 адресом."""
    try:
        ip_obj = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified:
        return None
    return str(ip_obj)


def _load_geo_cache() -> None:
    global _CACHE_LOADED
    with _CACHE_LOCK:
        if _CACHE_LOADED:
            return
        _CACHE_LOADED = True
        if not _GEO_CACHE_PATH.exists():
            return
        try:
            data = json.loads(_GEO_CACHE_PATH.read_text(encoding="utf-8"))
            now = time.time()
            if isinstance(data, dict):
                for ip_str, rec in data.items():
                    if (
                        isinstance(rec, list)
                        and len(rec) == 2
                        and isinstance(rec[1], (int, float))
                        and (now - rec[1]) < _GEO_CACHE_TTL_SEC
                    ):
                        norm = normalize_country_code(rec[0])
                        if norm:
                            _MEMORY_CACHE[ip_str] = (norm, float(rec[1]))
        except Exception:
            pass


def _save_geo_cache() -> None:
    with _CACHE_LOCK:
        try:
            now = time.time()
            payload = {
                ip_str: [code, ts]
                for ip_str, (code, ts) in _MEMORY_CACHE.items()
                if (now - ts) < _GEO_CACHE_TTL_SEC
            }
            tmp_path = _GEO_CACHE_PATH.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp_path.replace(_GEO_CACHE_PATH)
        except Exception:
            pass


def _query_json(url: str, timeout: float = 3.5) -> Tuple[int, Optional[object]]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def _fetch_country_single(ip_str: str) -> str:
    """Определяет ISO-код страны для одного публичного IP по цепочке GeoIP-провайдеров."""
    global _IPINFO_COOLDOWN_UNTIL, _IPWHO_COOLDOWN_UNTIL
    now = time.monotonic()

    # 1. ipinfo.io (наиболее точный для VPS/хостингов)
    if now >= _IPINFO_COOLDOWN_UNTIL:
        status, data = _query_json(f"https://ipinfo.io/{ip_str}/json", timeout=3.5)
        if status == 429:
            with _RATE_LOCK:
                _IPINFO_COOLDOWN_UNTIL = time.monotonic() + 120.0
        elif isinstance(data, dict):
            code = normalize_country_code(data.get("country"))
            if code:
                return code

    # 2. ipwho.is (высокая точность на европейских провайдерах)
    if time.monotonic() >= _IPWHO_COOLDOWN_UNTIL:
        status, data = _query_json(f"https://ipwho.is/{ip_str}", timeout=3.5)
        if status == 429:
            with _RATE_LOCK:
                _IPWHO_COOLDOWN_UNTIL = time.monotonic() + 120.0
        elif isinstance(data, dict) and data.get("success", True):
            code = normalize_country_code(data.get("country_code"))
            if code:
                return code

    # 3. api.country.is (быстрый fallback)
    _, data = _query_json(f"https://api.country.is/{ip_str}", timeout=3.5)
    if isinstance(data, dict):
        code = normalize_country_code(data.get("country"))
        if code:
            return code

    # 4. get.geojs.io (резервный fallback)
    _, data = _query_json(f"https://get.geojs.io/v1/ip/country.json?ip={ip_str}", timeout=3.5)
    if isinstance(data, list) and data:
        data = data[0]
    if isinstance(data, dict):
        code = normalize_country_code(data.get("country"))
        if code:
            return code

    return ""


def lookup_countries(ips: Iterable[str], max_workers: int = 8) -> Dict[str, str]:
    """Возвращает {ip: ISO_CODE} для списка публичных IP с использованием локального кэша."""
    _load_geo_cache()
    result: Dict[str, str] = {}
    missing: List[str] = []
    seen = set()
    now = time.time()

    with _CACHE_LOCK:
        for raw in ips:
            norm_ip = _is_public_ip(raw)
            if not norm_ip or norm_ip in seen:
                continue
            seen.add(norm_ip)
            cached = _MEMORY_CACHE.get(norm_ip)
            if cached and (now - cached[1]) < _GEO_CACHE_TTL_SEC:
                result[norm_ip] = cached[0]
            else:
                missing.append(norm_ip)

    if not missing:
        return result

    def _worker(ip_item: str) -> Tuple[str, str]:
        return ip_item, _fetch_country_single(ip_item)

    new_entries: Dict[str, Tuple[str, float]] = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(missing))) as pool:
        for ip_item, code in pool.map(_worker, missing):
            if code:
                result[ip_item] = code
                new_entries[ip_item] = (code, time.time())

    if new_entries:
        with _CACHE_LOCK:
            _MEMORY_CACHE.update(new_entries)
        _save_geo_cache()

    return result


def _probe_xray_chunk(xray_bin: Path, chunk: List[Tuple[object, dict]], max_workers: int = 28) -> Dict[str, str]:
    """Запускает Xray на чанке узлов и получает реальный внешний Exit IP каждого узла."""
    if not chunk:
        return {}

    from checker import get_free_port

    base_port = get_free_port() + 120
    inbounds = []
    outbounds = []
    rules = []
    test_map = []

    for i, (node, ob) in enumerate(chunk):
        port = base_port + i
        tag_in = f"geo_in_{i}"
        ob_copy = dict(ob)
        ob_copy["tag"] = f"geo_out_{i}"
        inbounds.append({"port": port, "listen": "127.0.0.1", "protocol": "http", "tag": tag_in})
        outbounds.append(ob_copy)
        rules.append({"type": "field", "inboundTag": [tag_in], "outboundTag": ob_copy["tag"]})
        test_map.append((node, port))

    temp_cfg = Path(tempfile.gettempdir()) / f"xray_geo_{base_port}.json"
    cfg = {"log": {"loglevel": "error"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}}
    temp_cfg.write_text(json.dumps(cfg), encoding="utf-8")

    proc = subprocess.Popen(
        [str(xray_bin), "run", "-c", str(temp_cfg)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=_NO_WINDOW,
    )
    time.sleep(1.2)
    if proc.poll() is not None:
        temp_cfg.unlink(missing_ok=True)
        if len(chunk) > 1:
            mid = len(chunk) // 2
            res_map = _probe_xray_chunk(xray_bin, chunk[:mid], max_workers=max_workers)
            res_map.update(_probe_xray_chunk(xray_bin, chunk[mid:], max_workers=max_workers))
            return res_map
        return {}

    def _probe_one(item) -> Tuple[str, str]:
        node, port = item
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"})
        )
        for url in _EXIT_IP_URLS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
                with opener.open(req, timeout=3.8) as resp:
                    if resp.status == 200:
                        raw_ip = resp.read(80).decode("utf-8", errors="ignore").strip()
                        valid_ip = _is_public_ip(raw_ip)
                        if valid_ip:
                            return node.unique_key, valid_ip
            except Exception:
                continue
        return node.unique_key, ""

    exit_ips: Dict[str, str] = {}
    try:
        with ThreadPoolExecutor(max_workers=min(len(test_map), max_workers)) as pool:
            for key, ex_ip in pool.map(_probe_one, test_map):
                if ex_ip:
                    exit_ips[key] = ex_ip
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        temp_cfg.unlink(missing_ok=True)

    return exit_ips


def probe_exit_ips_xray(nodes: List[object], max_workers: int = 28) -> Dict[str, str]:
    """Возвращает {node.unique_key: exit_ip} для узлов с рабочим туннелем через Xray."""
    if not nodes:
        return {}
    try:
        from checker import _build_xray_outbound, _resolve_xray_bin
    except Exception:
        return {}

    xray_bin = _resolve_xray_bin()
    if not xray_bin:
        return {}

    prepared: List[Tuple[object, dict]] = []
    seen = set()
    for n in nodes:
        if n.unique_key in seen:
            continue
        ob = _build_xray_outbound(n, f"geo_{len(prepared)}")
        if ob:
            seen.add(n.unique_key)
            prepared.append((n, ob))

    if not prepared:
        return {}

    t0 = time.monotonic()
    exit_ips: Dict[str, str] = {}
    for start in range(0, len(prepared), 40):
        exit_ips.update(_probe_xray_chunk(xray_bin, prepared[start:start + 40], max_workers=max_workers))

    logger.info(f"GeoIP: определён реальный Exit IP для {len(exit_ips)} из {len(prepared)} проверенных узлов за {time.monotonic() - t0:.1f}с")
    return exit_ips


def resolve_nodes_countries(selected_nodes: List[Tuple[object, bool]]) -> Dict[str, str]:
    """
    Определяет реальный код страны (ISO-2 или 'CF') для финального списка узлов [(ProxyNode, url_verified)].
    Для URL-проверенных узлов приоритетно замеряется реальный Exit IP через туннель;
    для остальных (или при таймауте пробы) используется GeoIP входного IP узла.
    """
    if not selected_nodes:
        return {}

    from parser import resolve_to_ip
    from filter import is_cloudflare_ip, is_russian_cidr

    verified_nodes: List[object] = []
    all_by_key: Dict[str, object] = {}
    for node, url_verified in selected_nodes:
        all_by_key.setdefault(node.unique_key, node)
        if url_verified:
            verified_nodes.append(node)

    exit_ip_map = probe_exit_ips_xray(verified_nodes) if verified_nodes else {}

    ips_to_lookup: List[str] = []
    entry_ip_map: Dict[str, str] = {}
    for key, node in all_by_key.items():
        entry_ip = resolve_to_ip(node.host).strip()
        entry_ip_map[key] = entry_ip
        target_ip = exit_ip_map.get(key) or entry_ip
        if _is_public_ip(target_ip) and (key in exit_ip_map or not is_cloudflare_ip(entry_ip)):
            ips_to_lookup.append(target_ip)

    geo_map = lookup_countries(ips_to_lookup) if ips_to_lookup else {}

    resolved_codes: Dict[str, str] = {}
    for key, node in all_by_key.items():
        if key in exit_ip_map:
            code = geo_map.get(exit_ip_map[key], "")
            if code:
                resolved_codes[key] = code
                continue

        entry_ip = entry_ip_map.get(key, "")
        if is_cloudflare_ip(entry_ip):
            resolved_codes[key] = "CF"
            continue

        code = geo_map.get(entry_ip, "")
        if not code and is_russian_cidr(node):
            code = "RU"
        resolved_codes[key] = code

    return resolved_codes
