# -*- coding: utf-8 -*-
"""
Логика классификации конфигураций (White-List vs Black-List), дедупликация и форматирование имен.
"""

import re
import ipaddress
import logging
import urllib.request
from typing import List, Tuple, Dict, Set
from parser import ProxyNode
from config import RU_WHITE_SNI

logger = logging.getLogger("harvester.filter")

# Официальные списки ТСПУ белых списков РФ (домены и IP CIDR из hxehex/russia-mobile-internet-whitelist)
_TSPU_LOADED = False
_TSPU_DOMAINS: Set[str] = set()
_TSPU_CIDRS_BY_FIRST: Dict[int, List[ipaddress.IPv4Network]] = {}
_FALLBACK_TSPU_CIDRS = (
    "185.229.0.0/18",
    "185.86.144.0/22",
)


def _ensure_tspu_lists() -> None:
    """Ленивая загрузка актуальных списков разрешенных доменов и подсетей ТСПУ (с офлайн-фоллбэком)."""
    global _TSPU_LOADED
    if _TSPU_LOADED:
        return
    _TSPU_LOADED = True

    for cidr_str in _FALLBACK_TSPU_CIDRS:
        net = ipaddress.ip_network(cidr_str, strict=False)
        _TSPU_CIDRS_BY_FIRST.setdefault(int(net.network_address) >> 24, []).append(net)

    base = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/"
    try:
        raw_dom = urllib.request.urlopen(base + "whitelist.txt", timeout=5.0).read().decode("utf-8", errors="ignore")
        for line in raw_dom.splitlines():
            d = line.strip().lower()
            if d and not d.startswith("#"):
                _TSPU_DOMAINS.add(d)
    except Exception as e:
        logger.debug(f"Не удалось подгрузить TSPU whitelist.txt ({e}), используем встроенный список")

    try:
        raw_cidr = urllib.request.urlopen(base + "cidrwhitelist.txt", timeout=5.0).read().decode("utf-8", errors="ignore")
        loaded_cidrs = 0
        _TSPU_CIDRS_BY_FIRST.clear()
        for line in raw_cidr.splitlines():
            c = line.strip()
            if not c or c.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(c, strict=False)
                if net.version == 4:
                    _TSPU_CIDRS_BY_FIRST.setdefault(int(net.network_address) >> 24, []).append(net)
                    loaded_cidrs += 1
            except Exception:
                continue
        if loaded_cidrs > 0:
            logger.info(f"Загружены списки ТСПУ: {len(_TSPU_DOMAINS)} доменов, {loaded_cidrs} IPv4 CIDR")
    except Exception as e:
        logger.debug(f"Не удалось подгрузить TSPU cidrwhitelist.txt ({e}), используем резервные CIDR")


def is_tspu_cidr(host: str) -> bool:
    """Точная проверка IP-адреса на вхождение в официальный список ТСПУ-подсетей (cidrwhitelist.txt), исключая зарубежные пулы (Contabo FR / AEZA FI)."""
    _ensure_tspu_lists()
    h = (host or "").strip()
    if h.startswith(("194.163.", "185.102.", "185.103.")):
        return False
    try:
        ip = ipaddress.ip_address(h)
        if ip.version != 4:
            return False
        first_octet = int(ip) >> 24
        return any(ip in net for net in _TSPU_CIDRS_BY_FIRST.get(first_octet, ()))
    except Exception:
        return False


def is_ru_white_sni(sni: str) -> bool:
    """Проверка, относится ли SNI строго к разрешенному российскому пулу (Минцифры / ТСПУ)."""
    if not sni:
        return False
    sni = sni.strip().lower()

    if sni in RU_WHITE_SNI:
        return True

    for white_domain in RU_WHITE_SNI:
        if sni.endswith("." + white_domain):
            return True

    return False


def deduplicate_nodes(nodes: List[ProxyNode]) -> List[ProxyNode]:
    """Удаление дубликатов серверов по уникальному ключу (протокол + хост + порт + ключ)."""
    seen: Dict[str, ProxyNode] = {}
    for node in nodes:
        key = node.unique_key
        if key not in seen:
            seen[key] = node
        else:
            if node.is_whitelist_source:
                seen[key].is_whitelist_source = True
            if node.is_blacklist_source:
                seen[key].is_blacklist_source = True

    logger.info(f"Дедупликация: из {len(nodes)} узлов осталось уникальных: {len(seen)}")
    return list(seen.values())


def is_russian_cidr(node: ProxyNode) -> bool:
    """Проверка, относится ли сервер к ТСПУ-подсетям или российским облакам (VK, Yandex, Timeweb, Beget, RTK)."""
    h = node.host.strip()
    if is_tspu_cidr(h):
        return True

    ru_prefixes = (
        "95.163.", "51.250.", "158.160.", "84.201.", "89.169.", "178.154.", "130.193.", "62.84.",
        "77.88.", "87.250.", "188.72.", "84.23.", "193.168.", "185.12.", "185.129.", "188.68.", "188.93.",
        "92.53.", "95.85.", "80.90.", "95.173.", "95.182.", "194.226.", "195.19.", "5.188.", "195.209.",
        "72.56.", "91.185.", "46.243.", "188.127.", "188.225.", "94.241.", "90.156.",
        "176.108.", "78.37.", "195.208.", "213.171.", "109.120.", "212.233.", "185.248.",
        "141.133.", "185.229.", "185.86.", "178.248.", "88.218.", "88.210.", "84.54.",
        "45.67.", "186.246."
    )
    if any(h.startswith(p) for p in ru_prefixes):
        return True

    name_upper = (node.name or "").upper()
    if "[*CIDR]" in name_upper or "[CIDR]" in name_upper:
        return True

    return False


def is_official_ru_sni(sni_or_host: str) -> bool:
    """Проверка на официальные российские домены из белых списков Минцифры / ТСПУ."""
    _ensure_tspu_lists()
    dom = (sni_or_host or "").lower().strip()
    if not dom or dom == "maps.apple.com":
        return False

    if _TSPU_DOMAINS:
        parts = dom.split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in _TSPU_DOMAINS:
                return True

    if is_ru_white_sni(dom):
        return True
    extra_official = (
        "wbbasket.ru", "yastatic.net", "mts.ru", "t2.ru", "tele2.ru", "megafon.ru", "beeline.ru",
        "pochta.ru", "rzd.ru", "alfabank.ru", "gazprombank.ru", "2gis.ru",
        "kp.ru", "ivi.ru", "wink.ru", "hh.ru"
    )
    return any(dom == d or dom.endswith("." + d) for d in extra_official)


def is_ru_domain_sni(sni_or_host: str) -> bool:
    """Проверка, относится ли SNI/Host к российским доменам (.ru / .su / .рф или официальным платформам)."""
    check_domain = (sni_or_host or "").lower().strip()
    if not check_domain:
        return False
    return (
        is_official_ru_sni(check_domain) or
        check_domain.endswith((".ru", ".su", ".xn--p1ai"))
    )


def is_confirmed_wl_prefix(host: str) -> bool:
    """Подсети из cidrwhitelist.txt, реально пробивающие региональные белые списки (VK, Citytelecom, HLL, Yandex Cloud)."""
    h = (host or "").strip()
    return h.startswith((
        "185.86.", "185.229.", "178.248.",
        "95.163.", "84.23.", "51.250.", "158.160.", "84.201.",
        "84.252.", "217.13.", "37.9."
    ))


def get_wl_rank(node: ProxyNode) -> int:
    """
    Приоритет узлов для обхода региональных белых списков ТСПУ:
    Ранг 0: IP в официальном ТСПУ cidrwhitelist + официальный SNI Минцифры (максимальный шанс пробития!)
    Ранг 1: Проверенные белые подсети в ТСПУ cidrwhitelist (VK Cloud / Citytelecom / HLL / Yandex Cloud)
    Ранг 2: Прочие российские IP в официальном ТСПУ cidrwhitelist
    Ранг 3: Официальный SNI Минцифры на любом живом сервере (yandex.net, yandex.ru, max.ru, mail.ru, vk.com)
    Ранг 4: Прочие RU-префиксы + российский доменный SNI (.ru / .su / .рф)
    Ранг 5: Российский доменный SNI (.ru / .su / .рф) на прочих серверах
    Ранг 6: Прочие RU-префиксы на стандартном/нестандартном порту
    """
    if node.protocol not in ("vless", "vmess"):
        return 99

    net = node.params.get("type", "tcp").lower().strip()
    if net not in ("tcp", "raw", "xhttp", "splithttp", "grpc", "ws", "http", "h2", ""):
        return 99

    if node.protocol == "vless":
        sec = node.params.get("security", "").lower().strip()
        if sec not in ("reality", "tls"):
            return 99
        if sec == "reality" or node.is_reality:
            pbk = node.params.get("pbk", "").strip().replace(" ", "+")
            if len(pbk) < 42 or len(pbk) > 45:
                return 99

    check_domain = (node.sni or node.params.get("host", "")).lower().strip()
    if "cloudflare.com" in check_domain or "rkn" in check_domain:
        return 99

    in_tspu_ip = is_tspu_cidr(node.host)
    in_tspu_sni = is_official_ru_sni(check_domain)
    in_ru_net = is_russian_cidr(node)
    in_ru_dom = is_ru_domain_sni(check_domain)

    if not (in_tspu_ip or in_tspu_sni or in_ru_net or in_ru_dom):
        return 99

    if in_tspu_ip and in_tspu_sni:
        return 0
    if in_tspu_ip and is_confirmed_wl_prefix(node.host):
        return 1
    if in_tspu_ip:
        return 2
    if in_tspu_sni:
        return 3
    if in_ru_net and in_ru_dom:
        return 4
    if in_ru_dom:
        return 5
    if in_ru_net:
        return 6

    return 99


def is_cloudflare_ip(host: str) -> bool:
    """Проверка, относится ли адрес к диапазонам Cloudflare CDN Anycast."""
    h = (host or "").lower().strip()
    cf_prefixes = (
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
        "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.",
        "172.64.", "172.65.", "172.66.", "172.67.", "188.114.", "162.158.", "162.159."
    )
    return any(h.startswith(p) for p in cf_prefixes)


def is_valid_blacklist_node(node: ProxyNode) -> bool:
    """Проверка узла для Black-List: VLESS Reality (без CDN) или проверенный VLESS TLS для обхода ТСПУ."""
    if node.protocol != "vless":
        return False

    sec = node.params.get("security", "").lower().strip()
    if sec not in ("reality", "tls"):
        return False

    net = node.params.get("type", "tcp").lower().strip()
    if net not in ("tcp", "raw", "ws", "grpc", ""):
        return False

    h = node.host.lower()
    sni = (node.sni or "").lower()

    if sec == "reality":
        pbk = node.params.get("pbk", "").strip()
        if len(pbk) < 40:
            return False
        # Reality не может работать через WebSocket или за прокси Cloudflare/Fastly
        if net == "ws" or is_cloudflare_ip(h):
            return False
    else:
        # Для VLESS TLS + WS требуется доменный host/sni (не голый IP и не cloudflare.com)
        if net == "ws" and not (sni or node.params.get("host")):
            return False

    # СТРОГО исключаем российские домены (.ru/VK/Yandex/White-SNI) из Black-List
    if is_ru_white_sni(sni) or sni.endswith((".ru", ".su")):
        return False

    # Исключаем мусорные имена и локальные адреса
    if "rkn" in sni or "fuck" in sni or "127.0.0.1" in h or "0.0.0.0" in h:
        return False

    # Исключаем сам домен cloudflare.com в SNI (жестко сбрасывается мобильным ТСПУ МТС)
    if "cloudflare.com" in sni or "cloudflare.com" in (node.params.get("host", "").lower()):
        return False

    # Исключаем Fastly и облачные подсети, массово заблокированные РКН в РФ (IBM/Alibaba/Oracle)
    bad_markers = (
        "fastly", "199.232.", "151.101.", "167.82.", "146.75.",
        "169.40.", "47.84.", "47.251.", "47.252.", "47.253.", "47.254.",
        "156.229.", "166.0.", "185.95.231.",
        "158.101.", "140.245.", "130.61.", "132.145.", "129.151."
    )
    if any(m in h or m in sni for m in bad_markers):
        return False

    # Разрешаем стандартные HTTPS/CDN порты, а для курируемых RU Black-List источников — любые порты (напр. 29976, 39790, 6750)
    if not node.is_blacklist_source and str(node.port) not in ("443", "8443", "2053", "2083", "2087", "2096"):
        return False

    return True


def is_mts_confirmed_sni(sni: str) -> bool:
    """Топовые проверенные SNI, пробивающие мобильный ТСПУ МТС в РФ."""
    if not sni:
        return False
    sni = sni.lower().strip()
    return "nlafterdate" in sni or "h1clayd" in sni


def is_trusted_sni(sni: str) -> bool:
    """Проверка SNI на надежные мировые домены."""
    if not sni:
        return False
    sni = sni.lower().strip()
    if is_mts_confirmed_sni(sni):
        return True
    trusted = (
        "apple.com", "icloud.com", "itunes.com", "aaplimg.com",
        "microsoft.com", "live.com", "azure.com", "skype.com",
        "samsung.com", "nvidia.com", "sony.com"
    )
    return any(sni == t or sni.endswith("." + t) for t in trusted)


def get_bl_rank(node: ProxyNode) -> int:
    """Ранжирование узлов Black-List с учетом совместимости с МТС и Wi-Fi:
    Ранг 0: Прямой не-Cloudflare VLESS Reality TCP (Vision) на порту 443 (лучший выбор и для МТС, и для Wi-Fi)
    Ранг 1: Прямой не-Cloudflare VLESS TLS TCP на 443/8443 (быстрые прямые и каскадные TLS-узлы)
    Ранг 2: Прочие прямые не-Cloudflare Reality/TLS (gRPC, нестандартные порты, прямой WS)
    Ранг 3: Чистые Cloudflare CDN Worker VLESS TLS WS (без cloudflare.com в SNI)
    """
    sec = node.params.get("security", "").lower().strip()
    flow = node.params.get("flow", "").lower()
    net = node.params.get("type", "tcp").lower().strip()
    is_p443 = str(node.port) == "443"
    is_cf = is_cloudflare_ip(node.host)

    if is_cf:
        return 3
    if sec == "reality" and is_p443 and "vision" in flow and net in ("tcp", "raw", ""):
        return 0
    if sec == "tls" and net in ("tcp", "raw", "") and str(node.port) in ("443", "8443"):
        return 1
    return 2


def is_germany_node(node: ProxyNode) -> bool:
    """Определение, является ли узел сервером / релеем с выходом в Германию."""
    h = node.host.strip()
    de_ips = (
        "188.68.218.205",
        "5.188.26.85",
        "195.19.20.80",
        "194.226.142.120",
        "2.27.54.132",
        "144.31.159.84",
        "185.137.157.72",
        "188.68.216.38"
    )
    if h in de_ips:
        return True

    name_upper = (node.name or "").upper()
    if "GERMANY" in name_upper or "🇩🇪" in node.name or "DE" in name_upper:
        return True

    host_param = (node.params.get("host", "")).lower()
    sni_param = (node.sni or "").lower()
    if "mirra.now" in host_param or "wbbasket.ru" in sni_param or "mirra.now" in sni_param:
        return True

    return False


def classify_nodes(
    alive_nodes_with_ping: List[Tuple[ProxyNode, float]],
    tcp_alive_nodes: List[ProxyNode] = None,
    all_raw_nodes: List[ProxyNode] = None
) -> Tuple[List[str], List[str]]:
    """
    Разделение живых узлов на:
    1. White-List (СТРОГО: xHTTP / gRPC / VMess WS + порт 443/80 + официальный RU-SNI под шатдауны Минцифры)
    2. Black-List (Обход блокировок, зарубежные сайты)
    """
    wl_pairs: List[Tuple[ProxyNode, float, int, bool]] = []
    seen_wl_keys = set()
    bl_candidates: List[Tuple[ProxyNode, float, bool]] = []
    seen_bl_keys = set()

    for node, ping_ms in alive_nodes_with_ping:
        # Если узел подходит под Black-List - добавляем в Black-List с флагом проверенного URL-теста!
        if is_valid_blacklist_node(node) and node.unique_key not in seen_bl_keys:
            bl_candidates.append((node, ping_ms, True))
            seen_bl_keys.add(node.unique_key)

        # Если узел подходит под White-List - добавляем с флагом URL-теста!
        rank = get_wl_rank(node)
        if rank < 10 and node.unique_key not in seen_wl_keys:
            wl_pairs.append((node, ping_ms, rank, True))
            seen_wl_keys.add(node.unique_key)

    # 2. Берем подтвержденные по TCP порту узлы ТОЛЬКО как резерв после URL-проверенных
    if tcp_alive_nodes:
        for node in tcp_alive_nodes:
            if is_valid_blacklist_node(node) and node.unique_key not in seen_bl_keys:
                bl_candidates.append((node, node.tcp_ping or 150.0, False))
                seen_bl_keys.add(node.unique_key)

            rank = get_wl_rank(node)
            if rank < 10 and node.unique_key not in seen_wl_keys:
                wl_pairs.append((node, node.tcp_ping or 120.0, rank, False))
                seen_wl_keys.add(node.unique_key)

    # Сортировка White-List:
    # 1. URL-проверенные (Xray xHTTP + Sing-Box YouTube 204) ВСЕГДА впереди!
    # 2. Ранг устойчивости (0 = RU-CIDR + RU-SNI -> 1 = RU-CIDR -> 2..4 = RU-SNI)
    # 3. Задержка
    wl_pairs.sort(key=lambda x: (not x[3], x[2], x[1] > 1200 if x[3] else True, x[1]))

    # Ограничение White-List до 100 уникальных серверов (максимум 2 записи на host:port)
    selected_wl = []
    wl_overflow = []
    wl_hp_counts: Dict[Tuple[str, int], int] = {}
    for item in wl_pairs:
        hp = (item[0].host.lower(), int(item[0].port))
        cnt = wl_hp_counts.get(hp, 0)
        if cnt < 2:
            selected_wl.append(item)
            wl_hp_counts[hp] = cnt + 1
            if len(selected_wl) >= 100:
                break
        else:
            wl_overflow.append(item)
    if len(selected_wl) < 100:
        selected_wl.extend(wl_overflow[:(100 - len(selected_wl))])

    whitelist_uris: List[str] = []
    de_count = 0
    ru_count = 0

    for node, ping_ms, rank, url_verified in selected_wl:
        display_sni = node.sni or node.params.get("host", "no-sni")
        if len(display_sni) > 22:
            display_sni = display_sni[:20] + ".."
        net = node.params.get("type", "tcp").lower().strip()
        prefix = f"⚡ [{int(ping_ms)}ms] " if url_verified else ""

        if is_russian_cidr(node):
            ru_count += 1
            flag = "🇷🇺"
            if "nvidia" in display_sni:
                label = f"Russia Nvidia #{ru_count:02d}"
            elif net in ("xhttp", "splithttp"):
                label = f"Russia xHTTP #{ru_count:02d}"
            elif net == "grpc":
                label = f"Russia gRPC #{ru_count:02d}"
            else:
                label = f"Russia CIDR #{ru_count:02d}"
        else:
            de_count += 1
            flag = "🇩🇪" if is_germany_node(node) else "🌐"
            if net in ("xhttp", "splithttp"):
                label = f"White xHTTP #{de_count:02d}"
            elif net == "grpc":
                label = f"White gRPC #{de_count:02d}"
            else:
                label = f"White Relay #{de_count:02d}"

        clean_name = f"{prefix}{flag} {label} ({display_sni})"
        node.name = clean_name
        whitelist_uris.append(node.build_uri(new_name=clean_name))

    # Для Black-List (МТС + Wi-Fi):
    # 1. Проверенные YouTube-тестом узлы всегда впереди
    # 2. Прямые не-CDN узлы до 1200мс впереди медленных (> 1200мс) и Cloudflare CDN
    # 3. Внутри уровня — минимальный реальный пинг, а доля Cloudflare CDN ограничена (не более 6 шт при наличии прямых)
    def bl_sort_key(item):
        node, ping_ms, verified = item
        rank = get_bl_rank(node)
        tier = 0 if rank <= 1 else (1 if rank == 2 else 2)
        is_slow = (ping_ms > 1200 or ping_ms <= 0) if verified else True
        return (
            not verified,
            tier == 2,
            is_slow,
            tier,
            ping_ms if ping_ms > 0 else 9999.0,
            rank,
        )

    bl_candidates.sort(key=bl_sort_key)

    # Ограничиваем до 2 узлов на один (host, port) и до 6 Cloudflare CDN в топе 50
    selected_bl = []
    cf_overflow = []
    overflow_bl = []
    host_port_counts: Dict[Tuple[str, int], int] = {}
    cf_count = 0
    for item in bl_candidates:
        is_cf = is_cloudflare_ip(item[0].host)
        hp = (item[0].host.lower(), int(item[0].port))
        cnt = host_port_counts.get(hp, 0)
        if cnt < 2:
            if is_cf and cf_count >= 6:
                cf_overflow.append(item)
                continue
            selected_bl.append(item)
            host_port_counts[hp] = cnt + 1
            if is_cf:
                cf_count += 1
            if len(selected_bl) >= 50:
                break
        else:
            overflow_bl.append(item)

    if len(selected_bl) < 50:
        selected_bl.extend(cf_overflow[:(50 - len(selected_bl))])
    if len(selected_bl) < 50:
        selected_bl.extend(overflow_bl[:(50 - len(selected_bl))])

    blacklist_uris: List[str] = []

    for i, (node, ping_ms, url_verified) in enumerate(selected_bl, 1):
        display_sni = node.sni or node.params.get("host", "no-sni")
        if len(display_sni) > 22:
            display_sni = display_sni[:20] + ".."
        orig_name = node.name.strip()
        prefix = f"⚡ [{int(ping_ms)}ms] " if url_verified else ""
        if any(f in orig_name for f in ("🇨🇿", "🇩🇪", "🇯🇵", "🇸🇪", "🇸🇬", "🇮🇪", "🇦🇪", "🇫🇮", "🇧🇬", "🇳🇱", "🇺🇸", "🇬🇧", "🇫🇷")):
            clean_name = f"{prefix}{orig_name} ({display_sni})"
        else:
            clean_name = f"{prefix}🌐 Global Reality #{i:02d} ({display_sni})"
        blacklist_uris.append(node.build_uri(new_name=clean_name))

    logger.info(f"Классификация завершена: White-List: {len(whitelist_uris)} шт (🇩🇪 Германия: {de_count}, 🇷🇺 Россия: {ru_count}), Black-List: {len(blacklist_uris)} шт (лимит 50)")
    return (whitelist_uris, blacklist_uris)
