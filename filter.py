# -*- coding: utf-8 -*-
"""
Логика классификации конфигураций (White-List vs Black-List), дедупликация и форматирование имен.
"""

import re
import ipaddress
import logging
import urllib.request
from typing import List, Tuple, Dict, Set
from parser import ProxyNode, resolve_to_ip
from config import RU_WHITE_SNI
from geo import resolve_nodes_countries, format_country_label

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
    Ранг 1: IP в официальном ТСПУ cidrwhitelist + российский доменный SNI (.ru / .su / .рф)
    Ранг 2: Официальный SNI Минцифры на любом живом сервере (yandex.ru, vk.com, vk.me, gosuslugi.ru, max.ru, mail.ru)
    Ранг 3: Проверенные белые подсети в ТСПУ cidrwhitelist (VK Cloud / Citytelecom / HLL / Yandex Cloud)
    Ранг 4: Прочие российские IP в официальном ТСПУ cidrwhitelist
    Ранг 5: Прочие RU-префиксы + российский доменный SNI (.ru / .su / .рф)
    Ранг 6: Российский доменный SNI (.ru / .su / .рф) на прочих серверах
    Ранг 7: Прочие RU-префиксы
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
    if in_tspu_ip and in_ru_dom:
        return 1
    if in_tspu_sni:
        return 2
    if in_tspu_ip and is_confirmed_wl_prefix(node.host):
        return 3
    if in_tspu_ip:
        return 4
    if in_ru_net and in_ru_dom:
        return 5
    if in_ru_dom:
        return 6
    if in_ru_net:
        return 7

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
    if net not in ("tcp", "raw", "xhttp", "splithttp", "ws", "grpc", ""):
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
        # Для VLESS TLS + WS / xHTTP требуется доменный host/sni
        if net in ("ws", "xhttp", "splithttp") and not (sni or node.params.get("host")):
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
    """Ранжирование узлов Black-List с приоритетом мобильной устойчивости (МТС/ТСПУ + Wi-Fi):
    Ранг 0: Прямой не-Cloudflare VLESS Reality TCP (Vision) на порту 443
    Ранг 1: Прочие прямые не-Cloudflare VLESS Reality (без Vision, xHTTP, gRPC, нестандартные порты)
    Ранг 2: Прямой не-Cloudflare VLESS TLS TCP (443/8443) или прямой VLESS TLS xHTTP (без WebSocket)
    Ранг 3: Прямой не-Cloudflare VLESS TLS WebSocket (резерв, чаще режется на мобильных)
    Ранг 4: Чистые Cloudflare CDN Worker VLESS TLS WS/xHTTP (без cloudflare.com в SNI)
    """
    sec = node.params.get("security", "").lower().strip()
    flow = node.params.get("flow", "").lower()
    net = node.params.get("type", "tcp").lower().strip()
    is_p443 = str(node.port) == "443"
    is_cf = is_cloudflare_ip(node.host)

    if is_cf:
        return 4
    if sec == "reality" and is_p443 and "vision" in flow and net in ("tcp", "raw", ""):
        return 0
    if sec == "reality":
        return 1
    if sec == "tls" and ((net in ("tcp", "raw", "") and str(node.port) in ("443", "8443")) or net in ("xhttp", "splithttp")):
        return 2
    return 3


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


def _format_node_name(
    idx: int,
    node: ProxyNode,
    ping_ms: float,
    url_verified: bool,
    country_code: str,
    is_whitelist: bool = False,
) -> str:
    """Форматирует чистое отображаемое имя узла: задержка, флаг, страна на русском, номер и SNI."""
    display_sni = (node.sni or node.params.get("host") or "").strip() or "no-sni"
    if len(display_sni) > 22:
        display_sni = display_sni[:20] + ".."
    prefix = f"⚡ [{int(ping_ms)}ms] " if url_verified else ""
    flag, country_ru = format_country_label(country_code)

    transport_tag = ""
    if is_whitelist:
        net = node.params.get("type", "tcp").lower().strip()
        if net in ("xhttp", "splithttp"):
            transport_tag = " [xHTTP]"
        elif net == "grpc":
            transport_tag = " [gRPC]"

    return f"{prefix}{flag} {country_ru} #{idx:02d}{transport_tag} ({display_sni})"


def classify_nodes(
    alive_nodes_with_ping: List[Tuple[ProxyNode, float]],
    tcp_alive_nodes: List[ProxyNode] = None,
    all_raw_nodes: List[ProxyNode] = None,
    resolve_geo: bool = True,
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

    # Ограничение White-List до 20 серверов (максимум 2 записи на физический resolved IP:port)
    wl_limit = 20
    selected_wl = []
    wl_overflow = []
    wl_hp_counts: Dict[Tuple[str, int], int] = {}
    for item in wl_pairs:
        resolved_host = resolve_to_ip(item[0].host).lower()
        hp = (resolved_host, int(item[0].port))
        cnt = wl_hp_counts.get(hp, 0)
        if cnt < 2:
            selected_wl.append(item)
            wl_hp_counts[hp] = cnt + 1
            if len(selected_wl) >= wl_limit:
                break
        else:
            wl_overflow.append(item)
    if len(selected_wl) < wl_limit:
        selected_wl.extend(wl_overflow[:(wl_limit - len(selected_wl))])

    # Для Black-List (мобильный ТСПУ + Wi-Fi):
    # 1. Стабильные (прошедшие 2/2 gstatic <= 2.8с в Xray) всегда строго впереди!
    # 2. Остальные URL-проверенные перед голым TCP-резервом
    # 3. Все прямые VLESS Reality и TLS-TCP/xHTTP (ранги 0..2) выше TLS-WS (3) и Cloudflare CDN (4)
    # 4. Внутри группы — быстрые (<= 1800мс) раньше медленных, затем ранг и минимальный пинг
    def bl_sort_key(item):
        node, ping_ms, verified = item
        rank = get_bl_rank(node)
        is_stable = getattr(node, "bl_verified", False)
        is_fragile = rank >= 3  # TLS-WS и Cloudflare CDN
        is_slow = (ping_ms > 1800 or ping_ms <= 0) if verified else True
        return (
            not is_stable,
            not verified,
            is_fragile,
            rank == 4,
            is_slow,
            rank,
            ping_ms if ping_ms > 0 else 9999.0,
        )

    # Убираем дубликаты одного и того же узла под доменом vs resolved IP до финальной выборки
    dedup_bl_candidates: List[Tuple[ProxyNode, float, bool]] = []
    seen_bl_resolved = set()
    bl_candidates.sort(key=bl_sort_key)
    for item in bl_candidates:
        node = item[0]
        r_ip = resolve_to_ip(node.host).lower()
        net = node.params.get("type", "tcp").strip().lower()
        if net in ("raw", ""):
            net = "tcp"
        elif net == "splithttp":
            net = "xhttp"
        auth = node.uuid.strip().lower() or node.params.get("pbk", "").strip()
        rkey = f"{node.protocol}@{r_ip}:{node.port}@{auth}@{net}"
        if rkey not in seen_bl_resolved:
            seen_bl_resolved.add(rkey)
            dedup_bl_candidates.append(item)

    # Максимум 1 конфиг на один физический resolved IP в основном топе-20 (чтобы 1 сервер не забивал весь список)
    # и до 5 быстрых проверенных 2/2 Cloudflare CDN в хвосте; дубли одного IP добираются только если уникальных IP < 20
    bl_limit = 20
    cf_limit = 5
    selected_bl = []
    cf_overflow = []
    overflow_bl = []
    ip_counts: Dict[str, int] = {}
    cf_count = 0
    for item in dedup_bl_candidates:
        r_ip = resolve_to_ip(item[0].host).lower()
        is_cf = is_cloudflare_ip(r_ip)
        cnt = ip_counts.get(r_ip, 0)
        if cnt < 1:
            if is_cf and cf_count >= cf_limit:
                cf_overflow.append(item)
                continue
            selected_bl.append(item)
            ip_counts[r_ip] = 1
            if is_cf:
                cf_count += 1
            if len(selected_bl) >= bl_limit:
                break
        else:
            overflow_bl.append(item)

    if len(selected_bl) < bl_limit:
        selected_bl.extend(cf_overflow[:(bl_limit - len(selected_bl))])
    if len(selected_bl) < bl_limit:
        for item in overflow_bl:
            r_ip = resolve_to_ip(item[0].host).lower()
            if ip_counts.get(r_ip, 0) < 2:
                selected_bl.append(item)
                ip_counts[r_ip] = ip_counts.get(r_ip, 0) + 1
                if len(selected_bl) >= bl_limit:
                    break
    if len(selected_bl) < bl_limit:
        selected_ids = {id(x[0]) for x in selected_bl}
        for item in overflow_bl:
            if id(item[0]) not in selected_ids:
                selected_bl.append(item)
                if len(selected_bl) >= bl_limit:
                    break

    country_codes: Dict[str, str] = {}
    if resolve_geo:
        geo_targets = [(item[0], item[3]) for item in selected_wl] + [(item[0], item[2]) for item in selected_bl]
        country_codes = resolve_nodes_countries(geo_targets)

    whitelist_uris: List[str] = []
    wl_codes: List[str] = []
    for i, (node, ping_ms, _rank, url_verified) in enumerate(selected_wl, 1):
        code = country_codes.get(
            node.unique_key,
            "RU" if is_russian_cidr(node) else ("CF" if is_cloudflare_ip(node.host) else ""),
        )
        wl_codes.append(code)
        clean_name = _format_node_name(i, node, ping_ms, url_verified, code, is_whitelist=True)
        node.name = clean_name
        whitelist_uris.append(node.build_uri(new_name=clean_name))

    blacklist_uris: List[str] = []
    for i, (node, ping_ms, url_verified) in enumerate(selected_bl, 1):
        code = country_codes.get(node.unique_key, "CF" if is_cloudflare_ip(node.host) else "")
        clean_name = _format_node_name(i, node, ping_ms, url_verified, code, is_whitelist=False)
        node.name = clean_name
        blacklist_uris.append(node.build_uri(new_name=clean_name))

    ru_count = sum(1 for c in wl_codes if c == "RU")
    foreign_count = len(whitelist_uris) - ru_count
    logger.info(
        f"Классификация завершена: White-List: {len(whitelist_uris)} шт "
        f"(🌐 Зарубеж/выход: {foreign_count}, 🇷🇺 РФ: {ru_count}), "
        f"Black-List: {len(blacklist_uris)} шт (лимит {bl_limit})"
    )
    return (whitelist_uris, blacklist_uris)
