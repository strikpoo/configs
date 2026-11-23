# -*- coding: utf-8 -*-
"""
Логика классификации конфигураций (White-List vs Black-List), дедупликация и форматирование имен.
"""

import re
import logging
from typing import List, Tuple, Dict
from parser import ProxyNode
from config import RU_WHITE_SNI

logger = logging.getLogger("harvester.filter")


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
            # Если у дубликата указан стандартный chrome, используем его
            if node.params.get("fp") == "chrome":
                seen[key].params["fp"] = "chrome"

    logger.info(f"Дедупликация: из {len(nodes)} узлов осталось уникальных: {len(seen)}")
    return list(seen.values())


def is_russian_cidr(node: ProxyNode) -> bool:
    """Проверка, относится ли сервер к российским пулам адресов (VK Cloud, Selectel, Yandex, Timeweb, Reg.ru)."""
    h = node.host.strip()
    ru_prefixes = (
        "95.163.", "51.250.", "77.88.", "87.250.", "185.12.", "185.129.",
        "188.68.", "188.93.", "92.53.", "80.90.", "95.173.", "95.182.",
        "194.226.", "195.19.", "5.188.", "195.209."
    )
    if any(h.startswith(p) for p in ru_prefixes):
        return True
    
    name_upper = (node.name or "").upper()
    if "[*CIDR]" in name_upper or "CIDR" in name_upper or "RUSSIA" in name_upper or "🇷🇺" in node.name:
        return True

    return False


def get_wl_rank(node: ProxyNode) -> int:
    """
    Приоритет узлов для обхода региональных белых списков:
    Ранг 0: Внутрироссийский CIDR / Релей (VK xHTTP, Selectel gRPC Reality, Reg.ru VMess WS) на 443 с RU-SNI / RU-Host
    Ранг 1: VLESS Reality xHTTP на 443 порт с RU-SNI
    Ранг 2: VLESS Reality gRPC на 443 порт с RU-SNI
    Ранг 3: VLESS Reality TCP (Raw) на 443 порт с RU-SNI
    Ранг 4: Другие xHTTP узлы из белых источников
    Ранг 5: Прочие узлы из белых источников (VMess WS, etc.)
    """
    net = node.params.get("type", "tcp").lower().strip()
    is_real = node.is_reality or node.params.get("security") == "reality"
    is_p443 = node.port in (443, 80)
    
    check_domain = (node.sni or node.params.get("host", "")).lower().strip()
    is_ru_sni = (
        is_ru_white_sni(check_domain) or
        check_domain in ("ok.ru", "vk.com", "ya.ru", "yandex.ru", "alfastat.ru", "donatov.net", "git.xpkg.ru", "git.medrocket.ru") or
        check_domain.endswith(".ru") or
        check_domain.endswith(".userapi.com") or
        check_domain.endswith(".yandex.net") or
        check_domain.endswith(".mirra.now") or
        "mirra.now" in check_domain or
        "wbbasket.ru" in check_domain or
        "nvidia.com" in check_domain
    )
    is_cidr = is_russian_cidr(node)
    is_de = is_germany_node(node)

    if not is_p443:
        return 99

    # Топовый приоритет: Внутрироссийский CIDR / Релей на 443 порт
    if is_cidr and is_ru_sni:
        if "wbbasket.ru" in check_domain:
            return 0  # Selectel gRPC Reality (Wildberries - надежно открыт на мобильных сетях)
        elif "nvidia.com" in check_domain:
            return 0  # Nvidia Relay 443
        elif net in ("xhttp", "splithttp") and is_real:
            return 1  # VK xHTTP Reality
        elif net == "grpc" and is_real:
            return 1  # Другие gRPC Reality
        elif node.protocol == "vmess" and net == "ws":
            return 1  # Reg.ru VMess WS TLS
        return 2

    # Немецкий релей для белого списка
    if is_de and is_ru_sni:
        return 0

    if is_real and is_ru_sni:
        if net in ("xhttp", "splithttp"):
            return 1
        elif net == "grpc":
            return 2
        elif net in ("tcp", "raw", ""):
            return 3
        return 4
    elif is_ru_sni:
        if net in ("xhttp", "splithttp"):
            return 4
        return 5
    elif is_de:
        return 6

    return 10


def is_valid_blacklist_node(node: ProxyNode) -> bool:
    """Проверка узла для Black-List: СТРОГО чистый VLESS Reality для обхода ТСПУ."""
    if node.protocol != "vless":
        return False
    if node.params.get("security") != "reality":
        return False
    pbk = node.params.get("pbk", "").strip()
    if len(pbk) < 40:
        return False

    # Исключаем WebSocket (ws блокируется ТСПУ в РФ на мобильных сетях)
    net = node.params.get("type", "tcp").lower().strip()
    if net == "ws":
        return False

    h = node.host.lower()
    sni = (node.sni or "").lower()

    # СТРОГО исключаем российские домены и российские сети из Black-List!
    # (Они принадлежат белому списку и не могут открыть YouTube/Instagram)
    if is_ru_white_sni(sni) or sni.endswith(".ru") or is_russian_cidr(node):
        return False

    # Исключаем мусорные имена
    if "rkn" in sni or "fuck" in sni or "127.0.0.1" in h or "0.0.0.0" in h:
        return False

    # Исключаем Cloudflare SNI (жестко блокируется ТСПУ на мобильных сетях в РФ)
    if "cloudflare.com" in sni:
        return False

    # Исключаем Cloudflare CDN и Fastly Anycast IP (они не работают как прямой Reality)
    bad_markers = (
        "fastly", "199.232.", "151.101.", "167.82.", "146.75.",
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.24.", "104.27.",
        "172.64.", "172.67.", "188.114.", "162.159."
    )
    if any(m in h or m in sni for m in bad_markers):
        return False

    # Порты 443 или 8443
    if str(node.port) not in ("443", "8443"):
        return False

    return True


def is_trusted_sni(sni: str) -> bool:
    """Проверка SNI на максимальную совместимость с мобильным ТСПУ МТС."""
    if not sni:
        return False
    sni = sni.lower().strip()
    # Приоритетные SNI, подтвержденные на сети МТС
    if "nlafterdate" in sni or "h1clayd" in sni:
        return True
    trusted = (
        "apple.com", "icloud.com", "itunes.com", "aaplimg.com",
        "microsoft.com", "live.com", "azure.com", "skype.com",
        "amazon.com", "aws.amazon.com", "cloudfront.net",
        "samsung.com", "yahoo.com", "nvidia.com", "sony.com"
    )
    return any(sni == t or sni.endswith("." + t) for t in trusted)


def get_bl_rank(node: ProxyNode) -> int:
    """Приоритет узлов Black-List под мобильные сети (МТС ТСПУ):
    Ранг 0: nlafterdate / h1clayd / Apple / Microsoft + Port 443 + Vision + Прямой IP
    Ранг 1: nlafterdate / h1clayd / Apple / Microsoft + Port 443 + Vision (домен)
    Ранг 2: Прочие Reality на порту 443 + Vision
    Ранг 3: Reality на порту 443 без Vision
    Ранг 4: Прочие порты
    """
    flow = node.params.get("flow", "").lower()
    net = node.params.get("type", "tcp").lower().strip()
    is_p443 = str(node.port) == "443"
    sni = (node.sni or "").lower()
    is_mts_fav = is_trusted_sni(sni)
    is_vision = "vision" in flow and net in ("tcp", "raw", "")
    is_direct_ip = all(p.isdigit() for p in node.host.split(".")) if node.host.count(".") == 3 else False

    if is_p443 and is_vision and is_mts_fav:
        return 0 if is_direct_ip else 1
    if is_p443 and is_vision:
        return 2
    if is_p443:
        return 3
    return 4


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
    wl_pairs: List[Tuple[ProxyNode, float, int]] = []
    seen_wl_keys = set()
    bl_candidates: List[Tuple[ProxyNode, float, bool]] = []
    seen_bl_keys = set()

    for node, ping_ms in alive_nodes_with_ping:
        # Если узел подходит под Black-List - добавляем в Black-List с флагом проверенного URL-теста!
        if is_valid_blacklist_node(node) and node.unique_key not in seen_bl_keys:
            bl_candidates.append((node, ping_ms, True))
            seen_bl_keys.add(node.unique_key)

        # Если узел подходит под White-List - добавляем в White-List
        rank = get_wl_rank(node)
        if rank < 10 and node.unique_key not in seen_wl_keys:
            wl_pairs.append((node, ping_ms, rank))
            seen_wl_keys.add(node.unique_key)

    # 2. Берем подтвержденные живые узлы, проверенные по TCP порту (как запасные)
    if tcp_alive_nodes:
        for node in tcp_alive_nodes:
            if is_valid_blacklist_node(node) and node.unique_key not in seen_bl_keys:
                bl_candidates.append((node, node.tcp_ping or 150.0, False))
                seen_bl_keys.add(node.unique_key)

            rank = get_wl_rank(node)
            if rank < 10 and node.unique_key not in seen_wl_keys:
                wl_pairs.append((node, node.tcp_ping or 120.0, rank))
                seen_wl_keys.add(node.unique_key)

    # 3. Гарантированное включение подтвержденных немецких релеев и российских CIDR для White-List
    if all_raw_nodes:
        for node in all_raw_nodes:
            if is_germany_node(node) and get_wl_rank(node) < 10 and node.unique_key not in seen_wl_keys:
                wl_pairs.append((node, 105.0, 0))
                seen_wl_keys.add(node.unique_key)
            elif get_wl_rank(node) == 0 and node.unique_key not in seen_wl_keys:
                wl_pairs.append((node, 115.0, 0))
                seen_wl_keys.add(node.unique_key)

    # Разделяем на немецкие релеи и российские узлы
    de_list = [p for p in wl_pairs if is_germany_node(p[0])]
    ru_list = [p for p in wl_pairs if not is_germany_node(p[0])]

    de_list.sort(key=lambda x: (x[2], x[1]))
    ru_list.sort(key=lambda x: (x[2], x[1]))

    # Ограничение White-List максимум 100 серверами (быстрые и отзывчивые под мобильные):
    # Балансируем: лучшие немецкие релеи (50 шт) и лучшие российские узлы (50 шт) по рангу и TCP-пингу
    max_de = 50
    max_ru = 50
    selected_de = de_list[:max_de]
    selected_ru = ru_list[:max_ru]
    if len(selected_de) < max_de:
        selected_ru = ru_list[:(100 - len(selected_de))]
    elif len(selected_ru) < max_ru:
        selected_de = de_list[:(100 - len(selected_ru))]

    wl_pairs = selected_de + selected_ru

    whitelist_uris: List[str] = []
    de_count = 0
    ru_count = 0

    for node, ping_ms, rank in wl_pairs:
        display_sni = node.sni or node.params.get("host", "no-sni")
        if len(display_sni) > 22:
            display_sni = display_sni[:20] + ".."
        net = node.params.get("type", "tcp").lower().strip()

        if is_germany_node(node):
            de_count += 1
            flag = "🇩🇪"
            if node.protocol == "vmess":
                label = f"Germany VMess #{de_count:02d}"
            elif net == "grpc":
                label = f"Germany Selectel #{de_count:02d}"
            else:
                label = f"Germany Relay #{de_count:02d}"
        else:
            ru_count += 1
            flag = "🇷🇺"
            if "nvidia" in display_sni:
                label = f"Russia Nvidia #{ru_count:02d}"
            elif net in ("xhttp", "splithttp"):
                label = f"Russia VK #{ru_count:02d}"
            elif net == "grpc":
                label = f"Russia gRPC #{ru_count:02d}"
            else:
                label = f"Russia CIDR #{ru_count:02d}"

        clean_name = f"{flag} {label} ({display_sni})"
        node.name = clean_name
        whitelist_uris.append(node.build_uri(new_name=clean_name))

    # Ограничение Black-List максимум 50 серверами под мобильные сети (МТС ТСПУ):
    # 1. Подтвержденные Sing-Box URL-тестом узлы с пингом < 800мс идут первыми, строго по возрастанию пинга
    # 2. Подтвержденные узлы с высоким пингом (> 800мс) смещаются назад (на мобильных они дают таймаут)
    # 3. Далее идут высокоранговые неподтвержденные узлы под МТС (nlafterdate, h1clayd, Apple, Microsoft)
    bl_candidates.sort(
        key=lambda x: (
            not x[2],                                     # 0 если проверен Sing-Box (True), 1 если нет
            x[1] > 800 if x[2] else True,                 # На мобильном интернете пинг > 800мс дает таймаут
            x[1] if (x[2] and x[1] <= 800) else 9999.0,   # Быстрые проверенные строго по пингу
            get_bl_rank(x[0]),                            # Ранг МТС (nlafterdate, h1clayd, direct IP)
            x[1] if x[1] > 0 else 9999.0                  # Прочий TCP пинг
        )
    )
    selected_bl = bl_candidates[:50]
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
