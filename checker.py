import os
# -*- coding: utf-8 -*-
"""
Двухэтапный валидатор доступности узлов:
1. Экспресс-фильтр TCP Ping (отсеивает мертвые порты за 1-2 секунды).
2. Реальный URL Test через ядро Sing-Box (Clash API):
   Выполняет настоящее TLS Reality рукопожатие и замеряет честный RTT до https://www.google.com/generate_204.
"""

import sys
import json
import time
import socket
import asyncio
import logging
import base64
import tempfile
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures
from pathlib import Path
from typing import List, Tuple, Optional

from parser import ProxyNode, resolve_to_ip
from filter import is_ru_white_sni, get_wl_rank, is_tspu_cidr, _ensure_tspu_lists
from config import (
    CHECKER_CONCURRENCY,
    TCP_CHECK_TIMEOUT,
    SINGBOX_PATH,
    XRAY_PATH,
    URL_TEST_ENDPOINT,
    URL_TEST_TIMEOUT,
    URL_TEST_CONCURRENCY
)

logger = logging.getLogger("harvester.checker")
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def get_free_port() -> int:
    """Поиск свободного локального порта для Sing-Box API."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


async def check_tcp_single(sem: asyncio.Semaphore, node: ProxyNode) -> Tuple[ProxyNode, bool, float]:
    """Быстрая сокет-проверка доступности порта (Stage 1) с увеличенным тайм-аутом для ТСПУ-подсетей."""
    timeout = max(TCP_CHECK_TIMEOUT, 2.0) if is_tspu_cidr(node.host) else TCP_CHECK_TIMEOUT
    async with sem:
        start_time = time.monotonic()
        try:
            connect_task = asyncio.open_connection(node.host, node.port)
            reader, writer = await asyncio.wait_for(connect_task, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            elapsed_ms = (time.monotonic() - start_time) * 1000.0
            node.tcp_ping = elapsed_ms
            return (node, True, elapsed_ms)
        except Exception:
            return (node, False, -1.0)


async def filter_tcp_alive(nodes: List[ProxyNode]) -> List[ProxyNode]:
    """Параллельная экспресс-проверка TCP портов с сортировкой по скорости."""
    if not nodes:
        return []

    _ensure_tspu_lists()
    logger.info(f"Этап 1/2: Экспресс TCP-фильтр {len(nodes)} узлов (пул {CHECKER_CONCURRENCY} потоков, тайм-аут {TCP_CHECK_TIMEOUT}с / ТСПУ 2.0с)...")
    sem = asyncio.Semaphore(CHECKER_CONCURRENCY)
    tasks = [check_tcp_single(sem, node) for node in nodes]
    results = await asyncio.gather(*tasks)
    alive_pairs = [(node, ping) for node, is_alive, ping in results if is_alive]

    alive_pairs.sort(key=lambda x: (get_wl_rank(x[0]), x[1]))
    tcp_alive = [node for node, _ in alive_pairs]

    dead_count = len(nodes) - len(tcp_alive)
    logger.info(f"Этап 1 завершен: доступно по TCP: {len(tcp_alive)}, мертвых портов отсеяно: {dead_count}")
    return tcp_alive


def run_singbox_urltest(nodes: List[ProxyNode]) -> List[Tuple[ProxyNode, float]]:
    """
    Этап 2/2: Полноценное тестирование связи через ядро Sing-Box.
    Проверяет реальное прохождение трафика через VLESS Reality до тестового URL.
    """
    import shutil
    singbox_bin = Path(SINGBOX_PATH)
    if not singbox_bin.exists():
        which_sb = shutil.which("sing-box")
        if which_sb:
            singbox_bin = Path(which_sb)
        else:
            logger.warning(f"Бинарник Sing-Box не найден по пути {SINGBOX_PATH}. Пропускаем Stage 2.")
            return []

    if not nodes:
        return []

    api_port = get_free_port()
    import tempfile
    temp_dir = Path(tempfile.gettempdir())
    config_file = temp_dir / f"singbox_urltest_{api_port}.json"

    # Формируем конфигурацию Sing-Box
    outbounds = [{"type": "direct", "tag": "direct"}]
    node_tag_map = {}

    for i, node in enumerate(nodes):
        tag = f"node_{i}"
        ob = node.to_singbox_outbound(tag)
        if ob:
            outbounds.append(ob)
            node_tag_map[tag] = node

    if not node_tag_map:
        logger.warning("Не удалось преобразовать ни одного узла в формат Sing-Box.")
        return []

    singbox_config = {
        "log": {"level": "panic"},
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{api_port}"
            }
        },
        "outbounds": outbounds
    }

    import re

    # Проверяем валидность конфига перед запуском и отсеиваем сбойные узлы
    max_prune = 500
    pruned_count = 0
    while True:
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(singbox_config, f)

        chk = subprocess.run([str(singbox_bin), "check", "-c", str(config_file)], capture_output=True, text=True, creationflags=_NO_WINDOW)
        if chk.returncode == 0:
            break

        match = re.search(r'outbound\[(\d+)\]', chk.stderr)
        if match and pruned_count < max_prune:
            idx = int(match.group(1))
            if 0 <= idx < len(singbox_config["outbounds"]):
                bad_ob = singbox_config["outbounds"].pop(idx)
                bad_tag = bad_ob.get("tag")
                if bad_tag in node_tag_map:
                    del node_tag_map[bad_tag]
                pruned_count += 1
                continue
        logger.error(f"Ошибка проверки конфигурации Sing-Box: {chk.stderr[:250]}")
        return []

    if pruned_count > 0:
        logger.info(f"Автоматически отсеяно несовместимых для ядра узлов: {pruned_count}")

    logger.info(f"Этап 2/2: Запуск глубокого URL-теста (VLESS Reality/TLS + YouTube 204) для {len(node_tag_map)} узлов...")
    logger.info(f"Целевой URL: {URL_TEST_ENDPOINT}, тайм-аут: {URL_TEST_TIMEOUT}с, потоков: {URL_TEST_CONCURRENCY}")

    # Запуск фонового процесса Sing-Box
    proc = subprocess.Popen(
        [str(singbox_bin), "run", "-c", str(config_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=_NO_WINDOW
    )

    # Проверка, что процесс успешно поднялся
    time.sleep(1.2)
    if proc.poll() is not None:
        err = proc.stderr.read().decode("utf-8", errors="ignore")
        logger.error(f"Sing-Box завершился аварийно: {err}")
        return []

    alive_nodes: List[Tuple[ProxyNode, float]] = []
    timeout_ms = int(URL_TEST_TIMEOUT * 1000)

    def test_single_tag(tag: str) -> Optional[Tuple[ProxyNode, float]]:
        node = node_tag_map[tag]

        # Строгий тест через YouTube 204 (отсеивает внутренние/заблокированные выходы)
        ep = urllib.parse.quote(URL_TEST_ENDPOINT, safe="")
        url = f"http://127.0.0.1:{api_port}/proxies/{tag}/delay?timeout={timeout_ms}&url={ep}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=URL_TEST_TIMEOUT + 0.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                delay = data.get("delay", 0)
                if delay > 0:
                    return (node, float(delay))
        except Exception:
            pass

        return None

    try:
        tested_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=URL_TEST_CONCURRENCY) as executor:
            futures = [executor.submit(test_single_tag, tag) for tag in node_tag_map]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                tested_count += 1
                if res:
                    node, delay = res
                    alive_nodes.append((node, delay))
                    if len(alive_nodes) % 10 == 0 or len(alive_nodes) <= 5:
                        logger.info(f" [URL OK] {delay:.0f}ms | {node.sni or node.host} ({node.host})")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            config_file.unlink(missing_ok=True)
        except Exception:
            pass

    # Сортировка по реальной задержке (самые быстрые сверху)
    alive_nodes.sort(key=lambda x: x[1])

    logger.info(f"Глубокий URL-тест завершен! ИЗ {len(node_tag_map)} узлов РЕАЛЬНО РАБОТАЮТ: {len(alive_nodes)} серверов!")
    return alive_nodes


def is_valid_reality_key(pbk_raw: str) -> bool:
    """Валидация base64 Reality x25519 ключа (должен строго декодироваться в 32 байта)."""
    if not pbk_raw or len(pbk_raw) < 42 or len(pbk_raw) > 45:
        return False
    padded = pbk_raw + "=" * ((4 - len(pbk_raw) % 4) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw_bytes = decoder(padded.encode("ascii"))
            if len(raw_bytes) == 32:
                return True
        except Exception:
            continue
    return False


def _build_xray_outbound(n: ProxyNode, tag_out: str) -> Optional[dict]:
    """Формирует VLESS outbound для Xray-core (>= 25.x) с поддержкой tcp/raw, xhttp, grpc и ws."""
    if n.protocol != "vless":
        return None
    net = n.params.get("type", "tcp").lower().strip()
    if net in ("raw", ""):
        net = "tcp"
    elif net == "splithttp":
        net = "xhttp"
    if net not in ("tcp", "xhttp", "grpc", "ws"):
        return None

    sec = n.params.get("security", "none").lower().strip()
    if sec not in ("reality", "tls"):
        return None
    if sec == "reality":
        pbk = n.params.get("pbk", "").strip().replace(" ", "+")
        if not is_valid_reality_key(pbk):
            return None
        n.params["pbk"] = pbk

    enc = (n.params.get("encryption", "none") or "none").strip()
    user = {"id": n.uuid, "encryption": enc}
    flow = n.params.get("flow", "").strip()
    if flow and net == "tcp":
        user["flow"] = flow

    stream = {"network": net, "security": sec or "none"}
    if net == "xhttp":
        xs = {
            "path": n.params.get("path", "/") or "/",
            "host": n.params.get("host", "") or n.sni or "",
            "mode": n.params.get("mode", "auto") or "auto"
        }
        if n.params.get("extra"):
            try:
                xs["extra"] = json.loads(n.params["extra"])
            except Exception:
                pass
        stream["xhttpSettings"] = xs
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": n.params.get("serviceName", "") or n.params.get("path", ""),
            "multiMode": n.params.get("mode", "") == "multi"
        }
    elif net == "ws":
        ws = {"path": n.params.get("path", "/") or "/"}
        ws_host = n.params.get("host", "")
        if ws_host:
            ws["headers"] = {"Host": ws_host}
        stream["wsSettings"] = ws

    if sec == "reality":
        stream["realitySettings"] = {
            "serverName": n.sni or "ok.ru",
            "fingerprint": n.params.get("fp", "chrome") or "chrome",
            "publicKey": n.params["pbk"],
            "shortId": n.params.get("sid", "")
        }
    elif sec == "tls":
        ts = {
            "serverName": n.sni or n.params.get("host", "") or n.host,
            "fingerprint": n.params.get("fp", "chrome") or "chrome"
        }
        if n.params.get("alpn"):
            ts["alpn"] = [x.strip() for x in n.params["alpn"].split(",") if x.strip()]
        stream["tlsSettings"] = ts

    return {
        "tag": tag_out,
        "protocol": "vless",
        "settings": {"vnext": [{"address": n.host, "port": int(n.port), "users": [user]}]},
        "streamSettings": stream
    }


def _run_xray_chunk(
    xray_bin: Path,
    chunk: List[Tuple[ProxyNode, dict]],
    test_url: str = URL_TEST_ENDPOINT,
    req_timeout: Optional[float] = None,
    checks: int = 1,
) -> List[Tuple[ProxyNode, float]]:
    """Запуск одного чанка узлов в Xray-core с автоделением при сбойном конфиге."""
    if not chunk:
        return []
    base_port = get_free_port() + 50
    inbounds = []
    outbounds = []
    rules = []
    test_map = []

    for i, (n, ob) in enumerate(chunk):
        port = base_port + i
        tag_in = f"in_{i}"
        ob_copy = dict(ob)
        ob_copy["tag"] = f"out_{i}"
        inbounds.append({"port": port, "listen": "127.0.0.1", "protocol": "http", "tag": tag_in})
        outbounds.append(ob_copy)
        rules.append({"type": "field", "inboundTag": [tag_in], "outboundTag": ob_copy["tag"]})
        test_map.append((n, port))

    temp_cfg = Path(tempfile.gettempdir()) / f"xray_wl_{base_port}.json"
    cfg = {"log": {"loglevel": "error"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}}
    with open(temp_cfg, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    proc = subprocess.Popen([str(xray_bin), "run", "-c", str(temp_cfg)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=_NO_WINDOW)
    time.sleep(1.3)
    if proc.poll() is not None:
        err = proc.stdout.read().decode("utf-8", errors="ignore")
        temp_cfg.unlink(missing_ok=True)
        if len(chunk) > 1:
            mid = len(chunk) // 2
            return (
                _run_xray_chunk(xray_bin, chunk[:mid], test_url=test_url, req_timeout=req_timeout, checks=checks)
                + _run_xray_chunk(xray_bin, chunk[mid:], test_url=test_url, req_timeout=req_timeout, checks=checks)
            )
        logger.warning(f"Xray пропустил сбойный узел {chunk[0][0].host}:{chunk[0][0].port} ({err.strip()[-160:]})")
        return []

    eff_timeout = req_timeout if req_timeout is not None else max(URL_TEST_TIMEOUT + 0.5, 6.5)

    def check_node(item):
        node, port = item
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}))
        delays = []
        for _ in range(checks):
            t0 = time.time()
            try:
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                with opener.open(req, timeout=eff_timeout) as resp:
                    if resp.status in (200, 204):
                        delays.append((time.time() - t0) * 1000.0)
                    else:
                        return None
            except Exception:
                return None
        return (node, sum(delays) / len(delays)) if len(delays) == checks else None

    alive: List[Tuple[ProxyNode, float]] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(test_map), 25)) as executor:
            for res in executor.map(check_node, test_map):
                if res:
                    node, delay = res
                    alive.append((node, delay))
                    if checks == 1:
                        logger.info(f" [Xray OK] {delay:.0f}ms | {node.params.get('type','tcp')} | {node.sni or node.host} ({node.host})")
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
    return alive


def _resolve_xray_bin() -> Optional[Path]:
    import shutil
    xray_bin = Path(XRAY_PATH)
    if xray_bin.exists():
        return xray_bin
    which_xr = shutil.which("xray")
    return Path(which_xr) if which_xr else None


def run_xray_urltest(
    nodes: List[ProxyNode],
    max_nodes: int = 220,
    test_url: str = URL_TEST_ENDPOINT,
    req_timeout: Optional[float] = None,
    checks: int = 1,
) -> List[Tuple[ProxyNode, float]]:
    """
    Тестирование узлов (xHTTP, TCP/RAW, gRPC, WS) через нативное ядро Xray-core (>= 25.x).
    """
    xray_bin = _resolve_xray_bin()
    if not xray_bin:
        logger.warning(f"Бинарник Xray не найден по пути {XRAY_PATH}. Пропускаем Xray тест.")
        return []
    if not nodes:
        return []

    prepared: List[Tuple[ProxyNode, dict]] = []
    for n in nodes:
        ob = _build_xray_outbound(n, f"out_{len(prepared)}")
        if ob:
            prepared.append((n, ob))
            if len(prepared) >= max_nodes:
                break

    if not prepared:
        return []

    alive: List[Tuple[ProxyNode, float]] = []
    for start in range(0, len(prepared), 35):
        alive.extend(_run_xray_chunk(xray_bin, prepared[start:start + 35], test_url=test_url, req_timeout=req_timeout, checks=checks))

    alive.sort(key=lambda x: x[1])
    if checks == 1:
        logger.info(f"Xray URL-тест завершен: проверено {len(prepared)} узлов, РАБОТАЮТ: {len(alive)} серверов!")
    else:
        logger.info(f"Контрольный тест ЧС (2/2 gstatic <= {req_timeout or 2.8}с): {len(alive)} стабильных из {len(prepared)} кандидатов")
    return alive


def verify_ru_reachability_checkhost(alive_pairs: List[Tuple[ProxyNode, float]], max_checks: int = 45) -> List[Tuple[ProxyNode, float]]:
    """
    Кросс-проверка доступности выживших узлов из РФ (для запуска на GitHub Actions вне России).
    Отбрасывает узлы только если оба московских сенсора (ru1, ru3) подтвердили TCP timeout.
    При сбоях API или лимитах срабатывает fail-open (узел сохраняется).
    """
    if not alive_pairs:
        return alive_pairs

    unique_eps = []
    seen_hp = set()
    for node, _ in sorted(alive_pairs, key=lambda x: x[1]):
        hp = (node.host.strip(), int(node.port))
        if hp not in seen_hp:
            seen_hp.add(hp)
            unique_eps.append(hp)
        if len(unique_eps) >= max_checks:
            break

    logger.info(f"Кросс-проверка доступности из РФ (check-host.net) для {len(unique_eps)} уникальных адресов...")
    rids = []
    for h, p in unique_eps:
        target = urllib.parse.quote(f"{h}:{p}", safe=":")
        api_url = f"https://check-host.net/check-tcp?host={target}&node=ru1.node.check-host.net&node=ru3.node.check-host.net"
        try:
            req = urllib.request.Request(api_url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read().decode("utf-8"))
                rid = data.get("request_id")
                if rid:
                    rids.append(((h, p), rid))
        except Exception:
            pass
        time.sleep(0.35)

    if not rids:
        return alive_pairs

    time.sleep(2.5)
    blocked_eps = set()
    for hp, rid in rids:
        try:
            req = urllib.request.Request(f"https://check-host.net/check-result/{rid}", headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                res = json.loads(r.read().decode("utf-8"))
            ok_cnt = 0
            fail_cnt = 0
            for probe_res in res.values():
                if isinstance(probe_res, list) and probe_res and isinstance(probe_res[0], dict):
                    if "address" in probe_res[0]:
                        ok_cnt += 1
                    elif "error" in probe_res[0]:
                        fail_cnt += 1
            if ok_cnt == 0 and fail_cnt >= 2:
                blocked_eps.add(hp)
                logger.info(f" [RU BLOCKED] {hp[0]}:{hp[1]} недоступен с сенсоров в РФ (ru1+ru3 timeout)")
        except Exception:
            pass

    if not blocked_eps:
        return alive_pairs

    filtered = [(n, d) for n, d in alive_pairs if (n.host.strip(), int(n.port)) not in blocked_eps]
    logger.info(f"После кросс-проверки из РФ осталось: {len(filtered)} из {len(alive_pairs)} серверов")
    return filtered


async def check_nodes_pool(nodes: List[ProxyNode]) -> Tuple[List[Tuple[ProxyNode, float]], List[ProxyNode]]:
    """Главная функция проверки пула узлов (TCP фильтр -> Xray / Sing-Box URL тест)."""
    if not nodes:
        return [], []

    # 1. Экспресс-отсев по TCP
    tcp_alive_nodes = await filter_tcp_alive(nodes)
    if not tcp_alive_nodes:
        logger.warning("Ни один узел не ответил на TCP-пинг!")
        return [], []

    from filter import is_valid_blacklist_node, get_bl_rank, get_wl_rank, is_cloudflare_ip

    # 2. Формируем пул кандидатов Black-List + White-List (не-xHTTP) для глубокого URL-теста через Sing-Box
    bl_candidates = [n for n in tcp_alive_nodes if is_valid_blacklist_node(n)]
    bl_candidates.sort(key=lambda x: (get_bl_rank(x), x.tcp_ping or 999.0))
    from config import MAX_BL_TEST_NODES
    bl_test_nodes = bl_candidates[:MAX_BL_TEST_NODES]

    wl_sb_candidates = [
        n for n in tcp_alive_nodes
        if get_wl_rank(n) < 10 and n.params.get("type", "tcp").lower() not in ("xhttp", "splithttp")
    ]
    wl_sb_candidates.sort(key=lambda x: (get_wl_rank(x), x.tcp_ping or 999.0))

    # Объединяем без дубликатов для единого прогона Sing-Box (xHTTP отправляем напрямую в Xray)
    bl_sb_nodes = [n for n in bl_test_nodes if n.params.get("type", "tcp").lower() not in ("xhttp", "splithttp")]
    sb_combined = []
    seen_sb = set()
    for n in bl_sb_nodes + wl_sb_candidates[:400]:
        if n.unique_key not in seen_sb:
            seen_sb.add(n.unique_key)
            sb_combined.append(n)

    # 3. White-List кандидаты для Xray-core (>= 25.x): все xHTTP + топовые non-xHTTP (которые мог отсеять Sing-Box)
    xhttp_candidates = [
        n for n in tcp_alive_nodes
        if n.params.get("type", "").lower() in ("xhttp", "splithttp") and get_wl_rank(n) < 10
    ]
    xhttp_candidates.sort(key=lambda x: (get_wl_rank(x), x.tcp_ping or 999.0))
    xhttp_nodes = xhttp_candidates[:90]

    logger.info(f"На глубокий URL-тест отправлено: Sing-Box (BL+WL): {len(sb_combined)} шт, Xray (WL + BL-добор): до {len(xhttp_nodes) + 250} шт")

    results: List[Tuple[ProxyNode, float]] = []
    seen_res = set()

    # Запуск параллельного тестирования Sing-Box
    if sb_combined:
        sb_alive = await asyncio.to_thread(run_singbox_urltest, sb_combined)
        for n, d in sb_alive:
            if n.unique_key not in seen_res:
                seen_res.add(n.unique_key)
                results.append((n, d))

    # Запуск Xray для всех xHTTP, не прошедших Sing-Box White-List кандидатов и добора Black-List
    # Ограничиваем дубли одного resolved IP в Xray-доборе, включая запасные Cloudflare (<= 1 на IP)
    wl_extra_for_xray = [n for n in wl_sb_candidates if n.unique_key not in seen_res][:200]
    bl_pool = [n for n in bl_test_nodes if n.unique_key not in seen_res]
    bl_pool.sort(key=lambda x: (get_bl_rank(x), x.tcp_ping or 999.0))
    bl_direct_for_xray = []
    bl_xr_overflow = []
    bl_cf_added = 0
    bl_ip_cnt = {}
    for n in bl_pool:
        rip = resolve_to_ip(n.host).lower()
        is_cf = is_cloudflare_ip(rip)
        cap = 1 if is_cf else 2
        if is_cf and bl_cf_added >= 35:
            continue
        c = bl_ip_cnt.get(rip, 0)
        if c < cap:
            bl_direct_for_xray.append(n)
            bl_ip_cnt[rip] = c + 1
            if is_cf:
                bl_cf_added += 1
            if len(bl_direct_for_xray) >= 270:
                break
        else:
            bl_xr_overflow.append(n)
    if len(bl_direct_for_xray) < 270:
        bl_direct_for_xray.extend(bl_xr_overflow[:(270 - len(bl_direct_for_xray))])

    xray_queue = []
    seen_xr = set()
    for n in xhttp_nodes + bl_direct_for_xray + wl_extra_for_xray:
        if n.unique_key not in seen_xr:
            seen_xr.add(n.unique_key)
            xray_queue.append(n)
    if xray_queue:
        xray_alive = await asyncio.to_thread(run_xray_urltest, xray_queue, 600)
        for n, d in xray_alive:
            if n.unique_key not in seen_res:
                seen_res.add(n.unique_key)
                results.append((n, d))

    # Контрольный двойной тест ЧС через Xray по gstatic.com/generate_204 (2/2 <= 2.8с), как проверяют INCY/Happ на телефоне
    bl_survivors = [n for n, _ in results if is_valid_blacklist_node(n)]
    if bl_survivors and _resolve_xray_bin():
        stable_bl = await asyncio.to_thread(
            run_xray_urltest,
            bl_survivors,
            len(bl_survivors),
            "https://www.gstatic.com/generate_204",
            2.8,
            2,
        )
        stable_map = {n.unique_key: d for n, d in stable_bl}
        if stable_map:
            updated_results = []
            for n, d in results:
                if n.unique_key in stable_map:
                    n.bl_verified = True
                    updated_results.append((n, stable_map[n.unique_key]))
                else:
                    updated_results.append((n, d))
            results = updated_results

    if os.name != "nt" and results:
        results = await asyncio.to_thread(verify_ru_reachability_checkhost, results)

    return results, tcp_alive_nodes
