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
import concurrent.futures
from pathlib import Path
from typing import List, Tuple, Optional

from parser import ProxyNode
from filter import is_ru_white_sni, get_wl_rank
from config import (
    CHECKER_CONCURRENCY,
    TCP_CHECK_TIMEOUT,
    SINGBOX_PATH,
    URL_TEST_ENDPOINT,
    URL_TEST_TIMEOUT,
    URL_TEST_CONCURRENCY
)

XRAY_PATH = str(Path(__file__).parent.parent / "tools" / "xray.exe")
if not os.path.exists(XRAY_PATH):
    XRAY_PATH = r"C:\Users\1\Desktop\v2rayN-windows-64\bin\xray\xray.exe"

logger = logging.getLogger("harvester.checker")


def get_free_port() -> int:
    """Поиск свободного локального порта для Sing-Box API."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


async def check_tcp_single(sem: asyncio.Semaphore, node: ProxyNode) -> Tuple[ProxyNode, bool, float]:
    """Быстрая сокет-проверка доступности порта (Stage 1)."""
    async with sem:
        start_time = time.monotonic()
        try:
            connect_task = asyncio.open_connection(node.host, node.port)
            reader, writer = await asyncio.wait_for(connect_task, timeout=TCP_CHECK_TIMEOUT)
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

    logger.info(f"Этап 1/2: Экспресс TCP-фильтр {len(nodes)} узлов (пул {CHECKER_CONCURRENCY} потоков, тайм-аут {TCP_CHECK_TIMEOUT}с)...")
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
            return [(node, 50.0) for node in nodes]

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

        chk = subprocess.run([str(singbox_bin), "check", "-c", str(config_file)], capture_output=True, text=True)
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

    logger.info(f"Этап 2/2: Запуск глубокого URL-теста (VLESS Reality + HTTPS 204) для {len(node_tag_map)} узлов...")
    logger.info(f"Целевой URL: {URL_TEST_ENDPOINT}, тайм-аут: {URL_TEST_TIMEOUT}с, потоков: {URL_TEST_CONCURRENCY}")

    # Запуск фонового процесса Sing-Box
    proc = subprocess.Popen(
        [str(singbox_bin), "run", "-c", str(config_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
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
        is_wl = node.is_whitelist_source or is_ru_white_sni(node.sni)
        
        # Тест на реальный интернет (Google 204 или Cloudflare 204)
        for ep in (URL_TEST_ENDPOINT, "https://cp.cloudflare.com/generate_204"):
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


def run_xray_urltest(nodes: List[ProxyNode]) -> List[Tuple[ProxyNode, float]]:
    """
    Тестирование xHTTP (SplitHTTP) Reality узлов через нативное ядро Xray-core.
    Именно этот транспорт обходит ТСПУ белые списки на мобильных сетях в РФ.
    """
    xray_bin = Path(XRAY_PATH)
    if not xray_bin.exists() or not nodes:
        return []

    # Отбираем узлы с валидными Reality ключами
    valid_nodes = []
    for n in nodes:
        pbk = n.params.get("pbk", "").strip().replace(" ", "+")
        if is_valid_reality_key(pbk):
            n.params["pbk"] = pbk
            valid_nodes.append(n)

    # Ограничиваем пул топ-кандидатами для стабильности портов
    valid_nodes = valid_nodes[:25]
    if not valid_nodes:
        return []

    base_port = 19200
    inbounds = []
    outbounds = []
    rules = []
    test_map = []

    for i, n in enumerate(valid_nodes):
        port = base_port + i
        tag_in = f"in_{i}"
        tag_out = f"out_{i}"
        pbk = n.params["pbk"]

        inbounds.append({
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "http",
            "tag": tag_in
        })
        outbounds.append({
            "tag": tag_out,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": n.host,
                    "port": int(n.port),
                    "users": [{"id": n.uuid, "encryption": "none"}]
                }]
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "serverName": n.sni or "ok.ru",
                    "fingerprint": n.params.get("fp", "chrome") or "chrome",
                    "publicKey": pbk,
                    "shortId": n.params.get("sid", "")
                },
                "xhttpSettings": {
                    "path": n.params.get("path", "/api/v1/e0163615") or "/api/v1/e0163615",
                    "host": n.params.get("host", "vk.com") or "vk.com",
                    "mode": n.params.get("mode", "stream-one") or "stream-one"
                }
            }
        })
        rules.append({"type": "field", "inboundTag": [tag_in], "outboundTag": tag_out})
        test_map.append((n, port))

    temp_cfg = Path(tempfile.gettempdir()) / f"xray_xhttp_{base_port}.json"
    cfg = {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules}
    }
    with open(temp_cfg, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    proc = subprocess.Popen([str(xray_bin), "run", "-c", str(temp_cfg)])
    time.sleep(1.5)

    def check_node(item):
        node, port = item
        proxy_handler = urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'})
        opener = urllib.request.build_opener(proxy_handler)
        t0 = time.time()
        try:
            req = urllib.request.Request(URL_TEST_ENDPOINT, headers={'User-Agent': 'Mozilla/5.0'})
            with opener.open(req, timeout=URL_TEST_TIMEOUT) as resp:
                elapsed = (time.time() - t0) * 1000.0
                if resp.status in (200, 204):
                    return (node, elapsed)
        except Exception:
            pass
        return None

    alive: List[Tuple[ProxyNode, float]] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(test_map), 25)) as executor:
            futures = [executor.submit(check_node, item) for item in test_map]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    node, delay = res
                    alive.append((node, delay))
                    logger.info(f" [Xray xHTTP OK] {delay:.0f}ms | {node.sni or node.host} ({node.host})")
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

    alive.sort(key=lambda x: x[1])
    logger.info(f"Xray xHTTP тест завершен: проверено {len(test_map)} узлов, РАБОТАЮТ: {len(alive)} серверов!")
    return alive


async def check_nodes_pool(nodes: List[ProxyNode]) -> Tuple[List[Tuple[ProxyNode, float]], List[ProxyNode]]:
    """Главная функция проверки пула узлов (TCP фильтр -> Xray / Sing-Box URL тест)."""
    if not nodes:
        return [], []

    # 1. Экспресс-отсев по TCP
    tcp_alive_nodes = await filter_tcp_alive(nodes)
    if not tcp_alive_nodes:
        logger.warning("Ни один узел не ответил на TCP-пинг!")
        return [], []

    from filter import is_valid_blacklist_node, get_bl_rank, get_wl_rank

    # 2. Формируем пул кандидатов Black-List для глубокого URL-теста через Sing-Box
    bl_candidates = [n for n in tcp_alive_nodes if is_valid_blacklist_node(n)]
    bl_candidates.sort(key=lambda x: (get_bl_rank(x), x.tcp_ping or 999.0))
    from config import MAX_BL_TEST_NODES
    bl_test_nodes = bl_candidates[:MAX_BL_TEST_NODES]

    # 3. White-List кандидаты (xHTTP / Selectel)
    xhttp_nodes = [n for n in tcp_alive_nodes if n.params.get("type", "").lower() in ("xhttp", "splithttp") and get_wl_rank(n) < 10][:35]

    logger.info(f"На глубокий URL-тест отправлено: Black-List (Sing-Box Reality): {len(bl_test_nodes)} шт, xHTTP: {len(xhttp_nodes)} шт")

    results: List[Tuple[ProxyNode, float]] = []

    # Запуск параллельного тестирования Sing-Box для Black-List
    if bl_test_nodes:
        bl_alive = await asyncio.to_thread(run_singbox_urltest, bl_test_nodes)
        results.extend(bl_alive)

    # Запуск Xray для xHTTP
    if xhttp_nodes:
        xray_alive = await asyncio.to_thread(run_xray_urltest, xhttp_nodes)
        results.extend(xray_alive)

    return results, tcp_alive_nodes
