# -*- coding: utf-8 -*-
"""
Асинхронный загрузчик подписок из источников (aiohttp).
"""

import json
import base64
import logging
import asyncio
import aiohttp
import urllib.parse
import yaml
from typing import List, Dict, Any
from pathlib import Path

from config import SOURCES_FILE, FETCHER_TIMEOUT
from parser import parse_proxy_uri, parse_vless_uri, parse_vmess_uri, decode_base64_content, ProxyNode

logger = logging.getLogger("harvester.fetcher")


def parse_json_nodes(content: str, is_wl: bool) -> List[ProxyNode]:
    nodes = []
    try:
        data = json.loads(content)
        outbounds = data.get("outbounds", [])
        for ob in outbounds:
            proto = ob.get("protocol") or ob.get("type")
            if proto == "vless":
                vnext_list = ob.get("settings", {}).get("vnext", [])
                if vnext_list:
                    vnext = vnext_list[0]
                    addr = vnext.get("address")
                    port = vnext.get("port")
                    users = vnext.get("users", [])
                    uid = users[0].get("id") if users else ""
                    flow = users[0].get("flow", "") if users else ""
                    stream = ob.get("streamSettings", {})
                    sec = stream.get("security", "")
                    real = stream.get("realitySettings", {})
                    sni = real.get("serverName", "")
                    pbk = real.get("publicKey", "")
                    sid = real.get("shortId", "")
                    net = stream.get("network", "tcp")
                    tag = ob.get("tag", "node")
                    xhttp = stream.get("xhttpSettings", {})
                    path = xhttp.get("path", "")
                    h_host = xhttp.get("host", "")
                    mode = xhttp.get("mode", "")
                    grpc = stream.get("grpcSettings", {})
                    if grpc and not path:
                        path = grpc.get("serviceName", "")
                    ws = stream.get("wsSettings", {})
                    if ws:
                        if not path:
                            path = ws.get("path", "")
                        if not h_host:
                            h_host = ws.get("headers", {}).get("Host", "")

                    params = {
                        "security": sec,
                        "encryption": "none",
                        "sni": sni,
                        "fp": real.get("fingerprint", "chrome") or "chrome",
                        "pbk": pbk,
                        "sid": sid,
                        "type": net,
                    }
                    if flow:
                        params["flow"] = flow
                    if path:
                        params["path"] = path
                    if h_host:
                        params["host"] = h_host
                    if mode:
                        params["mode"] = mode
                    q = urllib.parse.urlencode(params)
                    uri = f"vless://{uid}@{addr}:{port}?{q}#{tag}"
                    node = parse_proxy_uri(uri, is_whitelist_source=is_wl)
                    if node:
                        nodes.append(node)
                elif ob.get("server") and ob.get("uuid"):
                    server = ob.get("server")
                    port = ob.get("server_port")
                    uid = ob.get("uuid")
                    flow = ob.get("flow", "")
                    tls = ob.get("tls", {})
                    sec = "reality" if tls.get("reality", {}).get("enabled") else ("tls" if tls.get("enabled") else "none")
                    real = tls.get("reality", {})
                    sni = tls.get("server_name", "")
                    pbk = real.get("public_key", "")
                    sid = real.get("short_id", "")
                    tag = ob.get("tag", "node")
                    tr = ob.get("transport", {})
                    net = tr.get("type", "tcp")
                    path = tr.get("path", "") or tr.get("service_name", "")
                    hosts = tr.get("host", [])
                    h_host = hosts[0] if hosts else ""
                    
                    params = {
                        "security": sec,
                        "encryption": "none",
                        "sni": sni,
                        "fp": "chrome",
                        "pbk": pbk,
                        "sid": sid,
                        "type": net,
                    }
                    if flow:
                        params["flow"] = flow
                    if path:
                        params["path"] = path
                    if h_host:
                        params["host"] = h_host
                    q = urllib.parse.urlencode(params)
                    uri = f"vless://{uid}@{server}:{port}?{q}#{tag}"
                    node = parse_proxy_uri(uri, is_whitelist_source=is_wl)
                    if node:
                        nodes.append(node)
            elif proto == "vmess":
                vnext_list = ob.get("settings", {}).get("vnext", [])
                if vnext_list:
                    vnext = vnext_list[0]
                    addr = vnext.get("address")
                    port = vnext.get("port")
                    users = vnext.get("users", [])
                    uid = users[0].get("id") if users else ""
                    aid = users[0].get("alterId", 0) if users else 0
                    stream = ob.get("streamSettings", {})
                    sec = stream.get("security", "")
                    tls = stream.get("tlsSettings", {})
                    sni = tls.get("serverName", "")
                    net = stream.get("network", "ws")
                    tag = ob.get("tag", "vmess_node")
                    ws = stream.get("wsSettings", {})
                    path = ws.get("path", "") if ws else ""
                    h_host = ws.get("headers", {}).get("Host", "") if ws else ""
                    
                    vm_data = {
                        "v": "2",
                        "ps": tag,
                        "add": addr,
                        "port": str(port),
                        "id": uid,
                        "aid": str(aid),
                        "net": net,
                        "type": "none",
                        "host": h_host,
                        "path": path,
                        "tls": sec,
                        "sni": sni,
                        "scy": "auto"
                    }
                    b64 = base64.b64encode(json.dumps(vm_data).encode("utf-8")).decode("utf-8")
                    node = parse_proxy_uri(f"vmess://{b64}", is_whitelist_source=is_wl)
                    if node:
                        nodes.append(node)
    except Exception:
        pass
    return nodes


def parse_yaml_nodes(content: str, is_wl: bool) -> List[ProxyNode]:
    nodes = []
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            for p in data.get("proxies", []):
                p_type = p.get("type", "").lower()
                if p_type == "vless":
                    server = p.get("server")
                    port = p.get("port")
                    uid = p.get("uuid")
                    flow = p.get("flow", "")
                    sec = "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none")
                    real = p.get("reality-opts", {})
                    sni = p.get("servername") or server
                    pbk = real.get("public-key", "")
                    sid = str(real.get("short-id", ""))
                    net = p.get("network", "tcp")
                    tag = p.get("name", "clash_node")
                    uri = f"vless://{uid}@{server}:{port}?security={sec}&encryption=none&flow={flow}&sni={sni}&fp=chrome&pbk={pbk}&sid={sid}&type={net}#{tag}"
                    node = parse_proxy_uri(uri, is_whitelist_source=is_wl)
                    if node:
                        nodes.append(node)
                elif p_type == "vmess":
                    server = p.get("server")
                    port = p.get("port")
                    uid = p.get("uuid")
                    aid = p.get("alterId", 0)
                    sec = "tls" if p.get("tls") else ""
                    sni = p.get("servername") or server
                    net = p.get("network", "ws")
                    ws_opts = p.get("ws-opts", {}) or {}
                    path = ws_opts.get("path", "")
                    headers = ws_opts.get("headers", {}) or {}
                    h_host = headers.get("Host", "") or headers.get("host", "")
                    tag = p.get("name", "clash_vmess")
                    vm_data = {
                        "v": "2",
                        "ps": tag,
                        "add": server,
                        "port": str(port),
                        "id": uid,
                        "aid": str(aid),
                        "net": net,
                        "type": "none",
                        "host": h_host,
                        "path": path,
                        "tls": sec,
                        "sni": sni,
                        "scy": p.get("cipher", "auto")
                    }
                    b64 = base64.b64encode(json.dumps(vm_data).encode("utf-8")).decode("utf-8")
                    node = parse_proxy_uri(f"vmess://{b64}", is_whitelist_source=is_wl)
                    if node:
                        nodes.append(node)
    except Exception:
        pass
    return nodes


async def fetch_source(session: aiohttp.ClientSession, source: Dict[str, Any]) -> List[ProxyNode]:
    """Загрузка и парсинг одного источника."""
    name = source.get("name", "Unknown")
    url = source.get("url", "")
    if not url:
        return []

    nodes: List[ProxyNode] = []
    headers = {
        "User-Agent": "v2rayNG/1.8.12 (Android; ru-RU)",
        "Accept": "*/*"
    }

    try:
        timeout = aiohttp.ClientTimeout(total=FETCHER_TIMEOUT)
        async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
            if resp.status != 200:
                logger.warning(f"[{name}] Ошибка загрузки: HTTP {resp.status}")
                return []

            content = await resp.text(encoding="utf-8", errors="ignore")
            
            source_type = source.get("type", "multi_protocol")
            is_wl = source_type in ("whitelist_focused", "ru_mirror")
            is_bl = source_type == "blacklist_focused"

            # 1. Проверка JSON формата (Happ / Sing-Box / Xray)
            if content.strip().startswith("{"):
                json_nodes = parse_json_nodes(content, is_wl)
                if json_nodes:
                    nodes.extend(json_nodes)

            # 2. Проверка YAML формата (Clash / Mihomo)
            elif "proxies:" in content:
                yaml_nodes = parse_yaml_nodes(content, is_wl)
                if yaml_nodes:
                    nodes.extend(yaml_nodes)

            # 3. Стандартный построчный vless:// и vmess:// (или Base64)
            if not nodes:
                if "vless://" not in content and "vmess://" not in content and len(content.strip()) > 50:
                    decoded = decode_base64_content(content)
                    if "vless://" in decoded or "vmess://" in decoded:
                        content = decoded

                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for prefix in ("vless://", "vmess://"):
                        if prefix in line:
                            start_idx = line.find(prefix)
                            uri_part = line[start_idx:].split(" ")[0]
                            node = parse_proxy_uri(uri_part, is_whitelist_source=is_wl, is_blacklist_source=is_bl)
                            if node:
                                nodes.append(node)

            logger.info(f"[{name}] Загружено узлов: {len(nodes)}")
    except Exception as e:
        logger.error(f"[{name}] Исключение при загрузке: {e}")

    return nodes


async def fetch_all_sources() -> List[ProxyNode]:
    """Параллельная загрузка всех активных источников."""
    if not Path(SOURCES_FILE).exists():
        logger.error(f"Файл источников {SOURCES_FILE} не найден!")
        return []

    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources: List[Dict[str, Any]] = json.load(f)

    active_sources = [s for s in sources if s.get("enabled", True)]
    logger.info(f"Начало сбора из {len(active_sources)} активных источников...")

    all_nodes: List[ProxyNode] = []
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_source(session, s) for s in active_sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                all_nodes.extend(res)

    logger.info(f"Всего собрано узлов до дедупликации: {len(all_nodes)}")
    return all_nodes
