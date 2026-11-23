# -*- coding: utf-8 -*-
"""
Экспортер готовых подписок в файлы и доставка на подключенное устройство через ADB.
"""

import base64
import logging
import subprocess
from pathlib import Path
from typing import List
from config import OUTPUT_DIR, ADB_PATH, DEVICE_TARGET_DIR, BASE_DIR

logger = logging.getLogger("harvester.exporter")

import json
from parser import parse_proxy_uri

def generate_happ_json(nodes_list: List[str], max_nodes: int = 50, is_whitelist: bool = True) -> Path:
    """
    Генерация проверенного, 100% валидного профиля Happ VPN (Xray-core) в формате JSON,
    соответствующего официальной спецификации Happ (rawSettings, xhttpSettings, grpcSettings, VMess).
    """
    outbounds = []
    first_tag = "node-001"
    valid_count = 0

    for i, uri in enumerate(nodes_list):
        node = parse_proxy_uri(uri)
        if not node or not node.uuid or not node.host or not node.port:
            continue

        raw_net = node.params.get("type", "tcp").strip().lower().replace("<br/>", "").replace("<br>", "")

        # --- 1. VMess Outbound ---
        if node.protocol == "vmess":
            valid_count += 1
            tag = node.name if node.name else f"🇩🇪 Germany VMess #{valid_count:02d}"
            if valid_count == 1:
                first_tag = tag

            stream_settings = {
                "network": raw_net if raw_net in ("ws", "grpc", "tcp") else "ws",
                "sockopt": {
                    "tcpKeepAliveIdle": 300,
                    "tcpKeepAliveInterval": 60
                }
            }
            if raw_net == "ws" or raw_net not in ("grpc", "tcp"):
                ws_cfg = {"path": node.params.get("path", "/") or "/"}
                ws_host = node.params.get("host", "") or node.sni
                if ws_host:
                    ws_cfg["headers"] = {"Host": ws_host}
                stream_settings["wsSettings"] = ws_cfg
            elif raw_net == "grpc":
                svc = node.params.get("serviceName", "") or node.params.get("path", "")
                stream_settings["grpcSettings"] = {"serviceName": svc}

            if node.security == "tls" or node.sni:
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {
                    "serverName": node.sni or node.params.get("host", "") or node.host
                }
                fp = node.params.get("fp", "chrome")
                if fp:
                    stream_settings["tlsSettings"]["fingerprint"] = fp
            else:
                stream_settings["security"] = "none"

            ob = {
                "tag": tag,
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": node.host,
                        "port": int(node.port),
                        "users": [{
                            "id": node.uuid,
                            "alterId": int(node.params.get("aid", "0") or "0"),
                            "security": node.params.get("scy", "auto") or "auto"
                        }]
                    }]
                },
                "streamSettings": stream_settings
            }
            outbounds.append(ob)
            if max_nodes > 0 and len(outbounds) >= max_nodes:
                break
            continue

        # --- 2. VLESS Outbound ---
        is_reality = (node.is_reality or node.params.get("security") == "reality" or node.security == "reality")
        pbk = node.params.get("pbk", "").strip()

        # Для Reality публичный ключ обязателен
        if is_reality and (not pbk or len(pbk) < 40):
            continue

        # В ядре Happ для Reality TCP-транспорт называется 'raw' с обязательным rawSettings
        if raw_net in ("tcp", "raw", ""):
            net_type = "raw"
        elif raw_net in ("xhttp", "splithttp"):
            net_type = "xhttp"
        elif raw_net == "grpc":
            net_type = "grpc"
        elif raw_net == "ws":
            net_type = "ws"
        else:
            net_type = "raw"

        valid_count += 1
        tag = node.name if node.name else f"node-{valid_count:03d}"
        if valid_count == 1:
            first_tag = tag

        stream_settings = {
            "network": net_type,
            "sockopt": {
                "tcpKeepAliveIdle": 300,
                "tcpKeepAliveInterval": 60
            }
        }

        if net_type == "raw":
            stream_settings["rawSettings"] = {
                "header": {"type": "none"}
            }
        elif net_type == "xhttp":
            stream_settings["xhttpSettings"] = {
                "path": node.params.get("path", "/api/v1/e0163615") or "/api/v1/e0163615",
                "host": node.params.get("host", "vk.com") or "vk.com",
                "mode": node.params.get("mode", "stream-one") or "stream-one"
            }
        elif net_type == "grpc":
            svc = node.params.get("serviceName", "") or node.params.get("path", "")
            stream_settings["grpcSettings"] = {
                "serviceName": svc
            }
        elif net_type == "ws":
            ws_cfg = {"path": node.params.get("path", "/") or "/"}
            if node.params.get("host"):
                ws_cfg["headers"] = {"Host": node.params["host"]}
            stream_settings["wsSettings"] = ws_cfg

        if is_reality:
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = {
                "serverName": node.sni or "ok.ru",
                "fingerprint": node.params.get("fp", "chrome") or "chrome",
                "publicKey": pbk,
                "shortId": node.params.get("sid", "")
            }
        else:
            stream_settings["security"] = node.security or "none"

        user_obj = {
            "id": node.uuid,
            "encryption": "none"
        }
        flow = node.params.get("flow", "").strip()
        if net_type == "raw" and flow == "xtls-rprx-vision":
            user_obj["flow"] = "xtls-rprx-vision"

        ob = {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": node.host,
                    "port": int(node.port),
                    "users": [user_obj]
                }]
            },
            "streamSettings": stream_settings
        }
        outbounds.append(ob)

        if max_nodes > 0 and len(outbounds) >= max_nodes:
            break

    # Стандартные системные исходящие соединения
    system_outbounds = [
        {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
        {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
        {"tag": "dns-out", "protocol": "dns", "settings": {"network": "tcp,udp"}}
    ]

    # Загружаем мастер-шаблон конфигурации DNS и роутинга Happ
    template_path = BASE_DIR / "happ_template.json"
    if template_path.exists():
        with open(template_path, "r", encoding="utf-8") as f:
            happ_config = json.load(f)
    else:
        happ_config = {
            "log": {"loglevel": "warning"},
            "dns": {"servers": ["fakedns", "tcp+local://77.88.8.8:53"], "queryStrategy": "UseIPv4"},
            "fakedns": {"ipPool": "198.18.0.0/16", "poolSize": 65535},
            "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"}],
            "observatory": {},
            "routing": {}
        }

    cfg_name = f"🇷🇺 White-List TSPO Bypass ({len(outbounds)} nodes)" if is_whitelist else f"🌐 Global Black-List ({len(outbounds)} nodes)"
    target_filename = "happ_whitelist.json" if is_whitelist else "happ_blacklist.json"
    subject_selector = ["🇩🇪", "🇷🇺", "node-"] if is_whitelist else ["🌐", "node-"]

    happ_config["_meta"] = {
        "name": cfg_name,
        "generator": "VPN Harvester Pipeline",
        "notes": [
            f"{len(outbounds)} servers",
            "Interval is 5 minutes + leastPing + routing GLOBAL."
        ],
        "client": "Happ"
    }

    happ_config["outbounds"] = outbounds

    # Настраиваем балансировщик leastPing под созданные теги с флагами стран
    happ_config["observatory"] = {
        "subjectSelector": subject_selector,
        "probeURL": "https://www.gstatic.com/generate_204",
        "probeInterval": "5m",
        "enableConcurrency": True
    }

    happ_config["routing"]["balancers"] = [
        {
            "tag": "auto-leastPing",
            "selector": subject_selector,
            "fallbackTag": first_tag,
            "strategy": {"type": "leastPing"}
        }
    ]

    # Чистый стабильный DNS для гарантированной работы на мобильных сетях РФ
    happ_config["dns"] = {
        "servers": [
            "tcp+local://77.88.8.8:53",
            "tcp+local://77.88.8.88:53",
            "https://common.dot.dns.yandex.net/dns-query",
            "https://dns.google/dns-query"
        ],
        "queryStrategy": "UseIPv4",
        "disableCache": False
    }
    if "fakedns" in happ_config:
        del happ_config["fakedns"]

    # Удаляем fakedns из inbounds sniffing destOverride
    for ib in happ_config.get("inbounds", []):
        if "sniffing" in ib and "destOverride" in ib["sniffing"]:
            ib["sniffing"]["destOverride"] = [x for x in ib["sniffing"]["destOverride"] if x != "fakedns"]

    happ_file = OUTPUT_DIR / target_filename
    with open(happ_file, "w", encoding="utf-8") as f:
        json.dump(happ_config, f, ensure_ascii=False, indent=2)

    return happ_file


def save_subscriptions(whitelist: List[str], blacklist: List[str]) -> Path:
    """Сохранение списков в директорию output/."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    wl_file = OUTPUT_DIR / "whitelist.txt"
    bl_file = OUTPUT_DIR / "blacklist.txt"
    wl_b64_file = OUTPUT_DIR / "whitelist_base64.txt"
    bl_b64_file = OUTPUT_DIR / "blacklist_base64.txt"
    happ_txt_file = OUTPUT_DIR / "happ_whitelist.txt"
    happ_b64_file = OUTPUT_DIR / "happ_whitelist_base64.txt"

    # Сохранение White-List
    with open(wl_file, "w", encoding="utf-8") as f:
        f.write("\n".join(whitelist) + "\n")

    with open(happ_txt_file, "w", encoding="utf-8") as f:
        f.write("\n".join(whitelist) + "\n")

    wl_b64 = base64.b64encode("\n".join(whitelist).encode("utf-8")).decode("utf-8")
    with open(wl_b64_file, "w", encoding="utf-8") as f:
        f.write(wl_b64 + "\n")

    with open(happ_b64_file, "w", encoding="utf-8") as f:
        f.write(wl_b64 + "\n")

    # Сохранение Black-List
    with open(bl_file, "w", encoding="utf-8") as f:
        f.write("\n".join(blacklist) + "\n")

    bl_b64 = base64.b64encode("\n".join(blacklist).encode("utf-8")).decode("utf-8")
    with open(bl_b64_file, "w", encoding="utf-8") as f:
        f.write(bl_b64 + "\n")

    # Сохранение профилей Happ JSON
    happ_json_file = generate_happ_json(whitelist, is_whitelist=True)
    happ_bl_json_file = generate_happ_json(blacklist, is_whitelist=False)

    logger.info(f"Файлы успешно сохранены в папку: {OUTPUT_DIR}")
    logger.info(f" -> {wl_file.name} ({len(whitelist)} узлов)")
    logger.info(f" -> {bl_file.name} ({len(blacklist)} узлов)")
    logger.info(f" -> {happ_json_file.name} (профиль Happ White-List JSON)")
    logger.info(f" -> {happ_bl_json_file.name} (профиль Happ Black-List JSON)")
    logger.info(f" -> {happ_txt_file.name} (список URI для Happ VPN)")
    logger.info(f" -> {happ_b64_file.name} (Base64 для Happ VPN)")

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
